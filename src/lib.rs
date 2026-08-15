//! OpenAPI backend binding plugin (`kind: openapi`).
//!
//! Registers OpenAPI 3.0/3.1 documents as named `sources` in the plugin's
//! own config and exposes their operations as MCP tools. Tier 1: an
//! operator references one operation per binding via
//! `backend: { kind: openapi, source, operation }`; the plugin derives the
//! tool input/output schema (`input_schema`/`output_schema`) and dispatches
//! the call as an outbound HTTP request, reusing net-core's SSRF guard and
//! the structured response envelope the gateway projects onto `tools/call`.

mod config;
mod exec;
mod spec;

#[cfg(any(feature = "cdylib-export", feature = "static-firstparty"))]
mod cdylib;

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use mcpg_plugin_backend_net_core::client::build_http_client;
use mcpg_plugin_backend_net_core::types::{HttpBackendMethod, HttpRequestProfile};
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendInvocationContext, BackendPlugin, BackendRequest,
    BackendResponse, CapabilitySet, ExpandedResourceTemplate, ExpandedTool, PluginManifest,
    firstparty_manifest,
};
use serde_json::Value;
use tokio::sync::RwLock as AsyncRwLock;

use crate::config::{BindingSpec, ExposeConfig, FilterConfig, PluginConfig, SourceConfig};
use crate::spec::{OperationPlan, ParsedSpec, SecurityScheme};

pub const DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

/// A registered source: the (lenient) parsed spec + how to reach it.
struct SourceRuntime {
    spec: Result<ParsedSpec, String>,
    config_base_url: Option<String>,
    headers: BTreeMap<String, String>,
    allow_private_backends: bool,
    allow_insecure_http: bool,
    max_response_bytes: usize,
    timeout: Duration,
    expose: Option<ExposeConfig>,
    filter: FilterConfig,
    governance: Option<Value>,
    retry: Option<Value>,
    /// Injectable schemes parsed from the spec's `components.securitySchemes`.
    security_schemes: BTreeMap<String, SecurityScheme>,
    /// Operator-supplied secret/credential per scheme name.
    auth: BTreeMap<String, String>,
}

/// A registered tool binding: one operation of one source.
struct ProfileRuntime {
    source: String,
    base_url: String,
    plan: OperationPlan,
}

pub struct OpenapiBackendPlugin {
    manifest: PluginManifest,
    sources: BTreeMap<String, SourceRuntime>,
    profiles: RwLock<BTreeMap<String, Arc<ProfileRuntime>>>,
    clients: AsyncRwLock<BTreeMap<String, Arc<reqwest::Client>>>,
    host: OnceLock<Arc<dyn BackendHost>>,
}

impl OpenapiBackendPlugin {
    /// Build from `plugins[].config`. Spec parse errors are stored
    /// per-source and surfaced when a binding references the bad source
    /// (matches the "validate at register" convention). The top-level
    /// `config:` block parse fails CLOSED: a present-but-malformed block
    /// panics (the FFI `make` slot turns that into a boot rejection) rather
    /// than silently degrading to defaults; an empty/absent block still
    /// yields `PluginConfig::default()`.
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg: PluginConfig = mcpg_plugin_sdk::fail_closed_config!(config_json, PluginConfig);
        let mut sources = BTreeMap::new();
        for src in cfg.sources {
            sources.insert(src.name.clone(), SourceRuntime::from_config(src));
        }
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.openapi",
                name: "OpenAPI Binding",
                class: Backend,
            },
            sources,
            profiles: RwLock::new(BTreeMap::new()),
            clients: AsyncRwLock::new(BTreeMap::new()),
            host: OnceLock::new(),
        }
    }

    fn profile(&self, name: &str) -> Option<Arc<ProfileRuntime>> {
        self.profiles
            .read()
            .expect("profiles lock poisoned")
            .get(name)
            .cloned()
    }

    /// Get-or-build the DNS-pinned, SSRF-guarded client for a source. No
    /// headers are baked in — the client is pure transport; per-call headers
    /// (static + params + resolved auth) are sent per request.
    async fn client_for(
        &self,
        source: &str,
        base_url: &str,
    ) -> Result<Arc<reqwest::Client>, BackendError> {
        if let Some(c) = self.clients.read().await.get(source) {
            return Ok(c.clone());
        }
        let src = self
            .sources
            .get(source)
            .ok_or_else(|| BackendError::ProfileNotFound {
                backend_name: source.to_owned(),
            })?;
        let profile = HttpRequestProfile {
            url: base_url.to_owned(),
            method: HttpBackendMethod::Get, // avoid baked JSON default headers
            headers: BTreeMap::new(),
            expected_status_codes: vec![],
            require_json_response: false,
            max_response_bytes: src.max_response_bytes,
            timeout: src.timeout,
            allow_private_backends: src.allow_private_backends,
        };
        let client = build_http_client(&profile, base_url, &BTreeMap::new())
            .await
            .map_err(|e| BackendError::Transport {
                message: format!("building client for source '{source}': {e}"),
            })?;
        self.clients
            .write()
            .await
            .insert(source.to_owned(), client.clone());
        Ok(client)
    }

    /// Resolve `${cred://issuer/target}` credential tokens in the static
    /// headers + per-scheme auth values in a single host call (so basic-auth
    /// values are resolved before base64 encoding, and apiKey-query values
    /// before injection).
    ///
    /// STANDARDIZED GRAMMAR + CONFIG-ORIGIN ONLY. A credential resolves ONLY
    /// when an operator wrote it as a `${cred://issuer/target}` token; a BARE
    /// `cred://…` (not wrapped in `${}`) is NOT a credential reference and
    /// travels to the upstream verbatim. We extract the inner URIs from each
    /// config value with [`cred_tokens`], resolve those URIs through the host
    /// in one call (snapshot keyed by inner URI → resolved value), then splice
    /// each value back in with [`substitute_cred_tokens`].
    ///
    /// `config_headers` is the source's static `headers` map (where an operator
    /// may write a `${cred://…}` token); we cred-scan a header slot ONLY from
    /// that OPERATOR value, never the request-arg-merged `headers` map which can
    /// be overwritten by an `in: header` operation parameter taken verbatim from
    /// request arguments. Otherwise a caller could smuggle a `${cred://…}` token
    /// through a header param and have the gateway resolve — and emit — a
    /// credential they never held (for a static issuer, the secret itself). The
    /// per-scheme `auth` map is built solely from the operator's `auth` config,
    /// so it is scanned in full. Two layers protect against request-arg creds:
    /// the config-origin boundary here, plus the grammar (a request-supplied
    /// value is data, never a config-authored `${cred://…}` token).
    /// Regression: `tests::request_injected_cred_uri_is_never_resolved`
    /// (mirrors net-core / http `request_injected_cred_uri_is_never_resolved`).
    async fn resolve_creds(
        &self,
        headers: &mut BTreeMap<String, String>,
        auth: &mut BTreeMap<String, String>,
        config_headers: &BTreeMap<String, String>,
        request: &BackendRequest,
        profile_name: &str,
    ) -> Result<(), BackendError> {
        use mcpg_plugin_protocol::credential::{cred_tokens, substitute_cred_tokens};

        // 1. Collect the inner `cred://…` URIs from every `${cred://…}` token an
        // operator authored — config-origin only: cred-bearing static headers
        // (OPERATOR values, NOT the request-arg-merged ones) + per-scheme auth
        // values (all operator config). Header names whose operator value
        // carried a token are the only header positions we resolve.
        let cred_header_names: Vec<&String> = config_headers
            .iter()
            .filter(|(_, raw)| !cred_tokens(raw).is_empty())
            .map(|(name, _)| name)
            .collect();
        let mut cred_uris: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for name in &cred_header_names {
            if let Some(v) = config_headers.get(*name) {
                cred_uris.extend(cred_tokens(v));
            }
        }
        for v in auth.values() {
            cred_uris.extend(cred_tokens(v));
        }
        if cred_uris.is_empty() {
            return Ok(());
        }
        let Some(host) = self.host.get() else {
            return Err(BackendError::InvalidSpec {
                message: "host handle unavailable".to_owned(),
            });
        };

        // 2. Resolve those URIs through the host in one call. Snapshot is keyed
        // by the inner URI (a bare `cred://…` the host's resolver parses) → its
        // own value, so the resolver rewrites each in place.
        let mut snapshot = serde_json::Map::new();
        for uri in &cred_uris {
            snapshot.insert(uri.clone(), Value::String(uri.clone()));
        }
        let mut snapshot = Value::Object(snapshot);
        let mut ctx = BackendInvocationContext::root(
            request.request_id.clone(),
            request.session_id.clone(),
            profile_name.to_owned(),
        );
        ctx.identity = request.identity.clone();
        host.resolve_credentials(&ctx, &mut snapshot)
            .await
            .map_err(|e| BackendError::Transport {
                message: format!("credential resolution: {e}"),
            })?;
        let map: std::collections::HashMap<String, String> = snapshot
            .as_object()
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                    .collect()
            })
            .unwrap_or_default();

        // 3. Substitute. Write resolved headers back ONLY for the allowlisted
        // (config-origin) names — splicing from the OPERATOR value — so a
        // request-injected header param of the same name can never be displaced
        // by, or smuggle in, a resolved secret. Bare `cred://…` is left verbatim.
        for name in &cred_header_names {
            if let Some(raw) = config_headers.get(*name) {
                headers.insert((*name).clone(), substitute_cred_tokens(raw, &map));
            }
        }
        for v in auth.values_mut() {
            *v = substitute_cred_tokens(v, &map);
        }
        Ok(())
    }
}

/// `Authorization: Basic` value — base64 of the operator-supplied
/// `user:pass` (or any pre-formatted credential string).
fn basic_b64(value: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
}

impl SourceRuntime {
    fn from_config(src: SourceConfig) -> Self {
        let spec = ParsedSpec::load(&src.spec);
        let security_schemes = spec
            .as_ref()
            .map(ParsedSpec::security_schemes)
            .unwrap_or_default();
        Self {
            spec,
            config_base_url: src.base_url,
            headers: src.headers,
            allow_private_backends: src.upstream_safety.allow_private_backends,
            allow_insecure_http: src.upstream_safety.allow_insecure_http,
            max_response_bytes: src.response.max_response_bytes,
            timeout: Duration::from_millis(src.response.timeout_ms),
            expose: src.expose,
            filter: src.filter,
            governance: src.governance,
            retry: src.retry,
            security_schemes,
            auth: src.auth,
        }
    }
}

/// Pick the upstream base URL: the source override, else the spec's first
/// `servers[].url`.
fn resolve_base_url(src: &SourceRuntime, spec: &ParsedSpec) -> Result<String, String> {
    if let Some(b) = &src.config_base_url {
        return Ok(b.clone());
    }
    spec.root
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|s| s.first())
        .and_then(|s| s.get("url"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "no base_url configured and spec has no absolute servers[].url".to_owned())
}

#[async_trait]
impl BackendPlugin for OpenapiBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "openapi"
    }

    async fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
        host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let _ = self.host.set(host);

        let binding: BindingSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("openapi binding spec: {e}"),
            })?;

        // Identifier presence: a `source`/`operation` selector that trims to
        // nothing is a config typo, rejected up front so the operator sees a
        // precise message rather than a downstream "unknown source ''" lookup.
        if binding.source.trim().is_empty() {
            return Err(BackendError::InvalidSpec {
                message: "openapi binding spec: `source` must not be empty".to_owned(),
            });
        }
        if binding.operation.trim().is_empty() {
            return Err(BackendError::InvalidSpec {
                message: "openapi binding spec: `operation` must not be empty".to_owned(),
            });
        }

        let src = self
            .sources
            .get(&binding.source)
            .ok_or_else(|| BackendError::InvalidSpec {
                message: format!("unknown openapi source '{}'", binding.source),
            })?;
        let parsed = src.spec.as_ref().map_err(|e| BackendError::InvalidSpec {
            message: format!("source '{}' spec failed to load: {e}", binding.source),
        })?;

        let base_url = resolve_base_url(src, parsed).map_err(|e| BackendError::InvalidSpec {
            message: format!("source '{}': {e}", binding.source),
        })?;
        if base_url.starts_with("http://") && !src.allow_insecure_http {
            return Err(BackendError::InvalidSpec {
                message: format!(
                    "source '{}': insecure http base_url '{base_url}' (set allow_insecure_http)",
                    binding.source
                ),
            });
        }

        let plan =
            parsed
                .operation_plan(&binding.operation)
                .map_err(|e| BackendError::InvalidSpec {
                    message: format!("source '{}': {e}", binding.source),
                })?;

        // Build the client eagerly so SSRF/DNS problems surface at boot.
        self.client_for(&binding.source, &base_url).await?;

        self.profiles
            .write()
            .expect("profiles lock poisoned")
            .insert(
                profile_name.to_owned(),
                Arc::new(ProfileRuntime {
                    source: binding.source,
                    base_url,
                    plan,
                }),
            );
        Ok(())
    }

    fn input_schema(&self, profile_name: &str) -> Option<serde_json::Value> {
        self.profile(profile_name).map(|p| p.plan.input_schema())
    }

    fn output_schema(&self, profile_name: &str) -> Option<serde_json::Value> {
        self.profile(profile_name)
            .and_then(|p| p.plan.output_schema.clone())
    }

    /// Tier 2: enumerate every source's exposed operations into tools. The
    /// gateway synthesizes one binding per returned `ExpandedTool`. Fails
    /// closed (`InvalidSpec`) if a source exceeds its `max_capabilities`
    /// cap so a misconfigured filter can't silently mint thousands of tools.
    async fn expand_capabilities(&self) -> Result<CapabilitySet, BackendError> {
        let mut tools = Vec::new();
        let mut resource_templates = Vec::new();
        for (source_name, src) in &self.sources {
            let Some(expose) = &src.expose else { continue };
            if !expose.tools {
                continue;
            }
            // A source that failed to parse is skipped here; an explicit
            // Tier-1 binding against it still surfaces the error at register.
            let Ok(spec) = &src.spec else { continue };

            let prefix = expose.tool_prefix.as_deref().unwrap_or("");
            let mut produced = 0usize;
            for op in spec.operations() {
                if !src.filter.allows(&op) {
                    continue;
                }
                produced += 1;
                if produced > src.filter.max_capabilities {
                    return Err(BackendError::InvalidSpec {
                        message: format!(
                            "source '{source_name}' exposes more than max_capabilities ({}) operations; tighten the filter or raise the cap",
                            src.filter.max_capabilities
                        ),
                    });
                }
                let op_id = op.operation_id.clone();
                let description = op
                    .summary
                    .clone()
                    .or(op.description.clone())
                    .unwrap_or_default();
                let backend_spec = serde_json::json!({ "source": source_name, "operation": op_id });
                let meta = Some(serde_json::json!({
                    "openapi": { "source": source_name, "operationId": op_id, "tags": op.tags }
                }));

                // A read-by-id GET becomes a resource template (unless the
                // source opted reads back into tools); everything else is a
                // tool.
                if expose.reads_as_resource_templates && op.is_read_by_id() {
                    let uri_prefix = expose
                        .resource_uri_prefix
                        .clone()
                        .unwrap_or_else(|| format!("{source_name}://"));
                    resource_templates.push(ExpandedResourceTemplate {
                        name: format!("{prefix}{op_id}"),
                        uri_template: format!("{uri_prefix}{}", op.path.trim_start_matches('/')),
                        description,
                        mime_type: None,
                        meta,
                        backend_kind: "openapi".to_owned(),
                        backend_spec,
                        governance: src.governance.clone(),
                        retry: src.retry.clone(),
                    });
                } else {
                    let plan =
                        spec.operation_plan(&op_id)
                            .map_err(|e| BackendError::InvalidSpec {
                                message: format!("source '{source_name}': {e}"),
                            })?;
                    tools.push(ExpandedTool {
                        name: format!("{prefix}{op_id}"),
                        title: None,
                        description,
                        input_schema: plan.input_schema(),
                        output_schema: plan.output_schema.clone(),
                        annotations: None,
                        meta,
                        backend_kind: "openapi".to_owned(),
                        backend_spec,
                        governance: src.governance.clone(),
                        retry: src.retry.clone(),
                    });
                }
            }
        }
        Ok(CapabilitySet {
            tools,
            resource_templates,
        })
    }

    async fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let profile = self
            .profile(profile_name)
            .ok_or_else(|| BackendError::ProfileNotFound {
                backend_name: profile_name.to_owned(),
            })?;
        let src =
            self.sources
                .get(&profile.source)
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: profile.source.clone(),
                })?;

        let args: Value = if request.payload.is_empty() {
            Value::Object(Default::default())
        } else {
            serde_json::from_slice(&request.payload)
                .unwrap_or_else(|_| Value::Object(Default::default()))
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| profile_name.to_owned());

        let prepared = exec::build_request(&profile.plan, &args)
            .map_err(|e| BackendError::InvalidSpec { message: e })?;

        // Static source headers + per-operation header params. Collect the
        // operation's required auth values, then resolve cred:// across
        // headers + auth in one host call (so basic is base64'd post-resolve
        // and query keys carry resolved values).
        let mut headers = src.headers.clone();
        for (k, v) in &prepared.header_params {
            headers.insert(k.clone(), v.clone());
        }
        let mut auth_values: BTreeMap<String, String> = profile
            .plan
            .auth_schemes
            .iter()
            .filter_map(|name| src.auth.get(name).map(|v| (name.clone(), v.clone())))
            .collect();
        self.resolve_creds(
            &mut headers,
            &mut auth_values,
            &src.headers,
            &request,
            profile_name,
        )
        .await?;

        // Inject auth per the spec's securityScheme definitions.
        let mut query = prepared.query.clone();
        for name in &profile.plan.auth_schemes {
            let (Some(scheme), Some(value)) =
                (src.security_schemes.get(name), auth_values.get(name))
            else {
                continue; // unknown scheme, or operator supplied no secret → skip
            };
            match scheme {
                SecurityScheme::ApiKeyHeader { name: hn } => {
                    headers.insert(hn.clone(), value.clone());
                }
                SecurityScheme::ApiKeyQuery { name: qn } => {
                    query.push((qn.clone(), value.clone()));
                }
                SecurityScheme::Bearer => {
                    headers.insert("Authorization".to_owned(), format!("Bearer {value}"));
                }
                SecurityScheme::Basic => {
                    headers.insert(
                        "Authorization".to_owned(),
                        format!("Basic {}", basic_b64(value)),
                    );
                }
                SecurityScheme::Unsupported => {}
            }
        }

        let final_url = exec::full_url(&profile.base_url, &prepared.relative_path, &query)
            .map_err(|e| BackendError::InvalidSpec { message: e })?;
        let header_list: Vec<(String, String)> = headers.into_iter().collect();

        let client = self.client_for(&profile.source, &profile.base_url).await?;
        let outcome = exec::send_request(
            &client,
            &prepared.method,
            &final_url,
            &header_list,
            prepared.body.as_ref(),
            src.max_response_bytes,
        )
        .await;

        let truncated = matches!(&outcome, Ok(o) if o.body_truncated);

        // Resource-template reads: the gateway injects a `template_vars`
        // object into the args. On a 2xx we return the MCP resources/read
        // `{contents:[...]}` shape (the gateway's `decode_resource_result`
        // expects it); any failure falls through to the tool envelope so
        // its `downstreamError` marks the read failed.
        let is_resource_read = args
            .get("template_vars")
            .map(Value::is_object)
            .unwrap_or(false);
        let resource_ok = matches!(&outcome, Ok(o) if o.status / 100 == 2);
        let payload_value = if is_resource_read && resource_ok {
            let out = outcome.as_ref().expect("ok checked");
            let uri = args
                .get("uri")
                .and_then(Value::as_str)
                .unwrap_or(&final_url)
                .to_owned();
            let mime = out
                .content_type
                .clone()
                .unwrap_or_else(|| "application/json".to_owned());
            serde_json::json!({
                "contents": [ { "uri": uri, "mimeType": mime, "text": out.body_text } ]
            })
        } else {
            exec::build_envelope(&tool_name, profile_name, &prepared, &final_url, &outcome)
        };
        let payload = serde_json::to_vec(&payload_value).unwrap_or_else(|_| b"{}".to_vec());
        Ok(BackendResponse { payload, truncated })
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, serde_json::Value> {
        let mut map = serde_json::Map::new();
        map.insert("openapi.transport".to_owned(), serde_json::json!("plugin"));
        if let Some(p) = self.profile(profile_name) {
            map.insert("openapi.source".to_owned(), serde_json::json!(p.source));
            map.insert(
                "openapi.operation_id".to_owned(),
                serde_json::json!(p.plan.operation_id),
            );
        }
        map
    }
}

#[cfg(test)]
mod tests;

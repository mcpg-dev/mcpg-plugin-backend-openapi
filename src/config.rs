//! Operator-facing config for the openapi backend.
//!
//! The plugin owns a registry of `sources` in its own config record
//! (`plugins[].config`). Each source names one OpenAPI document
//! plus how to reach the upstream it describes. Tool bindings reference a
//! source + operation; the plugin derives schemas and dispatches calls.

use std::collections::BTreeMap;

use serde::Deserialize;

/// Top-level plugin config: `plugins[].config`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
}

/// One registered OpenAPI source.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    /// Source id referenced by tool bindings (`backend: { source: <name> }`).
    pub name: String,
    /// Where the spec document lives.
    pub spec: SpecSource,
    /// Upstream base URL. Overrides the spec's `servers[0].url`. Required
    /// in Tier 1 (we do not yet resolve relative `servers` against a spec
    /// origin).
    #[serde(default)]
    pub base_url: Option<String>,
    /// Static headers applied to every request to this source (e.g. a
    /// fixed `User-Agent`). Values may be literal or carry a
    /// `${cred://<issuer>/<target>}` token resolved per-call through the host.
    /// A bare `cred://…` (not wrapped in `${}`) is NOT a credential reference
    /// and travels to the upstream verbatim.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Secret/credential per spec `securityScheme` name. The plugin reads
    /// the scheme definition from the spec to know HOW to inject (header /
    /// query / bearer / basic) and uses this value as the secret. Values may
    /// be literal or carry a `${cred://<issuer>/<target>}` token (resolved
    /// per-call); a bare `cred://…` is left verbatim. A scheme an operation
    /// requires but with no entry here is simply not injected.
    #[serde(default)]
    pub auth: BTreeMap<String, String>,
    #[serde(default)]
    pub upstream_safety: UpstreamSafety,
    #[serde(default)]
    pub response: ResponseLimits,
    /// Tier 2 — bulk auto-expose. Absent (`None`) means reference-only:
    /// the source is used solely by explicit Tier-1 bindings.
    #[serde(default)]
    pub expose: Option<ExposeConfig>,
    /// Whitelist/blacklist applied to auto-exposed operations.
    #[serde(default)]
    pub filter: FilterConfig,
    /// Governance relayed onto every auto-exposed capability of this source
    /// (operator-authored; the gateway enforces). Shaped like a binding
    /// `governance:` block. Carried as raw JSON — the plugin doesn't
    /// interpret it.
    #[serde(default)]
    pub governance: Option<serde_json::Value>,
    /// Retry relayed onto every auto-exposed capability (raw JSON).
    #[serde(default)]
    pub retry: Option<serde_json::Value>,
}

/// What MCP surfaces to auto-expose from a source. Tools + resource
/// templates for read-by-id `GET`s. `prompts` / webhooks remain
/// future work; unknown keys are ignored.
///
/// NOTE: deliberately NOT `#[serde(deny_unknown_fields)]`. This struct is a
/// documented forward-compatible passthrough: the future `prompts` /
/// `webhooks` expose surfaces are meant to be accepted-and-ignored by older
/// builds, so a not-yet-implemented expose key must not fail the boot.
#[derive(Debug, Clone, Deserialize)]
pub struct ExposeConfig {
    #[serde(default)]
    pub tools: bool,
    /// Prefix prepended to each operationId to form the MCP tool name
    /// (e.g. `"petstore."` → `petstore.getPetById`).
    #[serde(default)]
    pub tool_prefix: Option<String>,
    /// When true (default), a read-by-id `GET` (a `GET` with ≥1 path
    /// parameter) is exposed as a resource template instead of a tool. Set
    /// false to expose every operation, including reads, as a tool.
    #[serde(default = "default_true")]
    pub reads_as_resource_templates: bool,
    /// URI scheme/prefix for generated resource templates. Defaults to
    /// `"{source}://"` when unset.
    #[serde(default)]
    pub resource_uri_prefix: Option<String>,
}

impl Default for ExposeConfig {
    fn default() -> Self {
        Self {
            tools: false,
            tool_prefix: None,
            reads_as_resource_templates: default_true(),
            resource_uri_prefix: None,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Whitelist/blacklist for auto-exposed operations. Empty include lists mean
/// "all"; exclude lists subtract. An operation must pass every active filter.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    #[serde(default)]
    pub include_tags: Vec<String>,
    #[serde(default)]
    pub exclude_tags: Vec<String>,
    #[serde(default)]
    pub include_operations: Vec<String>,
    #[serde(default)]
    pub exclude_operations: Vec<String>,
    /// Lowercased HTTP methods to include (empty = all).
    #[serde(default)]
    pub methods: Vec<String>,
    /// Hard cap on auto-exposed capabilities per source; boot fails if
    /// exceeded (guards against accidentally minting thousands of tools).
    #[serde(default = "default_max_capabilities")]
    pub max_capabilities: usize,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
            include_operations: Vec::new(),
            exclude_operations: Vec::new(),
            methods: Vec::new(),
            max_capabilities: default_max_capabilities(),
        }
    }
}

fn default_max_capabilities() -> usize {
    200
}

impl FilterConfig {
    /// Whether an operation survives this filter. Include lists (when
    /// non-empty) gate; exclude lists subtract.
    pub fn allows(&self, op: &crate::spec::OperationMeta) -> bool {
        if !self.methods.is_empty()
            && !self
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&op.method))
        {
            return false;
        }
        if !self.include_operations.is_empty()
            && !self.include_operations.contains(&op.operation_id)
        {
            return false;
        }
        if self.exclude_operations.contains(&op.operation_id) {
            return false;
        }
        if !self.include_tags.is_empty() && !op.tags.iter().any(|t| self.include_tags.contains(t)) {
            return false;
        }
        if op.tags.iter().any(|t| self.exclude_tags.contains(t)) {
            return false;
        }
        true
    }
}

/// Where a spec document is loaded from. `url://` is deferred to a later
/// phase (it needs async fetch + the SSRF guard at boot); inline + file
/// cover Tier 1.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum SpecSource {
    /// A URI string: `file:///path/to/spec.yaml` or `https://…` (deferred).
    Uri(String),
    /// The spec document inlined directly in config.
    Inline { inline: serde_json::Value },
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSafety {
    /// When false (default), the DNS-rebinding guard rejects upstreams
    /// that resolve only to private/loopback addresses.
    #[serde(default)]
    pub allow_private_backends: bool,
    /// When false (default), `http://` base URLs are rejected.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseLimits {
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: default_max_response_bytes(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

fn default_max_response_bytes() -> usize {
    1_048_576
}
fn default_timeout_ms() -> u64 {
    8_000
}

/// Per-binding spec the gateway forwards to `register_profile`. Tier 1
/// shape: `backend: { kind: openapi, source: <name>, operation: <id> }`.
#[derive(Debug, Clone, Deserialize)]
pub struct BindingSpec {
    pub source: String,
    pub operation: String,
}

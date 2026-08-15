//! Unit + integration tests for the openapi backend (Tier 1).

use std::sync::Arc;

use async_trait::async_trait;
use mcpg_plugin_protocol::{
    BackendHost, BackendHostError, BackendInvocationContext, BackendPlugin, BackendRequest,
};
use serde_json::{Value, json};

use crate::OpenapiBackendPlugin;

/// Minimal host: openapi only calls `resolve_credentials` (for `cred://`),
/// and these tests use no `cred://`, so the defaults suffice.
struct NoopHost;

#[async_trait]
impl BackendHost for NoopHost {
    async fn invoke_tool(
        &self,
        _ctx: &BackendInvocationContext,
        _tool: &str,
        _args: &Value,
    ) -> Result<Value, BackendHostError> {
        Err(BackendHostError::NotImplemented)
    }
}

fn host() -> Arc<dyn BackendHost> {
    Arc::new(NoopHost)
}

fn request(args: Value) -> BackendRequest {
    BackendRequest {
        payload: serde_json::to_vec(&args).unwrap(),
        headers: vec![],
        request_id: "test-req".to_owned(),
        session_id: None,
        identity: None,
        idempotency: None,
    }
}

/// A small petstore-ish spec covering: path param, query param, object body.
///
/// Tests that exercise the success path pass a loopback `base_url`
/// (`https://127.0.0.1`): `register_profile` eagerly builds the HTTP client
/// to surface SSRF/DNS problems at boot, and a literal IP resolves offline
/// (`lookup_host` short-circuits it) so the suite stays hermetic on
/// network-restricted CI runners. A real domain would fail `lookup_host`.
fn petstore_config(base_url: &str) -> String {
    let spec = json!({
        "openapi": "3.0.3",
        "info": { "title": "Petstore", "version": "1.0.0" },
        "paths": {
            "/pets": {
                "get": {
                    "operationId": "listPets",
                    "parameters": [
                        { "name": "limit", "in": "query", "required": false,
                          "schema": { "type": "integer", "nullable": true } }
                    ],
                    "responses": { "200": { "description": "ok",
                        "content": { "application/json": { "schema": {
                            "type": "array", "items": { "$ref": "#/components/schemas/Pet" } } } } } }
                },
                "post": {
                    "operationId": "createPet",
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "$ref": "#/components/schemas/NewPet" } } } },
                    "responses": { "201": { "description": "created",
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } } } } }
                }
            },
            "/pets/{petId}": {
                "get": {
                    "operationId": "getPetById",
                    "parameters": [
                        { "name": "petId", "in": "path", "required": true,
                          "schema": { "type": "integer" } }
                    ],
                    "responses": { "200": { "description": "ok",
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } } } } }
                }
            },
            "/ping": {
                "get": { "operationId": "ping",
                    "responses": { "200": { "description": "ok",
                        "content": { "application/json": { "schema": { "type": "object" } } } } } }
            }
        },
        "components": { "schemas": {
            "Pet": { "type": "object",
                "required": ["id", "name"],
                "properties": { "id": { "type": "integer" }, "name": { "type": "string" },
                                "tag": { "type": "string" } } },
            "NewPet": { "type": "object",
                "required": ["name"],
                "properties": { "name": { "type": "string" }, "tag": { "type": "string" } } }
        } }
    });
    json!({
        "sources": [{
            "name": "petstore",
            "spec": { "inline": spec },
            "base_url": base_url,
            "upstream_safety": { "allow_private_backends": true, "allow_insecure_http": true }
        }]
    })
    .to_string()
}

#[tokio::test]
async fn input_schema_path_param_required() {
    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config("https://127.0.0.1"));
    plugin
        .register_profile(
            "get-pet",
            &json!({ "source": "petstore", "operation": "getPetById" }),
            host(),
        )
        .await
        .expect("register");
    let schema = plugin.input_schema("get-pet").expect("schema");
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["properties"]["petId"]["type"], "integer");
    assert_eq!(schema["required"], json!(["petId"]));
    // Output schema derived from 2xx response ($ref resolved to Pet).
    let out = plugin.output_schema("get-pet").expect("output schema");
    assert_eq!(out["type"], "object");
    assert_eq!(out["properties"]["name"]["type"], "string");
}

#[tokio::test]
async fn input_schema_body_hoisted_and_nullable() {
    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config("https://127.0.0.1"));
    plugin
        .register_profile(
            "create-pet",
            &json!({ "source": "petstore", "operation": "createPet" }),
            host(),
        )
        .await
        .expect("register");
    let schema = plugin.input_schema("create-pet").expect("schema");
    // NewPet object body properties hoisted to the top level.
    assert_eq!(schema["properties"]["name"]["type"], "string");
    assert_eq!(schema["properties"]["tag"]["type"], "string");
    assert_eq!(schema["required"], json!(["name"]));

    // listPets: 3.0 `nullable: true` becomes a 2020-12 union type.
    plugin
        .register_profile(
            "list-pets",
            &json!({ "source": "petstore", "operation": "listPets" }),
            host(),
        )
        .await
        .expect("register");
    let list_schema = plugin.input_schema("list-pets").expect("schema");
    assert_eq!(
        list_schema["properties"]["limit"]["type"],
        json!(["integer", "null"])
    );
}

#[tokio::test]
async fn unknown_source_or_operation_fails_at_register() {
    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config("https://127.0.0.1"));
    let bad_source = plugin
        .register_profile(
            "x",
            &json!({ "source": "nope", "operation": "ping" }),
            host(),
        )
        .await;
    assert!(bad_source.is_err(), "unknown source must fail");
    let bad_op = plugin
        .register_profile(
            "y",
            &json!({ "source": "petstore", "operation": "nope" }),
            host(),
        )
        .await;
    assert!(bad_op.is_err(), "unknown operation must fail");
}

#[tokio::test]
async fn execute_get_with_path_param_succeeds() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pets/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 42, "name": "Rex" })))
        .mount(&server)
        .await;

    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config(&server.uri()));
    plugin
        .register_profile(
            "get-pet",
            &json!({ "source": "petstore", "operation": "getPetById" }),
            host(),
        )
        .await
        .expect("register");

    let resp = plugin
        .execute("get-pet", request(json!({ "petId": 42 })))
        .await
        .expect("execute");
    let env: Value = serde_json::from_slice(&resp.payload).unwrap();
    assert!(
        env["downstreamError"].is_null(),
        "expected success, got {env:#}"
    );
    assert_eq!(env["response"]["statusCode"], 200);
    assert_eq!(env["response"]["json"]["name"], "Rex");
}

#[tokio::test]
async fn execute_post_sends_json_body() {
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pets"))
        .and(body_json(json!({ "name": "Milo", "tag": "dog" })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 7, "name": "Milo" })))
        .mount(&server)
        .await;

    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config(&server.uri()));
    plugin
        .register_profile(
            "create-pet",
            &json!({ "source": "petstore", "operation": "createPet" }),
            host(),
        )
        .await
        .expect("register");

    let resp = plugin
        .execute(
            "create-pet",
            request(json!({ "name": "Milo", "tag": "dog" })),
        )
        .await
        .expect("execute");
    let env: Value = serde_json::from_slice(&resp.payload).unwrap();
    assert!(
        env["downstreamError"].is_null(),
        "expected success, got {env:#}"
    );
    assert_eq!(env["response"]["statusCode"], 201);
}

/// Host that resolves any `cred://…` string to a fixed token, for auth tests.
struct CredHost;

#[async_trait]
impl BackendHost for CredHost {
    async fn invoke_tool(
        &self,
        _ctx: &BackendInvocationContext,
        _tool: &str,
        _args: &Value,
    ) -> Result<Value, BackendHostError> {
        Err(BackendHostError::NotImplemented)
    }

    async fn resolve_credentials(
        &self,
        _ctx: &BackendInvocationContext,
        value: &mut Value,
    ) -> Result<usize, BackendHostError> {
        fn walk(v: &mut Value, n: &mut usize) {
            match v {
                Value::String(s) if s.contains("cred://") => {
                    *s = "tok-123".to_owned();
                    *n += 1;
                }
                Value::Array(a) => a.iter_mut().for_each(|x| walk(x, n)),
                Value::Object(o) => o.values_mut().for_each(|x| walk(x, n)),
                _ => {}
            }
        }
        let mut n = 0;
        walk(value, &mut n);
        Ok(n)
    }
}

/// Single-operation secured spec: `GET /thing` (operationId `getThing`)
/// guarded by one security scheme, with the operator's `auth` value.
fn secured_config(base_url: &str, scheme: Value, auth: Value) -> String {
    let spec = json!({
        "openapi": "3.0.3",
        "info": { "title": "Secured", "version": "1.0.0" },
        "security": [ { "scheme1": [] } ],
        "paths": {
            "/thing": {
                "get": {
                    "operationId": "getThing",
                    "responses": { "200": { "description": "ok",
                        "content": { "application/json": { "schema": { "type": "object" } } } } }
                }
            }
        },
        "components": { "securitySchemes": { "scheme1": scheme } }
    });
    json!({
        "sources": [{
            "name": "api",
            "spec": { "inline": spec },
            "base_url": base_url,
            "upstream_safety": { "allow_private_backends": true, "allow_insecure_http": true },
            "auth": auth
        }]
    })
    .to_string()
}

#[tokio::test]
async fn auth_apikey_header_is_injected() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/thing"))
        .and(header("X-API-Key", "secret123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .mount(&server)
        .await;

    let plugin = OpenapiBackendPlugin::from_config_json(&secured_config(
        &server.uri(),
        json!({ "type": "apiKey", "in": "header", "name": "X-API-Key" }),
        json!({ "scheme1": "secret123" }),
    ));
    plugin
        .register_profile(
            "t",
            &json!({ "source": "api", "operation": "getThing" }),
            host(),
        )
        .await
        .expect("register");
    let resp = plugin
        .execute("t", request(json!({})))
        .await
        .expect("execute");
    let env: Value = serde_json::from_slice(&resp.payload).unwrap();
    // 2xx (header matched the mock) ⇒ no downstream error.
    assert!(
        env["downstreamError"].is_null(),
        "apiKey header not injected: {env:#}"
    );
}

#[tokio::test]
async fn auth_bearer_resolves_cred_reference() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/thing"))
        .and(header("Authorization", "Bearer tok-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .mount(&server)
        .await;

    let plugin = OpenapiBackendPlugin::from_config_json(&secured_config(
        &server.uri(),
        json!({ "type": "http", "scheme": "bearer" }),
        // Standardized grammar: a `${cred://…}` token in operator config resolves.
        json!({ "scheme1": "${cred://oauth/api}" }),
    ));
    plugin
        .register_profile(
            "t",
            &json!({ "source": "api", "operation": "getThing" }),
            Arc::new(CredHost),
        )
        .await
        .expect("register");
    let resp = plugin
        .execute("t", request(json!({})))
        .await
        .expect("execute");
    let env: Value = serde_json::from_slice(&resp.payload).unwrap();
    assert!(
        env["downstreamError"].is_null(),
        "bearer ${{cred://…}} not resolved/injected: {env:#}"
    );
}

/// SECURITY (standardized grammar): a BARE `cred://…` in OPERATOR config is NOT
/// a credential token under the new grammar — it travels to the upstream
/// VERBATIM and is NEVER resolved. Only `${cred://…}` resolves. Here the
/// operator's bearer `auth` value is a bare `cred://oauth/api`; the upstream
/// must see `Bearer cred://oauth/api` (the literal), not `Bearer tok-123`.
#[tokio::test]
async fn bare_cred_in_operator_config_is_left_verbatim() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // 200 ONLY when the bare cred:// reached the upstream untouched.
    Mock::given(method("GET"))
        .and(path("/thing"))
        .and(header("Authorization", "Bearer cred://oauth/api"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .mount(&server)
        .await;
    // If it got resolved to the secret token, fall through to a 599.
    Mock::given(method("GET"))
        .and(path("/thing"))
        .respond_with(ResponseTemplate::new(599))
        .mount(&server)
        .await;

    let plugin = OpenapiBackendPlugin::from_config_json(&secured_config(
        &server.uri(),
        json!({ "type": "http", "scheme": "bearer" }),
        // BARE cred:// (not wrapped in ${}) — must NOT resolve.
        json!({ "scheme1": "cred://oauth/api" }),
    ));
    plugin
        .register_profile(
            "t",
            &json!({ "source": "api", "operation": "getThing" }),
            Arc::new(CredHost),
        )
        .await
        .expect("register");
    let resp = plugin
        .execute("t", request(json!({})))
        .await
        .expect("execute");
    let env: Value = serde_json::from_slice(&resp.payload).unwrap();
    assert!(
        env["downstreamError"].is_null(),
        "bare cred:// in operator config must travel verbatim (not resolve); got {env:#}"
    );
    assert_eq!(
        env["response"]["statusCode"], 200,
        "bare cred:// was resolved — leak; got {env:#}"
    );
}

#[tokio::test]
async fn auth_apikey_query_is_injected() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/thing"))
        .and(query_param("api_key", "qsecret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .mount(&server)
        .await;

    let plugin = OpenapiBackendPlugin::from_config_json(&secured_config(
        &server.uri(),
        json!({ "type": "apiKey", "in": "query", "name": "api_key" }),
        json!({ "scheme1": "qsecret" }),
    ));
    plugin
        .register_profile(
            "t",
            &json!({ "source": "api", "operation": "getThing" }),
            host(),
        )
        .await
        .expect("register");
    let resp = plugin
        .execute("t", request(json!({})))
        .await
        .expect("execute");
    let env: Value = serde_json::from_slice(&resp.payload).unwrap();
    assert!(
        env["downstreamError"].is_null(),
        "apiKey query not injected: {env:#}"
    );
}

/// Security invariant (F1): a credential supplied through a request ARGUMENT
/// must NEVER reach the host credential resolver. The host substitutes any
/// `cred://` it finds in the snapshot per the caller's identity with no config
/// whitelist, so only operator-config-origin values may enter it. Here the
/// operation carries an `in: header` parameter (its value is taken verbatim
/// from the caller's args) and a bearer scheme whose operator `auth` value is a
/// `${cred://…}` token. A malicious caller injects `cred://static/db-password`
/// (and a `${env.SECRET}`) via the header params; `CredHost` would rewrite any
/// `cred://` it sees to `tok-123`. We assert the upstream receives those
/// caller-supplied header values VERBATIM (never the resolved secret), while
/// the operator's `${cred://…}` tokens still resolve.
/// Mirrors net-core / http `request_injected_cred_uri_is_never_resolved`.
#[tokio::test]
async fn request_injected_cred_uri_is_never_resolved() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // 200 ONLY when every header matches the SAFE expectation:
    //   - operator bearer ${cred://…} resolved to the secret token,
    //   - operator static ${cred://…} header resolved to the secret token,
    //   - caller-injected header params carried VERBATIM (never resolved):
    //     `X-Injected` is doubly safe — request-origin AND a bare cred://.
    Mock::given(method("GET"))
        .and(path("/thing"))
        .and(header("Authorization", "Bearer tok-123"))
        .and(header("X-Op-Cred", "tok-123"))
        .and(header("X-Injected", "cred://static/db-password"))
        .and(header("X-Env", "${env.SECRET}"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .mount(&server)
        .await;
    // Any other header combination (e.g. an injected ref that got resolved to
    // `tok-123`) falls through to a 599, surfacing as a downstream error.
    Mock::given(method("GET"))
        .and(path("/thing"))
        .respond_with(ResponseTemplate::new(599))
        .mount(&server)
        .await;

    // Secured spec: bearer scheme + two `in: header` operation parameters
    // (caller-controlled). Operator config supplies a bearer `${cred://…}` and a
    // static `${cred://…}` header.
    let spec = json!({
        "openapi": "3.0.3",
        "info": { "title": "Injected", "version": "1.0.0" },
        "security": [ { "scheme1": [] } ],
        "paths": {
            "/thing": {
                "get": {
                    "operationId": "getThing",
                    "parameters": [
                        { "name": "X-Injected", "in": "header", "required": false,
                          "schema": { "type": "string" } },
                        { "name": "X-Env", "in": "header", "required": false,
                          "schema": { "type": "string" } }
                    ],
                    "responses": { "200": { "description": "ok",
                        "content": { "application/json": { "schema": { "type": "object" } } } } }
                }
            }
        },
        "components": { "securitySchemes": {
            "scheme1": { "type": "http", "scheme": "bearer" } } }
    });
    let config = json!({
        "sources": [{
            "name": "api",
            "spec": { "inline": spec },
            "base_url": server.uri(),
            "upstream_safety": { "allow_private_backends": true, "allow_insecure_http": true },
            // Operator-config `${cred://…}` token in both a static header and the
            // bearer auth — these resolve under the standardized grammar.
            "headers": { "X-Op-Cred": "${cred://config/header-secret}" },
            "auth": { "scheme1": "${cred://oauth/api}" }
        }]
    })
    .to_string();

    let plugin = OpenapiBackendPlugin::from_config_json(&config);
    plugin
        .register_profile(
            "t",
            &json!({ "source": "api", "operation": "getThing" }),
            Arc::new(CredHost),
        )
        .await
        .expect("register");

    // Caller smuggles a cred:// and a ${env.X} through the header params.
    let resp = plugin
        .execute(
            "t",
            request(json!({
                "X-Injected": "cred://static/db-password",
                "X-Env": "${env.SECRET}"
            })),
        )
        .await
        .expect("execute");
    let env: Value = serde_json::from_slice(&resp.payload).unwrap();

    // The strict mock matched ⇒ operator creds resolved AND injected refs
    // travelled verbatim. A 599 here means a caller-supplied ref leaked into
    // the resolver (the bug) or an operator cred failed to resolve.
    assert!(
        env["downstreamError"].is_null(),
        "request-injected cred:// must travel verbatim while operator cred:// resolves; got {env:#}"
    );
    assert_eq!(
        env["response"]["statusCode"], 200,
        "expected SAFE header set, got {env:#}"
    );
}

/// Petstore config with Tier-2 auto-expose enabled, plus optional filter +
/// governance (raw JSON merged into the single source).
fn exposed_config(extra: Value) -> String {
    let mut cfg: Value = serde_json::from_str(&petstore_config("https://127.0.0.1")).unwrap();
    let source = &mut cfg["sources"][0];
    source["expose"] = json!({ "tools": true, "tool_prefix": "petstore." });
    if let Value::Object(extra) = extra {
        for (k, v) in extra {
            source[k] = v;
        }
    }
    cfg.to_string()
}

#[tokio::test]
async fn expand_capabilities_produces_prefixed_tools_with_schemas() {
    // reads_as_resource_templates:false → every op (incl. getPetById) is a tool.
    let plugin = OpenapiBackendPlugin::from_config_json(&exposed_config(json!({
        "expose": { "tools": true, "tool_prefix": "petstore.", "reads_as_resource_templates": false },
        "governance": { "minimum_trust": "verified" }
    })));
    let set = plugin.expand_capabilities().await.expect("expand");
    // 4 operations in the fixture: listPets, createPet, getPetById, ping.
    assert_eq!(set.tools.len(), 4);
    assert!(set.resource_templates.is_empty());
    let by_name: std::collections::BTreeMap<_, _> =
        set.tools.iter().map(|t| (t.name.clone(), t)).collect();

    let get_pet = by_name
        .get("petstore.getPetById")
        .expect("getPetById exposed");
    assert_eq!(get_pet.backend_kind, "openapi");
    assert_eq!(
        get_pet.backend_spec,
        json!({ "source": "petstore", "operation": "getPetById" })
    );
    assert_eq!(
        get_pet.input_schema["properties"]["petId"]["type"],
        "integer"
    );
    assert_eq!(get_pet.input_schema["required"], json!(["petId"]));
    // Governance relayed verbatim from the source config.
    assert_eq!(
        get_pet.governance,
        Some(json!({ "minimum_trust": "verified" }))
    );
}

#[tokio::test]
async fn expand_capabilities_applies_method_and_operation_filters() {
    // Only GETs, and explicitly drop `ping`. reads-as-tools so the GET-by-id
    // surfaces as a tool for this filter assertion.
    let plugin = OpenapiBackendPlugin::from_config_json(&exposed_config(json!({
        "expose": { "tools": true, "tool_prefix": "petstore.", "reads_as_resource_templates": false },
        "filter": { "methods": ["get"], "exclude_operations": ["ping"] }
    })));
    let names: Vec<String> = plugin
        .expand_capabilities()
        .await
        .expect("expand")
        .tools
        .into_iter()
        .map(|t| t.name)
        .collect();
    // createPet (POST) filtered by method; ping dropped by exclude.
    assert!(names.contains(&"petstore.listPets".to_owned()));
    assert!(names.contains(&"petstore.getPetById".to_owned()));
    assert!(!names.iter().any(|n| n.contains("createPet")));
    assert!(!names.iter().any(|n| n.contains("ping")));
}

#[tokio::test]
async fn expand_capabilities_reads_become_resource_templates() {
    // Default expose: read-by-id GET (getPetById) → resource template; the
    // collection GET (listPets) + POST (createPet) + paramless GET (ping)
    // stay tools.
    let plugin = OpenapiBackendPlugin::from_config_json(&exposed_config(json!({})));
    let set = plugin.expand_capabilities().await.expect("expand");

    let tool_names: Vec<&str> = set.tools.iter().map(|t| t.name.as_str()).collect();
    assert!(tool_names.contains(&"petstore.listPets"));
    assert!(tool_names.contains(&"petstore.createPet"));
    assert!(
        !tool_names.iter().any(|n| n.contains("getPetById")),
        "read-by-id must not be a tool"
    );

    assert_eq!(set.resource_templates.len(), 1);
    let rt = &set.resource_templates[0];
    assert_eq!(rt.name, "petstore.getPetById");
    assert_eq!(rt.uri_template, "petstore://pets/{petId}");
    assert_eq!(rt.backend_kind, "openapi");
    assert_eq!(
        rt.backend_spec,
        json!({ "source": "petstore", "operation": "getPetById" })
    );
}

#[tokio::test]
async fn execute_resource_read_returns_contents_shape() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pets/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 42, "name": "Rex" })))
        .mount(&server)
        .await;

    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config(&server.uri()));
    plugin
        .register_profile(
            "get-pet",
            &json!({ "source": "petstore", "operation": "getPetById" }),
            host(),
        )
        .await
        .expect("register");

    // The gateway injects `uri` + `template_vars` for a resources/read; the
    // path var is also exposed top-level so build_request binds {petId}.
    let resp = plugin
        .execute(
            "get-pet",
            request(json!({
                "petId": 42,
                "uri": "petstore://pets/42",
                "template_vars": { "petId": "42" }
            })),
        )
        .await
        .expect("execute");
    let body: Value = serde_json::from_slice(&resp.payload).unwrap();
    // resources/read shape, NOT the tool envelope.
    let contents = body["contents"].as_array().expect("contents array");
    assert_eq!(contents.len(), 1);
    assert_eq!(contents[0]["uri"], "petstore://pets/42");
    let inner: Value = serde_json::from_str(contents[0]["text"].as_str().expect("text")).unwrap();
    assert_eq!(inner, json!({ "id": 42, "name": "Rex" }));
}

#[tokio::test]
async fn expand_capabilities_enforces_max_capabilities_cap() {
    let plugin = OpenapiBackendPlugin::from_config_json(&exposed_config(json!({
        "filter": { "max_capabilities": 1 }
    })));
    assert!(
        plugin.expand_capabilities().await.is_err(),
        "cap must fail closed"
    );
}

#[tokio::test]
async fn expand_capabilities_empty_without_expose() {
    // Reference-only source (no `expose:`) produces nothing.
    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config("https://127.0.0.1"));
    assert!(
        plugin
            .expand_capabilities()
            .await
            .expect("expand")
            .tools
            .is_empty()
    );
}

#[tokio::test]
async fn execute_maps_upstream_5xx_to_downstream_error() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ping"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config(&server.uri()));
    plugin
        .register_profile(
            "ping",
            &json!({ "source": "petstore", "operation": "ping" }),
            host(),
        )
        .await
        .expect("register");

    let resp = plugin
        .execute("ping", request(json!({})))
        .await
        .expect("execute");
    let env: Value = serde_json::from_slice(&resp.payload).unwrap();
    assert_eq!(env["downstreamError"]["statusCode"], 503);
    assert_eq!(env["downstreamError"]["retryable"], true);
}

// --- Fail-closed config parsing (SDK convention) ------------------------

/// An empty / unit / absent `config:` block is the operator opting out, not
/// a typo — it still yields defaults (no sources registered).
#[test]
fn empty_config_yields_defaults() {
    for block in ["", "  ", "{}", "null"] {
        let plugin = OpenapiBackendPlugin::from_config_json(block);
        assert!(
            plugin.sources.is_empty(),
            "empty config block {block:?} should register no sources"
        );
    }
}

/// A present-but-malformed `config:` block fails CLOSED: it panics rather
/// than silently degrading to defaults (the FFI `make` slot converts the
/// panic into a boot rejection).
#[test]
#[should_panic(expected = "failing closed")]
fn malformed_config_fails_closed() {
    let _ = OpenapiBackendPlugin::from_config_json("not json");
}

/// A stray / renamed / typo'd key in the operator `config:` block is a
/// parse error (`#[serde(deny_unknown_fields)]`) and therefore fails CLOSED
/// the same way a malformed block does — the bad key is refused at boot, not
/// silently ignored. Here the top-level `sourcs` is a typo for `sources`.
#[test]
#[should_panic(expected = "failing closed")]
fn unknown_top_level_key_fails_closed() {
    let _ = OpenapiBackendPlugin::from_config_json(r#"{ "sourcs": [] }"#);
}

/// A typo'd key inside a nested source struct is likewise rejected: `base_ur`
/// for `base_url` must not be silently dropped (it would otherwise fall back
/// to the spec's `servers[0]`, a fail-open footgun).
#[test]
#[should_panic(expected = "failing closed")]
fn unknown_nested_source_key_fails_closed() {
    let _ = OpenapiBackendPlugin::from_config_json(
        r#"{ "sources": [{ "name": "s", "spec": "file:///x.yaml", "base_ur": "https://x" }] }"#,
    );
}

// ---------------------------------------------------------------------------
// Stage-2B conformance: `register_profile` is the single source of truth for
// the openapi binding spec shape, defaults, and value-validation (so the
// gateway's typed `OpenapiBackendConfig` + dynamic_register_spec arm + validate
// arm can be deleted in Stage 3). The binding spec is only the
// `{ source, operation }` selector — both required, no defaults, and (unlike
// transport kinds) it carries no transport-only / `cred://`-bearing field.

/// An empty `source` selector is a config typo and is rejected at register
/// with `InvalidSpec` — the same guarantee the gateway's `validate()` gave
/// (`source must not be empty`), now owned by the plugin.
#[tokio::test]
async fn empty_source_rejected_as_invalid_spec() {
    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config("https://127.0.0.1"));
    let err = plugin
        .register_profile(
            "x",
            &json!({ "source": "  ", "operation": "getPetById" }),
            host(),
        )
        .await
        .expect_err("empty source must fail");
    assert!(
        matches!(&err, mcpg_plugin_protocol::BackendError::InvalidSpec { message }
            if message.contains("source")),
        "expected InvalidSpec mentioning source, got {err:?}"
    );
}

/// An empty `operation` selector is likewise rejected at register with
/// `InvalidSpec` (gateway parity: `operation must not be empty`).
#[tokio::test]
async fn empty_operation_rejected_as_invalid_spec() {
    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config("https://127.0.0.1"));
    let err = plugin
        .register_profile(
            "x",
            &json!({ "source": "petstore", "operation": "" }),
            host(),
        )
        .await
        .expect_err("empty operation must fail");
    assert!(
        matches!(&err, mcpg_plugin_protocol::BackendError::InvalidSpec { message }
            if message.contains("operation")),
        "expected InvalidSpec mentioning operation, got {err:?}"
    );
}

/// A missing required field (`operation` omitted) is a deserialize failure,
/// surfaced as `InvalidSpec` rather than a panic — the binding spec has no
/// defaulted fields to fall back on, so omission is always an error.
#[tokio::test]
async fn missing_required_field_is_invalid_spec() {
    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config("https://127.0.0.1"));
    let err = plugin
        .register_profile("x", &json!({ "source": "petstore" }), host())
        .await
        .expect_err("omitting operation must fail");
    assert!(
        matches!(&err, mcpg_plugin_protocol::BackendError::InvalidSpec { .. }),
        "expected InvalidSpec, got {err:?}"
    );
}

/// A bad value (an `operation` that names no operationId in the source's
/// spec) fails at register with `InvalidSpec` — value-validation lives in the
/// plugin, not a gateway `validate()` arm.
#[tokio::test]
async fn bad_operation_value_is_invalid_spec() {
    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config("https://127.0.0.1"));
    let err = plugin
        .register_profile(
            "x",
            &json!({ "source": "petstore", "operation": "noSuchOp" }),
            host(),
        )
        .await
        .expect_err("unknown operationId must fail");
    assert!(
        matches!(&err, mcpg_plugin_protocol::BackendError::InvalidSpec { .. }),
        "expected InvalidSpec, got {err:?}"
    );
}

/// The binding spec carries no transport-only field: `source`/`operation` are
/// identifiers, not connection facts, and the gateway's openapi binding had no
/// `cred://`-misplacement field policy (creds live in the plugin's
/// `sources[].headers/auth`). A bare `cred://…` placed in the `operation`
/// selector therefore is NOT silently honoured — it simply names no operation
/// and is rejected as `InvalidSpec` (it never reaches an upstream as a
/// transport value).
#[tokio::test]
async fn bare_cred_in_selector_is_rejected_not_honoured() {
    let plugin = OpenapiBackendPlugin::from_config_json(&petstore_config("https://127.0.0.1"));
    let err = plugin
        .register_profile(
            "x",
            &json!({ "source": "petstore", "operation": "cred://issuer/target" }),
            host(),
        )
        .await
        .expect_err("a cred-looking operation names no op and must fail");
    assert!(
        matches!(&err, mcpg_plugin_protocol::BackendError::InvalidSpec { .. }),
        "expected InvalidSpec, got {err:?}"
    );
}

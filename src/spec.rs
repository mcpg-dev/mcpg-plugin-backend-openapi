//! Parse an OpenAPI 3.0/3.1 document, locate operations, compile a
//! per-operation request plan, and derive MCP input/output JSON Schemas.
//!
//! The document is parsed into a `serde_json::Value` tree (JSON or
//! YAML) and walked directly rather than depending on a typed OpenAPI
//! crate. Internal
//! `#/components/...` `$ref`s are inlined with bounded recursion + cycle
//! detection; external refs are not resolved.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::config::SpecSource;

/// HTTP verbs scanned under each path item.
const METHODS: [&str; 7] = ["get", "put", "post", "delete", "patch", "head", "options"];

/// Max `$ref` inlining depth before a cycle/limit leaves the `$ref` in place.
const MAX_REF_DEPTH: usize = 12;

/// A parsed source: the spec document plus the operations indexed by id.
#[derive(Debug, Clone)]
pub struct ParsedSpec {
    pub root: Value,
}

impl ParsedSpec {
    /// Load + parse the document for a source. `file://` paths and inline
    /// docs are supported in Tier 1; `http(s)://` is deferred.
    pub fn load(source: &SpecSource) -> Result<Self, String> {
        let root = match source {
            SpecSource::Inline { inline } => inline.clone(),
            SpecSource::Uri(uri) => {
                if let Some(path) = uri.strip_prefix("file://") {
                    let text = std::fs::read_to_string(path)
                        .map_err(|e| format!("reading spec '{path}': {e}"))?;
                    parse_doc(&text).map_err(|e| format!("parsing spec '{path}': {e}"))?
                } else if uri.starts_with("http://") || uri.starts_with("https://") {
                    return Err(format!(
                        "remote spec sources are not yet supported (deferred to a later phase): '{uri}'"
                    ));
                } else {
                    return Err(format!("unsupported spec source scheme: '{uri}'"));
                }
            }
        };
        if !root.is_object() {
            return Err("spec document root is not a JSON/YAML object".to_owned());
        }
        Ok(Self { root })
    }

    /// Enumerate every operation that carries an `operationId`, with the
    /// metadata bulk auto-expose filters on (Tier 2). Operations without an
    /// `operationId` are skipped (see `DEFERRED.md`).
    pub fn operations(&self) -> Vec<OperationMeta> {
        let mut out = Vec::new();
        let Some(paths) = self.root.get("paths").and_then(Value::as_object) else {
            return out;
        };
        for (path, item) in paths {
            let Some(item) = item.as_object() else {
                continue;
            };
            // Level-1 templates: one `{var}` per path parameter.
            let path_param_count = path.matches('{').count();
            for method in METHODS {
                let Some(op) = item.get(method).and_then(Value::as_object) else {
                    continue;
                };
                let Some(operation_id) = op.get("operationId").and_then(Value::as_str) else {
                    continue;
                };
                let tags = op
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|t| t.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                out.push(OperationMeta {
                    operation_id: operation_id.to_owned(),
                    method: method.to_owned(),
                    path: path.clone(),
                    path_param_count,
                    tags,
                    summary: op.get("summary").and_then(Value::as_str).map(str::to_owned),
                    description: op
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                });
            }
        }
        out
    }

    /// Parse `components.securitySchemes` into the injectable shapes the
    /// plugin understands. Unrecognized schemes (mutualTLS, cookie apiKey)
    /// map to `Unsupported` and are skipped at injection time.
    pub fn security_schemes(&self) -> BTreeMap<String, SecurityScheme> {
        let mut out = BTreeMap::new();
        let Some(schemes) = self
            .root
            .pointer("/components/securitySchemes")
            .and_then(Value::as_object)
        else {
            return out;
        };
        for (name, raw) in schemes {
            let def = self.deref(raw);
            let Some(obj) = def.as_object() else { continue };
            let scheme = match obj.get("type").and_then(Value::as_str).unwrap_or("") {
                "apiKey" => {
                    let pname = obj
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    match obj.get("in").and_then(Value::as_str).unwrap_or("header") {
                        "query" => SecurityScheme::ApiKeyQuery { name: pname },
                        "header" => SecurityScheme::ApiKeyHeader { name: pname },
                        _ => SecurityScheme::Unsupported, // cookie — deferred
                    }
                }
                "http" => match obj
                    .get("scheme")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "bearer" => SecurityScheme::Bearer,
                    "basic" => SecurityScheme::Basic,
                    _ => SecurityScheme::Unsupported,
                },
                // oauth2 / OIDC: the operator supplies an access token via
                // `auth`, injected as a bearer.
                "oauth2" | "openIdConnect" => SecurityScheme::Bearer,
                _ => SecurityScheme::Unsupported,
            };
            out.insert(name.clone(), scheme);
        }
        out
    }

    /// Scheme names of the operation's effective security requirement:
    /// operation-level `security` overrides spec-level; the first
    /// requirement object's keys are returned (OR across objects, AND
    /// within; we apply the first). An explicit `security: []` disables auth.
    fn effective_auth_schemes(&self, op: &Map<String, Value>) -> Vec<String> {
        let security = op.get("security").or_else(|| self.root.get("security"));
        let Some(first) = security
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_object)
        else {
            return Vec::new();
        };
        first.keys().cloned().collect()
    }

    /// Compile the request plan for one operationId, or describe why not.
    pub fn operation_plan(&self, operation_id: &str) -> Result<OperationPlan, String> {
        let paths = self
            .root
            .get("paths")
            .and_then(Value::as_object)
            .ok_or_else(|| "spec has no `paths` object".to_owned())?;

        for (path, item) in paths {
            let Some(item) = item.as_object() else {
                continue;
            };
            // Path-level parameters apply to every operation under the path.
            let path_params = item.get("parameters").and_then(Value::as_array);
            for method in METHODS {
                let Some(op) = item.get(method).and_then(Value::as_object) else {
                    continue;
                };
                if op.get("operationId").and_then(Value::as_str) != Some(operation_id) {
                    continue;
                }
                return Ok(self.build_plan(operation_id, method, path, op, path_params));
            }
        }
        Err(format!("operationId '{operation_id}' not found in spec"))
    }

    fn build_plan(
        &self,
        operation_id: &str,
        method: &str,
        path: &str,
        op: &Map<String, Value>,
        path_level_params: Option<&Vec<Value>>,
    ) -> OperationPlan {
        let mut params: Vec<ParamPlan> = Vec::new();
        let mut seen: Vec<(String, String)> = Vec::new();
        let mut push = |raw: &Value, out: &mut Vec<ParamPlan>| {
            let obj = match self.deref(raw) {
                Value::Object(o) => o,
                _ => return,
            };
            let (Some(name), Some(location)) = (
                obj.get("name").and_then(Value::as_str),
                obj.get("in").and_then(Value::as_str),
            ) else {
                return;
            };
            // De-dupe: an operation-level param overrides a path-level one
            // with the same (name, in).
            let key = (name.to_owned(), location.to_owned());
            if seen.contains(&key) {
                return;
            }
            seen.push(key);
            let schema = obj
                .get("schema")
                .map(|s| self.inline_schema(s, 0))
                .unwrap_or_else(|| json!({}));
            out.push(ParamPlan {
                name: name.to_owned(),
                location: ParamLocation::parse(location),
                required: obj
                    .get("required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                description: obj
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                schema,
            });
        };
        for raw in path_level_params.into_iter().flatten() {
            push(raw, &mut params);
        }
        if let Some(arr) = op.get("parameters").and_then(Value::as_array) {
            for raw in arr {
                push(raw, &mut params);
            }
        }

        let body = self.build_body_plan(op);

        OperationPlan {
            operation_id: operation_id.to_owned(),
            method: method.to_ascii_uppercase(),
            path_template: path.to_owned(),
            params,
            body,
            output_schema: self.derive_output_schema(op),
            auth_schemes: self.effective_auth_schemes(op),
        }
    }

    fn build_body_plan(&self, op: &Map<String, Value>) -> Option<BodyPlan> {
        let rb = self.deref(op.get("requestBody")?);
        let rb = rb.as_object()?;
        let required = rb.get("required").and_then(Value::as_bool).unwrap_or(false);
        let schema = rb
            .get("content")
            .and_then(Value::as_object)
            .and_then(|c| c.get("application/json"))
            .and_then(Value::as_object)
            .and_then(|mt| mt.get("schema"))
            .map(|s| self.inline_schema(s, 0))?;
        Some(BodyPlan { required, schema })
    }

    fn derive_output_schema(&self, op: &Map<String, Value>) -> Option<Value> {
        let responses = self.deref(op.get("responses")?);
        let responses = responses.as_object()?;
        // Lowest 2xx status with an application/json schema.
        let mut codes: Vec<&String> = responses.keys().filter(|k| k.starts_with('2')).collect();
        codes.sort();
        for code in codes {
            let resp = self.deref(&responses[code]);
            if let Some(schema) = resp
                .as_object()
                .and_then(|r| r.get("content"))
                .and_then(Value::as_object)
                .and_then(|c| c.get("application/json"))
                .and_then(Value::as_object)
                .and_then(|mt| mt.get("schema"))
            {
                return Some(self.inline_schema(schema, 0));
            }
        }
        None
    }

    /// Resolve a single top-level `$ref` against `#/components/...`. Leaves
    /// non-ref values and unresolvable refs untouched.
    fn deref(&self, value: &Value) -> Value {
        let mut current = value.clone();
        let mut hops = 0;
        while let Some(ref_str) = current.get("$ref").and_then(Value::as_str) {
            if hops >= MAX_REF_DEPTH {
                break;
            }
            hops += 1;
            match self.resolve_pointer(ref_str) {
                Some(target) => current = target,
                None => break,
            }
        }
        current
    }

    /// Resolve a local JSON pointer `#/a/b/c`. Returns None for external refs.
    fn resolve_pointer(&self, ref_str: &str) -> Option<Value> {
        let pointer = ref_str.strip_prefix("#")?;
        self.root.pointer(pointer).cloned()
    }

    /// Inline a schema for use as an MCP JSON Schema: resolve `$ref`s
    /// against components (bounded + cycle-guarded) and translate OpenAPI
    /// 3.0 `nullable` into 2020-12 union types.
    fn inline_schema(&self, schema: &Value, depth: usize) -> Value {
        if depth >= MAX_REF_DEPTH {
            return schema.clone();
        }
        // Follow a top-level $ref first.
        if schema.get("$ref").is_some() {
            let resolved = self.deref(schema);
            if resolved.get("$ref").is_some() {
                // Unresolvable or cyclic — keep the ref rather than loop.
                return resolved;
            }
            return self.inline_schema(&resolved, depth + 1);
        }
        let Some(obj) = schema.as_object() else {
            return schema.clone();
        };
        let mut out = Map::new();
        for (k, v) in obj {
            match k.as_str() {
                "properties" => {
                    let mut props = Map::new();
                    if let Some(p) = v.as_object() {
                        for (name, sub) in p {
                            props.insert(name.clone(), self.inline_schema(sub, depth + 1));
                        }
                    }
                    out.insert("properties".to_owned(), Value::Object(props));
                }
                "items" => {
                    out.insert("items".to_owned(), self.inline_schema(v, depth + 1));
                }
                "allOf" | "anyOf" | "oneOf" => {
                    let arr = v
                        .as_array()
                        .map(|a| a.iter().map(|s| self.inline_schema(s, depth + 1)).collect())
                        .unwrap_or_default();
                    out.insert(k.clone(), Value::Array(arr));
                }
                // 3.0 `nullable` is folded into the type union below.
                "nullable" => {}
                _ => {
                    out.insert(k.clone(), v.clone());
                }
            }
        }
        // OpenAPI 3.0: `nullable: true` + `type: T` → `type: [T, "null"]`.
        if obj.get("nullable").and_then(Value::as_bool) == Some(true)
            && let Some(Value::String(t)) = out.get("type").cloned()
        {
            out.insert("type".to_owned(), json!([t, "null"]));
        }
        Value::Object(out)
    }
}

/// Parse a document as JSON first, then YAML (YAML is a JSON superset, but
/// trying JSON first gives cleaner errors for `.json` inputs).
fn parse_doc(text: &str) -> Result<Value, String> {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return Ok(v);
    }
    serde_yaml::from_str::<Value>(text).map_err(|e| e.to_string())
}

/// Metadata for one operation, used by Tier-2 auto-expose filtering.
#[derive(Debug, Clone)]
pub struct OperationMeta {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    /// Number of `in: path` parameters — a read-by-id `GET` has ≥1.
    pub path_param_count: usize,
    pub tags: Vec<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
}

impl OperationMeta {
    /// A read-by-id GET maps to a resource template: a `GET` with at least
    /// one path parameter (e.g. `GET /pets/{petId}`).
    pub fn is_read_by_id(&self) -> bool {
        self.method.eq_ignore_ascii_case("get") && self.path_param_count > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamLocation {
    Path,
    Query,
    Header,
    Cookie,
}

impl ParamLocation {
    fn parse(s: &str) -> Self {
        match s {
            "path" => Self::Path,
            "header" => Self::Header,
            "cookie" => Self::Cookie,
            _ => Self::Query,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParamPlan {
    pub name: String,
    pub location: ParamLocation,
    pub required: bool,
    pub description: Option<String>,
    pub schema: Value,
}

#[derive(Debug, Clone)]
pub struct BodyPlan {
    pub required: bool,
    pub schema: Value,
}

/// Everything needed to derive the tool schema and build a request.
#[derive(Debug, Clone)]
pub struct OperationPlan {
    pub operation_id: String,
    pub method: String,
    pub path_template: String,
    pub params: Vec<ParamPlan>,
    pub body: Option<BodyPlan>,
    pub output_schema: Option<Value>,
    /// Security-scheme names to apply to this operation (from its effective
    /// `security` requirement). Resolved against the source's parsed schemes
    /// + operator-supplied `auth` values at dispatch.
    pub auth_schemes: Vec<String>,
}

/// An injectable security scheme parsed from `components.securitySchemes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityScheme {
    ApiKeyHeader {
        name: String,
    },
    ApiKeyQuery {
        name: String,
    },
    /// `Authorization: Bearer <value>` — http-bearer, oauth2, openIdConnect.
    Bearer,
    /// `Authorization: Basic base64(<value>)` — http-basic.
    Basic,
    /// mutualTLS / cookie apiKey / unknown — not injected.
    Unsupported,
}

/// How the requestBody maps onto the flat tool-argument surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLayout {
    /// No requestBody.
    None,
    /// Object body: its properties are hoisted to top-level args, and any
    /// top-level arg not claimed by a param is folded back into the body.
    Hoisted,
    /// Non-object body (array/scalar): carried under a single `body` arg.
    Wrapped,
}

impl OperationPlan {
    pub fn body_layout(&self) -> BodyLayout {
        match &self.body {
            None => BodyLayout::None,
            Some(b) if is_object_schema(&b.schema) => BodyLayout::Hoisted,
            Some(_) => BodyLayout::Wrapped,
        }
    }

    fn body_property_names(&self) -> Vec<String> {
        if self.body_layout() == BodyLayout::Hoisted
            && let Some(body) = &self.body
        {
            return body
                .schema
                .get("properties")
                .and_then(Value::as_object)
                .map(|p| p.keys().cloned().collect())
                .unwrap_or_default();
        }
        Vec::new()
    }

    /// Top-level argument key for each param, index-aligned with
    /// `self.params`. Applies the collision rule once so schema generation
    /// (`input_schema`) and request building (`exec`) agree. Cookie params
    /// get an empty key (excluded from the tool surface in Tier 1).
    pub fn param_keys(&self) -> Vec<String> {
        let mut used: Vec<String> = self.body_property_names();
        if self.body_layout() == BodyLayout::Wrapped {
            used.push("body".to_owned());
        }
        let mut keys = Vec::with_capacity(self.params.len());
        for p in &self.params {
            if p.location == ParamLocation::Cookie {
                keys.push(String::new());
                continue;
            }
            let mut key = p.name.clone();
            if used.contains(&key) {
                key = format!("{}_{}", p.location.prefix(), p.name);
            }
            used.push(key.clone());
            keys.push(key);
        }
        keys
    }

    /// Build the MCP `inputSchema`: param properties + (object) requestBody
    /// properties hoisted to the top level. On a name collision the body
    /// field keeps the bare name and the param is prefixed with its
    /// location (`{loc}_{name}`).
    pub fn input_schema(&self) -> Value {
        let mut properties = Map::new();
        let mut required: Vec<String> = Vec::new();
        let layout = self.body_layout();

        match layout {
            BodyLayout::Hoisted => {
                let body = self.body.as_ref().expect("hoisted implies body");
                if let Some(props) = body.schema.get("properties").and_then(Value::as_object) {
                    for (name, sub) in props {
                        properties.insert(name.clone(), sub.clone());
                    }
                }
                if let Some(reqs) = body.schema.get("required").and_then(Value::as_array) {
                    required.extend(reqs.iter().filter_map(|r| r.as_str().map(str::to_owned)));
                }
            }
            BodyLayout::Wrapped => {
                let body = self.body.as_ref().expect("wrapped implies body");
                properties.insert("body".to_owned(), body.schema.clone());
                if body.required {
                    required.push("body".to_owned());
                }
            }
            BodyLayout::None => {}
        }

        let keys = self.param_keys();
        for (p, key) in self.params.iter().zip(keys.iter()) {
            if key.is_empty() {
                continue; // cookie param
            }
            let mut schema = p.schema.clone();
            if let (Some(desc), Value::Object(o)) = (&p.description, &mut schema) {
                o.entry("description")
                    .or_insert_with(|| Value::String(desc.clone()));
            }
            properties.insert(key.clone(), schema);
            if p.required {
                required.push(key.clone());
            }
        }

        let mut schema = Map::new();
        schema.insert("type".to_owned(), json!("object"));
        schema.insert("properties".to_owned(), Value::Object(properties));
        if !required.is_empty() {
            required.sort();
            required.dedup();
            schema.insert("required".to_owned(), json!(required));
        }
        Value::Object(schema)
    }
}

impl ParamLocation {
    fn prefix(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::Cookie => "cookie",
        }
    }
}

fn is_object_schema(schema: &Value) -> bool {
    schema.get("type").and_then(Value::as_str) == Some("object")
        || schema.get("properties").is_some()
}

//! Turn validated tool arguments + an `OperationPlan` into an HTTP request,
//! send it, and shape the structured envelope the gateway projects onto
//! `tools/call` (a non-null `downstreamError` slot marks the call failed).

use std::time::Instant;

use serde_json::{Map, Value, json};
use url::Url;

use crate::spec::{BodyLayout, OperationPlan, ParamLocation};

/// Request assembled from arguments, before base-URL/auth/header merge.
#[derive(Debug, Clone)]
pub struct PreparedRequest {
    pub method: String,
    /// Path with `{params}` substituted + percent-encoded; no query string.
    pub relative_path: String,
    pub query: Vec<(String, String)>,
    /// Header parameters carried by the operation (not static/auth headers).
    pub header_params: Vec<(String, String)>,
    pub body: Option<Value>,
}

/// Partition `args` into path / query / header / body per the plan.
pub fn build_request(plan: &OperationPlan, args: &Value) -> Result<PreparedRequest, String> {
    let empty = Map::new();
    let args_obj = args.as_object().unwrap_or(&empty);
    let keys = plan.param_keys();

    let mut path = plan.path_template.clone();
    let mut query: Vec<(String, String)> = Vec::new();
    let mut header_params: Vec<(String, String)> = Vec::new();
    let mut consumed: Vec<String> = Vec::new();

    for (p, key) in plan.params.iter().zip(keys.iter()) {
        if key.is_empty() {
            continue; // cookie param, excluded in Tier 1
        }
        let Some(value) = args_obj.get(key) else {
            continue;
        };
        consumed.push(key.clone());
        let rendered = scalar_to_string(value);
        match p.location {
            ParamLocation::Path => {
                if is_dot_segment(&rendered) {
                    return Err(format!(
                        "path parameter `{}` must not consist only of dots",
                        p.name
                    ));
                }
                let placeholder = format!("{{{}}}", p.name);
                path = path.replace(&placeholder, &percent_encode_path(&rendered));
            }
            ParamLocation::Query => query.push((p.name.clone(), rendered)),
            ParamLocation::Header => header_params.push((p.name.clone(), rendered)),
            ParamLocation::Cookie => {}
        }
    }

    let body = match plan.body_layout() {
        BodyLayout::None => None,
        BodyLayout::Wrapped => args_obj.get("body").cloned(),
        BodyLayout::Hoisted => {
            // Everything not consumed by a param folds back into the body.
            let mut obj = Map::new();
            for (k, v) in args_obj {
                if !consumed.contains(k) {
                    obj.insert(k.clone(), v.clone());
                }
            }
            Some(Value::Object(obj))
        }
    };

    Ok(PreparedRequest {
        method: plan.method.clone(),
        relative_path: path,
        query,
        header_params,
        body,
    })
}

/// Join the source base URL with the prepared relative path + query.
pub fn full_url(
    base_url: &str,
    relative_path: &str,
    query: &[(String, String)],
) -> Result<String, String> {
    let base = Url::parse(base_url).map_err(|e| format!("invalid base_url '{base_url}': {e}"))?;
    // Preserve any base path prefix, then append the operation path.
    let base_path = base.path().trim_end_matches('/');
    let joined = format!("{}{}", base_path, relative_path);
    let mut url = base.clone();
    url.set_path(&joined);
    if !query.is_empty() {
        let mut qp = url.query_pairs_mut();
        for (k, v) in query {
            qp.append_pair(k, v);
        }
    }
    Ok(url.to_string())
}

/// One HTTP exchange outcome.
#[derive(Debug, Clone)]
pub struct HttpOutcome {
    pub status: u16,
    pub content_type: Option<String>,
    pub body_text: String,
    pub body_truncated: bool,
    pub duration_ms: u128,
}

/// Send the request on a (DNS-pinned, SSRF-guarded) client.
pub async fn send_request(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&Value>,
    max_response_bytes: usize,
) -> Result<HttpOutcome, String> {
    let m = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| format!("invalid HTTP method '{method}'"))?;
    let mut req = client.request(m, url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(b) = body {
        req = req.json(b);
    }
    let started = Instant::now();
    let resp = req
        .send()
        .await
        .map_err(|e| format!("transport error: {e}"))?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("reading response body: {e}"))?;
    let truncated = bytes.len() > max_response_bytes;
    let slice = &bytes[..bytes.len().min(max_response_bytes)];
    Ok(HttpOutcome {
        status,
        content_type,
        body_text: String::from_utf8_lossy(slice).into_owned(),
        body_truncated: truncated,
        duration_ms: started.elapsed().as_millis(),
    })
}

/// Build the structured envelope. `outcome` is `Err` for a transport-level
/// failure (no response); otherwise the status decides `downstreamError`.
pub fn build_envelope(
    tool_name: &str,
    profile: &str,
    prepared: &PreparedRequest,
    final_url: &str,
    outcome: &Result<HttpOutcome, String>,
) -> Value {
    let request = json!({
        "method": prepared.method,
        "url": final_url,
        "query": prepared.query.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "body": prepared.body.clone(),
    });

    match outcome {
        Err(msg) => json!({
            "toolName": tool_name,
            "profile": profile,
            "request": request,
            "response": Value::Null,
            "error": msg,
            "downstreamError": {
                "kind": "transport_error",
                "message": msg,
                "retryable": true,
            },
        }),
        Ok(out) => {
            let is_json = out
                .content_type
                .as_deref()
                .map(|c| c.contains("json"))
                .unwrap_or(false);
            let parsed: Option<Value> = if is_json {
                serde_json::from_str(&out.body_text).ok()
            } else {
                None
            };
            let ok = out.status / 100 == 2;
            let downstream_error = if ok {
                Value::Null
            } else {
                json!({
                    "kind": "unexpected_status_code",
                    "statusCode": out.status,
                    "message": format!("upstream responded {}", out.status),
                    "retryable": out.status >= 500,
                })
            };
            json!({
                "toolName": tool_name,
                "profile": profile,
                "request": request,
                "response": {
                    "statusCode": out.status,
                    "contentType": out.content_type,
                    "body": out.body_text,
                    "bodyTruncated": out.body_truncated,
                    "json": parsed,
                    "durationMs": out.duration_ms,
                },
                "error": Value::Null,
                "downstreamError": downstream_error,
            })
        }
    }
}

/// Render a scalar JSON value for use in a path/query/header. Strings pass
/// through; numbers/bools stringify without quotes; structured values are
/// JSON-encoded (best-effort — uncommon in path/query positions).
fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Percent-encode a path segment: keep RFC 3986 unreserved characters,
/// escape everything else (including `/`, so a value can't inject path
/// segments).
fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// True when a rendered path parameter would form a dot segment.
///
/// `.` is unreserved, so encoding preserves it, and percent-encoding cannot
/// help either — URL parsing treats `%2e` as a dot when removing segments.
/// A parameter of `..` therefore walks up out of the operation's path and
/// reaches a different endpoint, carrying whatever auth the binding
/// attaches. The value has to be refused instead.
fn is_dot_segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b == b'.')
}

#[cfg(test)]
mod path_param_tests {
    use super::*;

    /// A path parameter of `..` walks out of the operation's path — URL
    /// parsing removes the dot segment along with the one before it — and
    /// reaches an endpoint the binding never scoped, carrying its auth.
    /// `.` is unreserved so the encoder preserves it, and `%2e` is treated
    /// as a dot for segment removal, so the value must be refused.
    #[test]
    fn dot_only_path_params_are_rejected() {
        for bad in [".", "..", "..."] {
            assert!(is_dot_segment(bad), "{bad} should be refused");
        }
        for ok in ["", "42", "a.b", "..a", "v1.0"] {
            assert!(!is_dot_segment(ok), "{ok} should be allowed");
        }
    }

    /// The encoder still has to stop separator injection.
    #[test]
    fn separators_are_escaped() {
        assert_eq!(percent_encode_path("a/b"), "a%2Fb");
        assert_eq!(percent_encode_path("a?b#c"), "a%3Fb%23c");
        assert_eq!(percent_encode_path("v1.0-x_y~z"), "v1.0-x_y~z");
    }
}

# OpenAPI Binding — `dev.mcpg.backend.openapi`

> class `backend` · `native` · package `mcpg-plugin-backend-openapi` · artifact `libmcpg_plugin_backend_openapi.so` · Apache-2.0

Turns an OpenAPI 3.0/3.1 document into MCP capabilities. You register the spec
once as a named source in the plugin's own config; from then on an operation
becomes a tool whose `inputSchema` and `outputSchema` are derived from that
operation's parameters, `requestBody`, and responses — nobody hand-writes a
schema, and nobody hand-writes a URL. Calls dispatch as outbound HTTP over the
same SSRF-guarded core the `http` / `grpc` / `graphql` backends use, with auth
injected exactly as the spec's `securitySchemes` describe it. Reach for it when
the system you want to expose already publishes an OpenAPI document and you would
otherwise be transcribing dozens of endpoints into `http` bindings by hand.

## What it does
- Loads each configured source's spec (inline in config, or `file://`), inlining
  internal `#/components/…` `$ref`s with bounded depth and cycle detection.
- Derives the MCP `inputSchema` for an operation by hoisting an object
  `requestBody`'s properties to the top level and merging path / query / header
  parameters alongside them; on a name collision the body field keeps the bare
  name and the parameter is prefixed with its location (`query_id`, `path_id`,
  `header_id`). A non-object body is carried under a single `body` argument.
- Derives `outputSchema` from the operation's success response, and reports both
  through the plugin ABI so the gateway populates the tool descriptor itself.
- Assembles each call from the arguments: path placeholders are substituted and
  percent-encoded, query parameters appended, header parameters attached, and
  everything left over folded back into the JSON body.
- Injects credentials the way the spec says to: `apiKey` in a header or query
  parameter, HTTP `bearer`, HTTP `basic` (base64-encoded from your configured
  value), and `oauth2` / `openIdConnect` as a bearer token. `mutualTLS` and
  cookie `apiKey` are recognised but not injected.
- Optionally bulk-exposes a whole source: with `expose.tools: true` the plugin
  enumerates every filtered operation at boot and the gateway synthesises one
  capability per operation, with read-by-id `GET`s becoming resource templates.
- Fails closed on config: a malformed `config:` block refuses the plugin rather
  than degrading to defaults, an unknown `source` or `operation` is an
  invalid-spec error at boot, and a source that would exceed
  `filter.max_capabilities` refuses to expand rather than silently minting
  thousands of tools.
- Declares the `network_outbound` capability; the gateway refuses to load the
  plugin unless the `plugins[]` entry grants it.

## Configuration
Unusually for a backend, most of the configuration lives on the plugin, not on
the binding: the source registry sits under the `config:` key of the entry in
the flat top-level `plugins:` list, and each binding names only which source and
which operation it wants.

```yaml
plugins:
  - id: dev.mcpg.backend.openapi
    class: backend
    kind: native
    source:
      path: ./plugins/libmcpg_plugin_backend_openapi.so
      # or, platform-agnostic:
      # oci: ghcr.io/mcpg-dev/source-code/plugins/backend-openapi:protocol-1
    granted_capabilities:
      - network_outbound
    config:
      sources:
        - name: petstore
          spec: "file:///etc/mcpg/specs/petstore.yaml"
          base_url: https://api.petstore.example.com
          headers:
            User-Agent: mcpg-gateway
          auth:
            # Key is the securityScheme name declared in the spec.
            api_key: "${cred://dev.mcpg.credential.static/petstore}"
          response:
            max_response_bytes: 1048576
            timeout_ms: 8000

mcp:
  capabilities:
    tools:
      - name: petstore.adopt
        description: Adopt a pet.
        backend: { kind: openapi, source: petstore, operation: adoptPet }
```

### Source fields (`plugins[].config.sources[]`)

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | — (required) | Source id that bindings reference. |
| `spec` | string or object | — (required) | Either a URI string (`file:///path/to/spec.yaml`, JSON or YAML) or `{ inline: <document> }`. Remote `http(s)://` spec URLs are refused. |
| `base_url` | string | spec `servers[0].url` | Upstream base URL. Required when the spec declares no absolute `servers[].url`. |
| `headers` | map<string,string> | `{}` | Static headers sent on every request to this source. Values may carry a `${cred://issuer/target}` token. |
| `auth` | map<string,string> | `{}` | Secret per spec `securityScheme` name. The spec decides how it is injected; this is only the value. May carry a `${cred://issuer/target}` token. |
| `upstream_safety.allow_private_backends` | bool | `false` | Allow an upstream that resolves only to private or loopback addresses. |
| `upstream_safety.allow_insecure_http` | bool | `false` | Allow an `http://` base URL. |
| `response.max_response_bytes` | usize | `1048576` | Response body cap; a larger body is truncated and flagged. |
| `response.timeout_ms` | u64 | `8000` | Per-call timeout. |
| `expose` | object | unset | Bulk auto-expose. Absent means reference-only: the source serves explicit bindings alone. |
| `filter` | object | see below | Whitelist / blacklist applied to auto-exposed operations. |
| `governance` | object | unset | Governance block relayed verbatim onto every auto-exposed capability of this source. The plugin does not interpret it. |
| `retry` | object | unset | Retry block relayed the same way. |

Unknown fields are rejected on the `config:` block itself, on the source entry,
on `upstream_safety`, on `response`, and on `filter`. `expose` is the deliberate
exception: it accepts and ignores keys it does not know.

### Binding fields (`backend: { kind: openapi, … }`)

Exactly two, both required: `source` names a registered source and `operation`
names an `operationId` in that source's spec. Neither may be blank, and an
operation without an `operationId` in the document is not addressable.

## Bulk auto-expose

Set `expose.tools: true` on a source and the gateway asks the plugin for the
source's capability set at boot, then synthesises one capability per surviving
operation — so a whole API surfaces without writing a single capability entry. An
explicitly declared binding with the same name wins over the synthetic one.

```yaml
      sources:
        - name: petstore
          spec: { inline: { openapi: "3.0.3" } }   # or a file:// URI
          base_url: https://api.petstore.example.com
          expose:
            tools: true
            tool_prefix: "petstore."
            reads_as_resource_templates: true
            resource_uri_prefix: "petstore://"
          filter:
            include_tags: ["pet", "store"]
            exclude_operations: ["uploadFile"]
            methods: ["get", "post", "put", "delete"]
            max_capabilities: 200
```

| Field | Type | Default | Description |
|---|---|---|---|
| `expose.tools` | bool | `false` | Enumerate this source's operations as capabilities. |
| `expose.tool_prefix` | string | `""` | Prepended to each `operationId` to form the capability name. |
| `expose.reads_as_resource_templates` | bool | `true` | A read-by-id `GET` (a `GET` with at least one path parameter) becomes a resource template instead of a tool. |
| `expose.resource_uri_prefix` | string | `<source>://` | URI scheme prefix for generated resource templates. |
| `filter.include_tags` | string[] | `[]` | When non-empty, an operation must carry one of these tags. |
| `filter.exclude_tags` | string[] | `[]` | Operations carrying any of these tags are dropped. |
| `filter.include_operations` | string[] | `[]` | When non-empty, only these `operationId`s survive. |
| `filter.exclude_operations` | string[] | `[]` | These `operationId`s are dropped. |
| `filter.methods` | string[] | `[]` | HTTP method names to keep, matched case-insensitively; empty keeps all. |
| `filter.max_capabilities` | usize | `200` | Hard per-source cap. Exceeding it fails the boot. |

## Security
`headers` and `auth` values accept a `${cred://issuer/target}` token, resolved
per caller identity through the gateway's credential issuer at dispatch time and
spliced back in before the value is used — so a `basic` secret is base64-encoded
after resolution, and an `apiKey`-in-query value is injected after resolution. A
bare `cred://…` outside `${}` is data and travels upstream verbatim.

A credential resolves only from an operator-authored config value. Header slots
are allowlisted by the names whose *config* value carried a token, so an
operation with an `in: header` parameter cannot displace a resolved secret or
smuggle a credential reference in through a request argument. The per-scheme
`auth` map comes solely from config and is scanned in full.

Every upstream client is built behind the DNS-rebinding guard: the host is
resolved, private and loopback resolutions are refused unless the source sets
`upstream_safety.allow_private_backends`, and the validated address is pinned so
the resolution cannot change underneath the connection. The client is built
eagerly at registration, so a bad upstream surfaces at boot rather than on the
first call.

## Response envelope
A call returns a structured envelope carrying `toolName`, `profile`, the
`request` that was sent (method, URL, query pairs, body), and a `response`
object with `statusCode`, `contentType`, the body text, `bodyTruncated`,
`durationMs`, and — for a JSON content type — the parsed `json`. A non-2xx
status or a transport failure populates `downstreamError`, which is what marks
the `tools/call` result as an error. Audit records carry
`openapi.transport: plugin` plus the source name and `operationId`.

## MCP surfaces & composition

### As a resource template
A read-by-id `GET` maps naturally onto a resource template. Under
`mcp.capabilities.resource_templates[]` the gateway supplies the extracted
template variables in the call arguments, and on a 2xx the plugin returns the
`resources/read` `{contents:[…]}` body keyed on the requested URI; a failure
falls through to the tool envelope so the error is still visible.

```yaml
  capabilities:
    resource_templates:
      - name: petstore.pet
        description: A pet by id.
        uri_template: "petstore://pets/{petId}"
        backend: { kind: openapi, source: petstore, operation: getPetById }
```

With `expose.tools: true` and `reads_as_resource_templates` left at its default,
these templates are generated for you.

### Schemas & annotations
`inputSchema` and `outputSchema` come from the spec, so a capability entry
normally declares neither. When an entry does declare one, the gateway merges it
over the derived schema key by key and the operator's value wins — the escape
hatch for a document whose schema is too loose to be useful, or whose
descriptions are worth rewriting for a model audience. Declare `annotations` on
the entry when the operation's read-only or destructive nature should be
advertised to clients.

## Build
Default feature set is OFF (avoids `mcpg_plugin_register` linker
collisions in the workspace build); opt in to the cdylib:

```bash
cargo build -p mcpg-plugin-backend-openapi --features cdylib-export --release   # → target/release/libmcpg_plugin_backend_openapi.so
```

## Testing
The suite is hermetic — specs are inlined and upstreams are `wiremock` servers
or literal loopback addresses, so no network access is required:

```bash
cargo test -p mcpg-plugin-backend-openapi
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Backend binding reference: <https://mcpg.dev/docs/reference/backends>
- Plugin classes and the plugin ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Known gaps and the reasoning behind each are tracked in the development
  repository, alongside the issue tracker.
- The shared HTTP core this plugin dispatches over: `libs/plugins/backend/net-core`

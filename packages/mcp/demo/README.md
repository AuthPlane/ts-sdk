# Calculator Service Example

A minimal MCP server demonstrating Authplane JWT authentication with per-tool scope enforcement, plus a tool that exercises the URL-elicitation flow against a Broker resource.

| Tool | Required scope | What it shows |
|------|---------------|---------------|
| `add` | `tools/add` | Per-tool scope enforcement (token-level). |
| `multiply` | `tools/multiply` | Per-tool scope enforcement (token-level). |
| `consent_demo` | `tools/consent_demo` | Wrapped `client.exchange()` translating the AS's `consent_required` response into MCP `UrlElicitationRequiredError` (`-32042`). Targets the demo authserver's `google-calendar` Broker resource. |
| `debug_client_credentials` / `debug_introspect_token` / `debug_exchange_token` / `debug_verify_dpop_proof` | `tools/add` | Direct `AuthplaneClient` calls for hand-testing token operations from an MCP client. |

Tokens must carry the scope for the specific tool being called. A token with only `tools/add` can call `add` but not `multiply` or `consent_demo`.

## Prerequisites

- Node.js 22+
- The **authserver authorization server** running locally — start it with:

  ```bash
  ./run-demo-server.sh
  ```

  This starts the auth server on `http://127.0.0.1:9000` by default.

## Setup

1. Copy the environment file (the demo key is pre-filled):

   ```bash
   cp demo/.env.example demo/.env
   ```

   `AUTHPLANE_RESOURCE` is used both as the JWT `aud` claim and as the `client_id` for token introspection.
   Legacy env names (`RESOURCE_URL`, `ISSUER_URL`, `CLIENT_SECRET`) are still accepted for compatibility.

2. Run the MCP server:

   ```bash
   cd packages/mcp
   ./demo/run.sh
   ```

   `run.sh` installs dependencies and starts the server on port `8080`.

3. **(Optional)** To connect with a real MCP client (e.g. Cursor, Claude Desktop) using a client_credentials token:

   ```bash
   ./demo/run-mcp-client.sh
   # or
   node demo/run-mcp-client.mjs
   ```

   Both fetch an access token from authserver and run `mcp-remote` with Bearer auth. For Cursor/Claude, use the **Node** runner in MCP config (`command: "node"`, `args: ["/path/to/demo/run-mcp-client.mjs"]`) if the host reports "Operation not permitted" when running the `.sh` script.

## How it works

```
MCP Client ──Bearer JWT──► mcpserver.ts (port 8080)
                                │
                                ├─ authplaneMcpAuth()
                                │    • Discovers JWKS from AUTHPLANE_ISSUER
                                │    • Validates JWT signature, aud, exp
                                │    • Introspects token (revocation check)
                                │
                                └─ requireScope("tools/add", extra.authInfo)
                                     • Reads authInfo from handler extra param
                                     • Throws Error if scope missing
                                       → MCP returns error to client
```

## Key patterns shown

**`authplaneMcpAuth()`** — wires up the verifier, bearer auth middleware, and Protected Resource Metadata in one call. The `scopes` list advertises supported scopes in the Protected Resource Metadata (`/.well-known/oauth-protected-resource`) and, by default, is also used as the `requiredScopes` list for the MCP auth middleware. This mirrors the official MCP SDK behaviour, where the configured required scopes double as the supported scopes for the resource.

**`requireScope(scope, authInfo)`** — call at the top of any tool handler to enforce per-tool scope. If the token is missing the scope the tool returns an error result to the MCP client.

**`IntrospectionRevocation`** — enables RFC 7662 token introspection on every `verify()` call using the adapter-supplied `asCredentials`. When `active: false` is returned, `TokenRevoked` is thrown (mapped to MCP's `InvalidTokenError`).

**`consent_demo`** — exchanges the inbound user token for a Google Calendar token via RFC 8693. The demo authserver registers `google-calendar` as a Broker resource with fake upstream credentials, so the AS consistently returns `consent_required` + a `consent_url`; the adapter's wrapped `client.exchange()` translates that into MCP `-32042` automatically — no `try/catch` in the tool handler.

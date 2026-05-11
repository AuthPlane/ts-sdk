# Calculator Service Example

A minimal FastMCP server demonstrating Authplane JWT authentication with per-tool scope enforcement.

The server exposes two tools:

| Tool | Required scope |
|------|---------------|
| `add` | `tools/add` |
| `multiply` | `tools/multiply` |

Tokens must carry the scope for the specific tool being called. A token with only `tools/add` can call `add` but not `multiply`.

## Prerequisites

- Node.js 22+
- The **authserver authorization server** running locally with these token settings:
  - `AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true`
  - `AUTHPLANE_TOKEN_EXCHANGE_ENABLED=true`
  - `AUTHPLANE_DPOP_ENABLED=true`
  - `AUTHPLANE_TOKEN_EXCHANGE_ALLOW_SELF_EXCHANGE=true` (required when the same client performs both `client_credentials` and `token_exchange`, as in `demo-fastmcp-dpop.ts`)

Start `authserver` with Docker Compose from the `authserver` repository:

  ```bash
  cd /path/to/authserver
  export AUTHPLANE_SESSION_SECRET="$(openssl rand -hex 32)"
  export AUTHPLANE_ADMIN_API_KEY="$(openssl rand -hex 32)"
  docker compose -f deploy/docker-compose.sqlite.yml up -d --build
  ```

  This starts the auth server on `http://localhost:9000` (OAuth) and `http://localhost:9001` (admin API) by default.

Before running this demo, ensure your client is created with:

- Grant types: `client_credentials`, `urn:ietf:params:oauth:grant-type:token-exchange`
- Scope: `tools/add` (and/or `tools/multiply`, depending on what you call)

## Setup

1. Copy the environment file (the demo key is pre-filled):

   ```bash
   cp demo/.env.example demo/.env
   ```

   `AUTHPLANE_BASE_URL` is the root URL of this server. The JWT audience (`aud`) is derived as `AUTHPLANE_BASE_URL/mcp` and also used as `client_id` for token introspection.
   Legacy env names (`BASE_URL`, `ISSUER_URL`, `CLIENT_SECRET`) are still accepted for compatibility.

2. Run the MCP server:

   ```bash
   cd packages/fastmcp
   ./demo/run.sh
   ```

   `run.sh` installs dependencies and starts the server on port `8080`.

## How it works

Note that FastMCP filters tools if the scope is not available.

```
MCP Client ──Bearer JWT──► mcpserver.ts (port 8080)
                                │
                                ├─ authplaneFastMcpAuth()
                                │    • Discovers JWKS from AUTHPLANE_ISSUER
                                │    • Validates JWT signature, aud, exp
                                │    • Introspects token (revocation check)
                                │
                                └─ tools registered with FastMCP
                                     • FastMCP enforces scope via authenticate()
                                       → Returns 401/403 to client if scope missing
```

## Key patterns shown

**`authplaneFastMcpAuth()`** — wires up the verifier and auth provider in one call. The `scopes` list advertises supported scopes in the Protected Resource Metadata (`/.well-known/oauth-protected-resource`); it does **not** require all scopes to be present in every token.

**`IntrospectionRevocation`** — enables RFC 7662 token introspection on every `verify()` call using the adapter-supplied `asCredentials`. When `active: false` is returned, the token is rejected.

> The MCP-adapter equivalent of this demo also ships a `consent_demo` tool that surfaces MCP's URL elicitation flow (`-32042`). It is intentionally **not** included here: fastmcp 3.35.0 catches every non-`UserError` thrown from a tool handler and wraps it as `{ isError: true, content: [...] }`, so a `UrlElicitationRequiredError` thrown from `client.exchange()` would never reach the JSON-RPC wire. Use the lower-level `@authplane/mcp` adapter to demo the flow end-to-end. See `packages/fastmcp/docs/user-guide.md` → URL elicitation for the full Limitation note.

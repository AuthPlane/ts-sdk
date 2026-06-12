# Calculator Service Example (Hono)

A minimal [Hono](https://hono.dev) server demonstrating Authplane JWT authentication with per-route scope enforcement.

The server exposes three routes:

| Route                 | Method | Required scope      |
|-----------------------|--------|---------------------|
| `/math/add`           | POST   | `tools/add`         |
| `/math/multiply`      | POST   | `tools/multiply`    |
| `/me`                 | GET    | (any valid token)   |

Tokens must carry the scope for the specific route being called. A token with only `tools/add` can call `/math/add` but not `/math/multiply`.

## Prerequisites

- Node.js 20+
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

2. Run the Hono server:

   ```bash
   cd packages/hono
   ./demo/run.sh
   ```

   `run.sh` installs dependencies and starts the server on port `8080`.

3. Exercise it with `curl`:

   ```bash
   # Fetch a client_credentials token from your authserver (example)
   TOKEN=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
     -d 'grant_type=client_credentials&scope=tools/add&resource=http://127.0.0.1:8080/mcp' \
     http://127.0.0.1:9000/token | jq -r .access_token)

   # Happy path
   curl -s -X POST http://127.0.0.1:8080/math/add \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"a":2,"b":3}'
   # => {"result":5}

   # Insufficient scope (token has tools/add but route needs tools/multiply)
   curl -i -X POST http://127.0.0.1:8080/math/multiply \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"a":2,"b":3}'
   # => HTTP/1.1 403 Forbidden
   #    WWW-Authenticate: Bearer error="insufficient_scope", ..., scope="tools/multiply"
   ```

## How it works

```
HTTP Client ──Bearer JWT──► server.ts (port 8080)
                                │
                                ├─ authplaneHonoAuth()
                                │    • Discovers JWKS from AUTHPLANE_ISSUER
                                │    • Validates JWT signature, aud, exp
                                │    • Introspects token (revocation check)
                                │
                                └─ requireScope(c, "tools/add")
                                     • Reads auth info from c.get("auth")
                                     • Throws core InsufficientScope if missing
                                       → app.onError bridges to RFC 6750 403
```

## Key patterns shown

**`authplaneHonoAuth()`** — wires up the verifier, bearer auth middleware, and Protected Resource Metadata in one call. The `scopes` list advertises supported scopes in the Protected Resource Metadata (`/.well-known/oauth-protected-resource/...`) and, by default, is also used as the `requiredScopes` list for the auth middleware. This mirrors the Express `@authplane/mcp` adapter.

**`requireScope(c, scope)`** — call at the top of any handler to enforce per-route scope. If the token is missing the scope the helper throws core `InsufficientScope`, which the `app.onError` hook translates to a 403 with a standards-compliant `WWW-Authenticate: Bearer error="insufficient_scope"` header.

**`app.onError`** — centralised RFC 6750 error bridge. The middleware already handles its own errors (invalid tokens become 401 with `WWW-Authenticate` set), but errors thrown *from inside a handler* (like `requireScope`) escape into Hono's error hook. The demo funnels any core `AuthplaneError` through `httpStatus()` + `wwwAuthenticate()`.

**`IntrospectionRevocation`** — enables RFC 7662 token introspection using the resource URL as `clientId` and the admin-provisioned secret. Without it, revoked tokens would remain accepted until their `exp`.

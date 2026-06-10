# Calculator Service Example (NestJS)

A minimal [NestJS](https://nestjs.com) server demonstrating Authplane JWT authentication with per-route scope enforcement.

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

1. Copy the environment file:

   ```bash
   cp demo/.env.example demo/.env
   ```

   `AUTHPLANE_RESOURCE` is used both as the JWT `aud` claim and as the `client_id` for token introspection.
   Legacy env names (`RESOURCE_URL`, `ISSUER_URL`, `CLIENT_SECRET`) are still accepted for compatibility.

2. Run the NestJS server:

   ```bash
   cd packages/nestjs
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
                                ├─ AuthplaneAuthGuard (from AuthplaneModule)
                                │    • Discovers JWKS from AUTHPLANE_ISSUER
                                │    • Validates JWT signature, aud, exp
                                │    • Introspects token (revocation check)
                                │    • Enforces module + @RequireScopes(...)
                                │
                                └─ @AuthInfo() inside the handler
                                     • Reads the verified claims off the request
                                     • AuthplaneExceptionFilter bridges guard
                                       throws to RFC 6750 401 / 403 responses
```

## Key patterns shown

**`AuthplaneModule.forRoot({ ... })`** — wires up the verifier, auth guard, exception filter, shutdown hook, and Protected Resource Metadata controller in one import. The `scopes` list advertises supported scopes in the PRM document (`/.well-known/oauth-protected-resource/...`) and, by default, is also used as the `requiredScopes` list for the guard.

**`@UseGuards(AuthplaneAuthGuard)` + `@RequireScopes("…")`** — compose the guard at the controller level and layer per-handler scope enforcement through the decorator. The guard merges module-level `requiredScopes` with every `@RequireScopes(...)` annotation `Reflector` sees for the handler.

**`@AuthInfo()`** — parameter decorator that reads the verified `VerifiedClaims` (from `@authplane/sdk/core`) the guard stashed on the request. Equivalent to `req[AUTH_INFO_REQUEST_KEY]` but type-safe.

**`AuthplaneExceptionFilter`** — bundled with the module; funnels every core `AuthplaneError` through `httpStatus()` + `wwwAuthenticate()`: `TokenMissing`/`TokenExpired`/`InvalidSignature` → 401 `Bearer error="invalid_token"`, `InsufficientScope` → 403 `Bearer error="insufficient_scope", scope="…"`, `JWKSFetchError`/`MetadataFetchError` → 503, DPoP failures → 401 `DPoP error="invalid_token"`. The RFC 9728 `resource_metadata=` pointer is included on every failure. Works unchanged on Express and Fastify.

**`IntrospectionRevocation`** — enables RFC 7662 token introspection using the resource URL as `clientId` and the admin-provisioned secret. Without it, revoked tokens would remain accepted until their `exp`. Obtain it via the singleton `IntrospectionRevocation.get()`.

**`app.enableShutdownHooks()`** — wakes up `AuthplaneShutdownHook` so `await client.close()` runs when the process receives `SIGINT` / `SIGTERM`, stopping the JWKS / metadata refresh timers.

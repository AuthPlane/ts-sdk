# `@authplane/hono` — User Guide

Complete reference for the Authplane adapter for [Hono](https://hono.dev). Starts with the quickstart and builds to advanced scenarios. For a short overview see the [package README](../README.md).

## Table of contents

- [Install](#install)
- [Quickstart](#quickstart)
- [`authplaneHonoAuth(options)` reference](#authplanehonoauthoptions-reference)
- [Context shape (`c.get("auth")`)](#context-shape-cgetauth)
- [Scope enforcement](#scope-enforcement)
- [Per-route scope enforcement with `requireScope`](#per-route-scope-enforcement-with-requirescope)
- [Error bridging with `app.onError`](#error-bridging-with-apponerror)
- [DPoP-bound tokens](#dpop-bound-tokens)
- [Introspection and revocation](#introspection-and-revocation)
- [Custom fetch settings](#custom-fetch-settings)
- [Runtime portability](#runtime-portability)
- [Local example commands](#local-example-commands)
- [Error handling](#error-handling)
- [Cleanup](#cleanup)

## Install

```bash
npm install @authplane/sdk @authplane/hono hono
```

Requires Node 20 LTS or newer when running on Node. The adapter itself is runtime-agnostic (see [Runtime portability](#runtime-portability)).

## Quickstart

A complete Hono server with Authplane auth on Node:

```ts
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import {
  authplaneHonoAuth,
  type HonoAuthVariables,
} from "@authplane/hono";

const auth = await authplaneHonoAuth({
  issuer: "http://localhost:9000",
  resource: "http://localhost:8090/mcp",
  scopes: ["tools/weather"],
  devMode: true,
});

const app = new Hono<{ Variables: HonoAuthVariables }>();

app.get(
  auth.protectedResourceMetadataPath,
  auth.protectedResourceMetadataHandler,
);

app.use("/mcp", auth.bearerAuth);
app.post("/mcp", (c) => {
  const info = c.get("auth");
  return c.json({ ok: true, clientId: info.clientId, scopes: info.scopes });
});

serve({ fetch: app.fetch, port: 8090 });
```

The adapter produces:

- a Hono `MiddlewareHandler` (`bearerAuth`) that verifies tokens and attaches the claims to `c.get("auth")`;
- a Hono `Handler` that serves RFC 9728 Protected Resource Metadata;
- an `AuthplaneResource` for direct lower-level access when needed.

## `authplaneHonoAuth(options)` reference

### Options

| Field | Type | Purpose |
|---|---|---|
| `issuer` | `string` (required) | Authplane issuer URL (your `authserver`). |
| `resource` | `string` (required) | Resource URI tokens must be audience-bound to (`aud` claim). |
| `scopes` | `string[]` (optional) | All scopes this server supports. Used for PRM and, by default, as `requiredScopes`. |
| `requiredScopes` | `string[]` (optional) | Override of scopes enforced by `bearerAuth`. Defaults to `scopes` when absent (matches `@authplane/mcp` behaviour). |
| `asCredentials` | `{ clientId, clientSecret }` (optional) | AS client credentials. Required when introspection/revocation is enabled. |
| `fetchSettings` | `FetchSettings` (optional) | Outbound fetch hardening (SSRF protection, timeouts, allowlists) applied to **both** AS metadata and JWKS document fetches. |
| `jwksRefreshSeconds` | `number` (optional, default `300`) | JWKS cache TTL. |
| `metadataRefreshSeconds` | `number` (optional, default `3600`) | Metadata cache TTL. |
| `devMode` | `boolean` (optional, default `false`) | Relaxes HTTPS and private-host restrictions. Only for local dev. |
| `revocationChecker` | `RevocationChecker \| IntrospectionRevocation` (optional) | Enable real-time revocation checking. |
| `replayStore` | `DPoPReplayStore` (optional) | Convenience shortcut folded into `inboundDPoP.replayStore`. Cannot be combined with `inboundDPoP.replayStore`. |
| `inboundDPoP` | `InboundDPoPOptions` (optional) | Full DPoP knobs (`required`, `maxProofAgeSeconds`, `allowedProofAlgorithms`, `replayStore`). |
| `dpopProvider` | `DPoPProvider` (optional) | Outbound DPoP provider for AS-facing calls (introspection, token exchange, revocation). |
| `cacheTtlBufferSeconds` | `number` (optional, default `30`) | Buffer subtracted from token TTLs before the outbound cache treats them as expired. |
| `defaultTtlSeconds` | `number` (optional, default `3600`) | Fallback outbound-token cache TTL when the AS response lacks expiry metadata. |
| `circuitBreakerThreshold` | `number` (optional, default `5`) | Consecutive AS failures before the breaker opens. |
| `circuitBreakerCooldownSeconds` | `number` (optional, default `30`) | Cooldown before the open breaker allows a probe. |

Plus every option from `AuthplaneResourceOptions` (`core`) not otherwise overridden.

### Return value

| Field | Type | Purpose |
|---|---|---|
| `client` | `AuthplaneClient` | The underlying client — owns the JWKS and metadata refresh timers. Use it to run AS traffic (token exchange, introspection, …), and call `client.close()` on shutdown to release the timers. Unlike `@authplane/mcp` and `@authplane/fastmcp`, Hono's factory always creates a client, so this field is non-nullable. |
| `verifier` | `AuthplaneResource` | The core resource primitive; call `verifier.verify(token)` directly to bypass the middleware. |
| `bearerAuth` | `MiddlewareHandler<{ Variables: HonoAuthVariables }>` | Ready-to-use Hono middleware. Verifies token, enforces scopes, attaches `c.get("auth")`. |
| `protectedResourceMetadataPath` | `string` | Hono route path where the PRM should be served (e.g. `/.well-known/oauth-protected-resource/mcp`). |
| `protectedResourceMetadata` | `ProtectedResourceMetadata` | The PRM JSON payload. |
| `protectedResourceMetadataHandler` | `Handler` | Hono handler that serves the PRM. |

## Context shape (`c.get("auth")`)

After `bearerAuth` runs, the verified claims are available via `c.get("auth")`. Type the app as `Hono<{ Variables: HonoAuthVariables }>` (from `@authplane/hono`) to get autocomplete:

```ts
import type { HonoAuthVariables } from "@authplane/hono";
const app = new Hono<{ Variables: HonoAuthVariables }>();

app.get("/me", auth.bearerAuth, (c) => {
  const info = c.get("auth"); // VerifiedClaims (from @authplane/sdk/core)
  return c.json({
    sub: info.sub,
    clientId: info.clientId,
    scopes: info.scopes,
    expiresAt: info.expiresAt,
    audience: info.audience,
  });
});
```

`VerifiedClaims` (re-exported by the SDK core) includes every verified claim: `sub`, `clientId`, `scopes`, `issuer`, `audience`, `expiresAt`, `issuedAt`, `notBefore`, `jti`, `kid`, and the raw claim object under `raw`. Call `info.requireScope(scope)` to enforce a scope inline.

## Scope enforcement

By default, `bearerAuth` requires every scope in `options.scopes`. Override with `requiredScopes`:

```ts
const auth = await authplaneHonoAuth({
  issuer: "...",
  resource: "...",
  scopes: ["tools/read", "tools/write", "tools/admin"], // advertised in PRM
  requiredScopes: ["tools/read"],                       // enforced by bearerAuth
});
```

Tokens missing any `requiredScopes` are rejected with HTTP 403 and `WWW-Authenticate: Bearer error="insufficient_scope"`.

## Per-route scope enforcement with `requireScope`

`bearerAuth` gates the route; for finer per-handler scope checks, call `requireScope(c, scope)` inside the handler:

```ts
import { requireScope } from "@authplane/hono";

app.post("/tools/delete_thing", auth.bearerAuth, async (c) => {
  requireScope(c, "tools/delete_thing");
  const { id } = await c.req.json<{ id: string }>();
  await deleteThing(id);
  return c.json({ ok: true, deleted: id });
});
```

`requireScope` throws core `InsufficientScope` (from `@authplane/sdk/core`) if the scope is missing from `c.get("auth").scopes`. Pair it with an `onError` bridge that funnels `AuthplaneError` subclasses through core's `httpStatus()` + `wwwAuthenticate()`.

> Note on cross-adapter ergonomics: `@authplane/mcp`'s `requireScope` takes `(scope, authInfo)` to match MCP's tool-handler extras. Hono's takes `(c, scope)` to match Hono's context-first convention. Same name, same behavior, argument order deliberately different — check the signature when switching adapters.

## Error bridging with `app.onError`

`bearerAuth` handles errors from its own verification path directly — it writes 401 / 403 with the right `WWW-Authenticate` header before the handler ever runs. But errors thrown *from inside a handler* (most commonly from `requireScope`) escape into Hono's `app.onError` hook. The minimal bridge:

```ts
import {
  AuthplaneError,
  httpStatus,
  InsufficientScope,
  wwwAuthenticate,
} from "@authplane/sdk/core";

app.onError((err, c) => {
  if (err instanceof AuthplaneError) {
    c.header(
      "WWW-Authenticate",
      wwwAuthenticate(err, {
        resourceMetadataUrl: auth.verifier.prmDocumentUrl(),
      }),
    );
    const code =
      err instanceof InsufficientScope ? "insufficient_scope" : "invalid_token";
    return c.json(
      { error: code, error_description: err.message },
      httpStatus(err) as 401 | 403 | 503,
    );
  }
  return c.json({ error: "server_error" }, 500);
});
```

Every error funnels through core's `httpStatus()` + `wwwAuthenticate()`: `InsufficientScope` → 403 + `Bearer …`, DPoP failures → 401 + `DPoP …` (except `DPoPNotSupported`), upstream-AS failures (`JWKSFetchError`, `MetadataFetchError`) → 503 with retry semantics.

> No equivalent to MCP's URL elicitation. `@authplane/mcp` ships `wrapToolWithUrlElicitation` / `toUrlElicitationRequiredError` to translate a `ConsentRequiredError` (raised by a token exchange against `authserver`) into MCP's `-32042` response. Hono has no analogous protocol hook — if a handler performs a token exchange and catches `ConsentRequiredError`, translate it yourself inside the handler (typically to a `401` with a JSON body carrying the `consent_url`) before returning.

## DPoP-bound tokens

DPoP is opt-in. The convenience `replayStore` option enables it implicitly (Mode 2 — Supported) and the adapter ships `InMemoryDPoPReplayStore` from `@authplane/sdk/core`; use a Redis-backed implementation across multiple processes. For full control over DPoP knobs (`required`, `maxProofAgeSeconds`, `allowedProofAlgorithms`), pass `inboundDPoP` directly — `replayStore` is then folded into it. Setting `replayStore` *and* `inboundDPoP.replayStore` together throws at construction.

```ts
import { InMemoryDPoPReplayStore } from "@authplane/sdk/core";
import { authplaneHonoAuth } from "@authplane/hono";

const auth = await authplaneHonoAuth({
  issuer: "...",
  resource: "...",
  scopes: ["tools/read"],
  replayStore: new InMemoryDPoPReplayStore(),
});
```

Once configured, requests carrying a `DPoP` header get full proof validation (method, URL, iat, nonce, replay) against the presented access token's confirmation claim. A missing or invalid proof produces 401 `invalid_token` with `WWW-Authenticate: DPoP …` (RFC 9449 §7.1).

If the resource has not been opted into DPoP and a request still carries a `DPoP` header, the core verifier rejects it with `DPoPNotSupported`. The challenge response carries `WWW-Authenticate: Bearer …` — RFC 9449 §7.1 carves `DPoPNotSupported` out so the retry hint matches the resource's actual support.

### `htu` is pinned to the configured `resource`

> DPoP `htu` is anchored to the configured resource origin; only the request's path and query are taken from the inbound request.

## Introspection and revocation

By default the adapter trusts signature + `exp`/`nbf`. To enable RFC 7662 introspection on every request (catches tokens revoked before expiry):

```ts
import { authplaneHonoAuth } from "@authplane/hono";
import { IntrospectionRevocation } from "@authplane/sdk/core";

const auth = await authplaneHonoAuth({
  issuer: "...",
  resource: "https://api.example.com/mcp",
  scopes: ["tools/read"],
  asCredentials: { clientId: "rs-client", clientSecret: "<secret>" },
  revocationChecker: IntrospectionRevocation.get(),
});
```

`IntrospectionRevocation` is a singleton class from `@authplane/sdk/core` — obtain its instance with `IntrospectionRevocation.get()` and pass it through `revocationChecker`. Internally it's detected via `instanceof`, which flips `AuthplaneResource` into "introspect on every verify" mode: the underlying resource calls `authserver`'s introspection endpoint on each `verify()` and raises on `active: false`. This adds one round-trip per request; use only if eager revocation matters to your threat model.

You can also pass a custom `RevocationChecker` — an async function `(claims, rawToken) => Promise<boolean>` — for database-backed revocation lists.

## Custom fetch settings

Every outbound call (metadata, JWKS, introspection, revocation) routes through a `FetchSettings` instance. Tighten defaults:

```ts
import { FetchSettings } from "@authplane/sdk/core";

const tight = new FetchSettings({
  timeoutMs: 3000,
  allowedHosts: ["auth.example.com"],
});

const auth = await authplaneHonoAuth({
  issuer: "https://auth.example.com",
  resource: "https://api.example.com/mcp",
  scopes: ["tools/read"],
  fetchSettings: tight,
});
```

See the [`@authplane/sdk` user guide](../../sdk/docs/user-guide.md#fetch-settings-and-ssrf-protection) for the full `FetchSettings` reference.

## Runtime portability

The middleware itself uses only `Request`/`Response`-level primitives, so it ports with your Hono app — examples use `@hono/node-server` for convenience.

**Workers caveat (be honest with yourself):** `AuthplaneClient` uses `setInterval` for JWKS and metadata refresh. Cloudflare Workers' `nodejs_compat` shim does **not** keep those timers alive across invocations, so the first cold start fetches JWKS / metadata eagerly but background refresh won't run. PRM is also computed at factory call time (top-level `await`). On Workers/edge today, prefer:

- A Node-attached `@hono/node-server` deployment behind your edge ingress, or
- A short-lived client per Worker iteration with `client.close()` in the finally block.

A first-class Workers integration (cron-triggered refresh + Durable-Object replay store) is on the roadmap — until then, treat Node/Bun/Deno as the supported runtimes.

## Local example commands

Two runnable scripts ship with the package:

1. `examples/oauth-server.ts` — minimal one-file example:

   ```bash
   PORT=8090 \
   AUTHPLANE_ISSUER=http://127.0.0.1:9000 \
   AUTHPLANE_RESOURCE=http://127.0.0.1:8090/resource \
   npm run -w @authplane/hono example:oauth
   ```

2. `demo/server.ts` — multi-route calculator demo with per-route scope enforcement and `onError` bridging. Run it via:

   ```bash
   cd packages/hono
   cp demo/.env.example demo/.env
   ./demo/run.sh
   ```

## Error handling

| Authplane error | HTTP | `WWW-Authenticate` |
|---|---|---|
| `TokenMissing` (no `Authorization`) | 401 | `Bearer error="invalid_token"` |
| `TokenExpired`, `InvalidSignature`, `InvalidClaims`, `TokenRevoked` | 401 | `Bearer error="invalid_token"` |
| `InsufficientScope` (from `requiredScopes` or `requireScope`) | 403 | `Bearer error="insufficient_scope", scope="…"` |
| `DPoPProofMissing`, `InvalidDPoPProof`, `DPoPReplayDetected`, `DPoPBindingMismatch` | 401 | `DPoP error="invalid_token"` (RFC 9449 §7.1) |
| `DPoPNotSupported` | 401 | `Bearer error="invalid_token"` (resource not opted into DPoP) |

Every failure also includes `resource_metadata="<PRM URL>"` when the factory has computed one, so clients following RFC 9728 can discover the authorization server automatically.

## Cleanup

The underlying `AuthplaneClient` owns timers for JWKS and metadata refresh. On server shutdown:

```ts
await auth.client.close();
```

This stops the refresh timers so the process can exit cleanly. The example and demo wire this to `SIGINT` / `SIGTERM`.

> `AuthplaneResource` (returned as `auth.verifier`) does not own any timers — its `close()` is a no-op. Always shut down the `AuthplaneClient` instead.

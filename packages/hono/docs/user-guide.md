# `@authplane/hono` — User Guide

Complete reference for the Authplane adapter for [Hono](https://hono.dev). Starts with the quickstart and builds to advanced scenarios. For a short overview see the [package README](../README.md).

## Table of contents

- [Install](#install)
- [Quickstart](#quickstart)
- [`authplaneHonoAuth(options)` reference](#authplanehonoauthoptions-reference)
- [Context shape (`c.get("auth")`)](#context-shape-cgetauth)
- [Scope enforcement](#scope-enforcement)
- [Per-route scope enforcement with `requireScope`](#per-route-scope-enforcement-with-requirescope)
- [Error handling with `authplaneOnError`](#error-handling-with-authplaneonerror)
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
| `realm` | `string` (optional) | RFC 6750 §3 protection realm, emitted as `realm="…"` on every `WWW-Authenticate` challenge. Wired into **both** `bearerAuth` and `auth.onError`, so the verification-path (401) and handler-raised (403) challenges cannot drift. |
| `emitDownstreamChallenge` | `boolean` (optional, default `true`) | Whether `bearerAuth` may write its own RFC 6750 §3 challenge for an `AuthplaneError` thrown by a guarded downstream route. Set `false` to keep full control of the downstream response from your own `onError`. Forwarded verbatim to `bearerAuth`. |
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
| `onError` | `ErrorHandler<E>` | Preconfigured `app.onError` handler, bound with the SAME `realm` + `resource_metadata` URL as `bearerAuth`. Install with `app.onError(auth.onError)` so a handler-raised `AuthplaneError` (e.g. `requireScope` → `InsufficientScope`) emits a challenge that matches the verification path. Generic over the app's `Env` — instantiate the factory at your `Bindings` shape to attach it to a Workers-typed app without a cast. |
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

`requireScope` throws core `InsufficientScope` (from `@authplane/sdk/core`) if the scope is missing from `c.get("auth").scopes`. **No error-handling wiring is required:** when the route is behind `auth.bearerAuth`, the adapter catches that `InsufficientScope` and returns `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="tools/delete_thing"` — the challenge carries the exact per-route scope you passed to `requireScope`, not the middleware-level required-scope union. See [Error handling with `authplaneOnError`](#error-handling-with-authplaneonerror) if you prefer an explicit application-level handler.

> Note on cross-adapter ergonomics: `@authplane/mcp`'s `requireScope` takes `(scope, authInfo)` to match MCP's tool-handler extras. Hono's takes `(c, scope)` to match Hono's context-first convention. Same name, same behavior, argument order deliberately different — check the signature when switching adapters.

## Error handling with `authplaneOnError`

**Recommended: install `auth.onError` as your app error handler.** The factory returns a preconfigured `onError` bound with the SAME `realm` and `resource_metadata` URL it wired into `auth.bearerAuth`, so a 401 from token verification and a 403 from a handler-raised `InsufficientScope` carry an identical challenge — they cannot drift, and you never re-plumb those values by hand. One line wires every `AuthplaneError` — whether raised on the middleware's own verification path or thrown from inside a guarded route (most commonly `requireScope` raising `InsufficientScope`) — to the correct RFC 6750 §3 response:

```ts
app.onError(auth.onError);
```

`auth.onError` is a ready-bound `authplaneOnError()`; call `authplaneOnError()` yourself only when you are not using the factory (e.g. you hand-wired `bearerAuth`) or need different challenge options:

```ts
import { authplaneOnError } from "@authplane/hono";

app.onError(
  authplaneOnError({
    realm: "https://api.example.com/mcp",
    resourceMetadataUrl: auth.verifier.prmDocumentUrl(),
  }),
);
```

Both are safe exactly as written. `authplaneOnError()` funnels every `AuthplaneError` through core's `httpStatus()` + `wwwAuthenticate()` — preferring the per-route scope stashed by `requireScope` for the `insufficient_scope` challenge — and by **default** maps any *non*-`AuthplaneError` to the same clean `server_error` 500 the middleware emits (with a fixed `"Internal Server Error"` description and a `console.error` of the original error, so the raw message never leaks to the caller while the stack is still logged server-side). Because `app.onError(handler)` *replaces* Hono's built-in error handler, that default is what stops a copy-pasted one-liner from turning a route `TypeError` or DB failure into an unhandled rejection. All challenge options (`realm`, `resourceMetadataUrl`, `requiredScopes`) are optional. It is also generic over the Hono `Env`, so it typechecks on a `Bindings`-typed app (e.g. `new Hono<{ Bindings: Env; Variables: HonoAuthVariables }>()`, the Cloudflare Workers shape).

> **`fallback` for non-`AuthplaneError`s.** The default `fallback: "server_error"` fills the gap left by replacing Hono's built-in handler. If you deliberately chain an outer error handler behind this one, pass `fallback: "rethrow"` to re-throw non-`AuthplaneError`s for it to catch — but with no outer handler a re-thrown error escapes uncaught and Hono (or your server) surfaces it with no clean 500.

### Safety net: the zero-config middleware guard

You do not *have* to install `authplaneOnError()`. Even with no app `onError`, `bearerAuth` guards the downstream handler itself: an `AuthplaneError` thrown from a route behind `auth.bearerAuth` is caught after `next()` and turned into the same RFC 6750 §3 challenge, so a scope failure still returns `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="<the scope you passed to requireScope>"` — zero wiring. Non-`AuthplaneError` failures are left untouched so genuine application errors are never masked as an auth response.

The two paths cooperate rather than double-handle. On a downstream throw, Hono dispatches to `app.onError` **first** (inside the middleware's `next()`), so `authplaneOnError()` produces the challenge before control returns to the middleware. The middleware's post-`next()` guard then sees a `WWW-Authenticate` header already on the response and, because of its `!c.res.headers.has("WWW-Authenticate")` check, suppresses its own write — so the challenge is emitted exactly once. (It is this header check, not the order of the two handlers, that prevents the double emit.) To keep full control of a downstream `AuthplaneError` response yourself — even one that carries no challenge — set `emitDownstreamChallenge: false`. Pass it to `authplaneHonoAuth({ emitDownstreamChallenge: false })` and the factory forwards it to `bearerAuth`; if you hand-wire the middleware, set it on `bearerAuth` directly.

> **Zero-config log spam.** On the zero-config path (no app `onError`), an expected `insufficient_scope` throw from a downstream `requireScope` travels through Hono's DEFAULT error handler, which `console.error`s the full stack *before* `bearerAuth` rewrites the response to the clean `403` challenge. The final HTTP response is correct, but the error is still logged at error level. This is inherent to the inspect-`c.error`-after-`next()` design and cannot be fixed inside the middleware. Installing `authplaneOnError()` (or any app `onError`) replaces Hono's default handler and suppresses that logging — another reason to prefer it.

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

# `@authplane/nestjs` — User Guide

Complete reference for the Authplane adapter for [NestJS](https://nestjs.com). Starts with the quickstart and builds to advanced scenarios. For a short overview see the [package README](../README.md).

## Table of contents

- [Install](#install)
- [Quickstart](#quickstart)
- [`AuthplaneModule.forRoot` / `.forRootAsync` reference](#authplanemoduleforroot--forrootasync-reference)
- [Per-request `VerifiedClaims`](#per-request-verifiedclaims)
- [Scope enforcement](#scope-enforcement)
- [Protected Resource Metadata](#protected-resource-metadata)
- [Introspection and revocation](#introspection-and-revocation)
- [DPoP-bound tokens](#dpop-bound-tokens)
- [Custom fetch settings](#custom-fetch-settings)
- [Error handling](#error-handling)
- [Express vs. Fastify](#express-vs-fastify)
- [Local example commands](#local-example-commands)
- [Cleanup](#cleanup)

## Install

```bash
npm install @authplane/sdk @authplane/nestjs @nestjs/common @nestjs/core reflect-metadata rxjs
```

Requires Node 22 LTS or newer (matches the workspace root). `@authplane/nestjs` treats `@nestjs/common`, `@nestjs/core`, `reflect-metadata`, and `rxjs` as peer dependencies. Include `@nestjs/platform-express` or `@nestjs/platform-fastify` — the adapter supports both unchanged.

## Quickstart

A complete NestJS server with Authplane auth:

```ts
import "reflect-metadata";
import { Body, Controller, Module, Post, UseGuards } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import {
  AuthInfo,
  AuthplaneAuthGuard,
  AuthplaneModule,
  RequireScopes,
  type VerifiedClaims,
} from "@authplane/nestjs";

@Controller("mcp")
@UseGuards(AuthplaneAuthGuard)
class McpController {
  @Post("tools/weather")
  @RequireScopes("tools/weather")
  async weather(
    @AuthInfo() info: VerifiedClaims,
    @Body() body: { city: string },
  ) {
    return {
      content: [{ type: "text", text: `${body.city}: sunny (caller=${info.clientId})` }],
    };
  }
}

@Module({
  imports: [
    AuthplaneModule.forRoot({
      issuer: "http://localhost:9000",
      resource: "http://localhost:8090/mcp",
      scopes: ["tools/weather"],
      devMode: true,
    }),
  ],
  controllers: [McpController],
})
class AppModule {}

const app = await NestFactory.create(AppModule);
app.enableShutdownHooks(); // so AuthplaneShutdownHook runs `client.close()` on exit
await app.listen(8090);
```

The module provisions four DI-scoped providers — the underlying `AuthplaneClient`, the per-resource `AuthplaneResource`, an `AuthplaneAuthGuard`, and an `AuthplaneExceptionFilter` — and registers a controller that publishes the RFC 9728 Protected Resource Metadata at the derived well-known path (`/.well-known/oauth-protected-resource/mcp` for the example above).

## `AuthplaneModule.forRoot` / `.forRootAsync` reference

### Synchronous registration

`AuthplaneModule.forRoot(options)` is a one-liner wrapper over `forRootAsync({ useFactory: () => options })` for the common case where every option is already known at import time.

### Asynchronous registration

`AuthplaneModule.forRootAsync(asyncOptions)` mirrors the standard NestJS async-module shape (`useFactory` / `useClass` / `useExisting`) so it composes naturally with `ConfigModule`:

```ts
AuthplaneModule.forRootAsync({
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (cfg: ConfigService) => ({
    issuer: cfg.getOrThrow("AUTHPLANE_ISSUER"),
    resource: cfg.getOrThrow("AUTHPLANE_RESOURCE"),
    scopes: cfg.get<string[]>("AUTHPLANE_SCOPES") ?? [],
  }),
})
```

> **Sync-factory caveat.** NestJS controllers need a string-literal path at module-registration time, but the PRM path depends on the resolved `resource`. To keep `forRootAsync` ergonomic when the factory has no `inject` and returns synchronously, `AuthplaneModule` invokes such factories **once at registration time** to derive the PRM path, then reuses the resolved options as a `useValue` provider. The DI container does not re-invoke the factory, so observable side effects (logs, counters) happen during `forRootAsync(...)` and **not** during `app.init()`. Factories with `inject` or a `Promise` return are always resolved through DI and never invoked at registration — pass `hints.prmPath` (computed via `oauthProtectedResourceMetadataPath(resource)` from `@authplane/sdk/core`) if you need the PRM controller in those cases.

### Options

> Types referenced below (`AuthProvider`, `ASCredentials`, `DPoPProvider`, etc.) are re-exported from `@authplane/nestjs` for convenience — import them from the same package as `AuthplaneModule`, or pull them from `@authplane/sdk/core` if you prefer.

| Field | Type | Purpose |
|---|---|---|
| `issuer` | `string` (required) | Authplane issuer URL (your `authserver`). |
| `resource` | `string` (required) | Resource URI tokens must be audience-bound to (`aud` claim). |
| `scopes` | `string[]` (optional) | All scopes this server supports. Used for PRM and, by default, as `requiredScopes`. |
| `requiredScopes` | `string[]` (optional) | Module-level scopes enforced by the guard. Defaults to `scopes` when absent. Layers with per-route `@RequireScopes(...)`. |
| `auth` | `AuthProvider \| ASCredentials` (optional) | AS-facing credentials for outbound calls. Accepts a full `AuthProvider` (e.g. `private_key_jwt`, mTLS, custom) or the `{ clientId, clientSecret }` shortcut (wrapped in `ClientCredentialsProvider` by core). Required when introspection/revocation is enabled. Mirrors `auth` on `AuthplaneClient.create`. |
| `asCredentials` | `{ clientId, clientSecret }` (optional) | Legacy shortcut for the client-secret path. When both `auth` and `asCredentials` are set, `auth` wins. Prefer `auth` for new code. |
| `fetchSettings` | `FetchSettings` (optional) | Unified outbound fetch hardening (SSRF, timeouts, allowlists). Applied to both AS metadata and JWKS fetches. Defaults derived from `devMode`. |
| `jwksRefreshSeconds` | `number` (optional, default `300`) | JWKS cache TTL. |
| `metadataRefreshSeconds` | `number` (optional, default `3600`) | Metadata cache TTL. |
| `cacheTtlBufferSeconds` | `number` (optional, default `30`) | Seconds subtracted from upstream `expires_in` when caching AS responses. Forwarded to `AuthplaneClient.create`. |
| `defaultTtlSeconds` | `number` (optional, default `3600`) | Fallback TTL when AS responses omit `expires_in`. Forwarded to `AuthplaneClient.create`. |
| `circuitBreakerThreshold` | `number` (optional, default `5`) | Consecutive AS failures before the outbound circuit breaker opens. |
| `circuitBreakerCooldownSeconds` | `number` (optional, default `30`) | Seconds the circuit breaker stays open before half-open retries. |
| `dpopProvider` | `DPoPProvider` (optional) | Outbound DPoP provider for AS-facing calls (token exchange, client-credentials). Inbound DPoP is configured separately via `inboundDPoP.replayStore`. |
| `devMode` | `boolean` (optional, default `false`) | Relaxes HTTPS and private-host restrictions. Only for local dev. |
| `revocationChecker` | `RevocationChecker \| IntrospectionRevocation` (optional) | Enable real-time revocation checking. |
| `inboundDPoP` | `InboundDPoPOptions` (optional) | Inbound DPoP knobs (`maxProofAgeSeconds`, `clockSkewSeconds`, `allowedProofAlgorithms`, `required`, `replayStore`). Setting `replayStore` here opts the resource into DPoP (Mode 2 — Supported). |
| `requestAdapter` | `RequestAdapter` (optional) | Escape hatch to replace the Express+Fastify anti-corruption layer. Most applications never set this. |

Plus every option accepted by `AuthplaneClient.create` and `AuthplaneResource` that is not otherwise overridden.

### Providers registered

Every provider is available via DI from any class imported into the same module graph:

| Token | Bound to |
|---|---|
| `AUTHPLANE_MODULE_OPTIONS` | The user-supplied options object. |
| `AUTHPLANE_CLIENT` | `AuthplaneClient` — owns JWKS/metadata refresh timers; use for token exchange / introspection / revocation calls. |
| `AUTHPLANE_RESOURCE` | `AuthplaneResource` — the per-resource verifier. |
| `AUTHPLANE_TOKEN_VERIFIER` | The same `AuthplaneResource` instance as `AUTHPLANE_RESOURCE`. Kept as a dedicated DI seam so tests can override the verifier with `{ provide: AUTHPLANE_TOKEN_VERIFIER, useValue: mock }` without touching the resource provider. |
| `AUTHPLANE_REQUEST_ADAPTER` | `RequestAdapter` — Express+Fastify ACL. |
| `AuthplaneAuthGuard` | Ready-to-use `CanActivate`. |
| `AuthplaneExceptionFilter` | RFC 6750 §3 filter. |
| `AuthplaneShutdownHook` | Runs `await client.close()` under `OnApplicationShutdown`. |

<a id="per-request-verifiedclaims"></a>
## Per-request `VerifiedClaims`

After `AuthplaneAuthGuard` runs, the verified claims are available two ways:

```ts
import { AuthInfo, type VerifiedClaims } from "@authplane/nestjs";

@Get("me")
whoami(@AuthInfo() info: VerifiedClaims) {
  return {
    sub: info.sub,
    clientId: info.clientId,
    scopes: info.scopes,
    expiresAt: info.expiresAt,
  };
}
```

Or by reading directly off the request (useful from interceptors / middleware):

```ts
import { AUTH_INFO_REQUEST_KEY, type VerifiedClaims } from "@authplane/nestjs";

@Injectable()
class AuditInterceptor implements NestInterceptor {
  intercept(ctx: ExecutionContext, next: CallHandler) {
    const req = ctx.switchToHttp().getRequest();
    const info = req[AUTH_INFO_REQUEST_KEY] as VerifiedClaims | undefined;
    // ...
    return next.handle();
  }
}
```

`VerifiedClaims` includes every verified claim: `token`, `sub`, `clientId`, `scopes`, `issuer`, `audience`, `resource` (a `URL`), `expiresAt`, `issuedAt`, `jti`, `kid`, `dpopProof` (when present), and the raw claim object under `raw`.

## Scope enforcement

`AuthplaneAuthGuard` enforces the union of two scope sources: module-level `requiredScopes` (or, by default, `scopes`) and any per-handler `@RequireScopes(...)` metadata. Tokens missing any scope in the merged set are rejected with HTTP 403 and `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"`.

Module-level only:

```ts
AuthplaneModule.forRoot({
  issuer: "...",
  resource: "...",
  scopes: ["tools/read", "tools/write", "tools/admin"], // advertised in PRM
  requiredScopes: ["tools/read"],                        // enforced by the guard on every handler
}),
```

Layered with per-route metadata:

```ts
@Controller("tools")
@UseGuards(AuthplaneAuthGuard)
class ToolsController {
  @Post("delete_thing")
  @RequireScopes("tools/delete_thing") // merged with module-level requiredScopes
  async delete(@Body() body: { id: string }) {
    await deleteThing(body.id);
    return { ok: true, deleted: body.id };
  }
}
```

Opting a handler out of auth entirely — useful for health checks hosted on the same controller as guarded routes:

```ts
import { SkipAuth } from "@authplane/nestjs";

@Get("health")
@SkipAuth()
health() {
  return { ok: true };
}
```

> Note on cross-adapter ergonomics: Hono's equivalent is a function call inside the handler — `requireScope(c, "tools/delete_thing")`. FastMCP takes the scope as metadata on the tool definition. NestJS uses decorator metadata (`@RequireScopes("…")`) that the guard resolves through `Reflector#getAllAndMerge`. Same semantics (401 vs 403 vs merged-union), different ergonomics — check the adapter-specific signature when porting code.

## Protected Resource Metadata

The RFC 9728 Protected Resource Metadata document is published automatically by a controller the module registers at registration time. The route path is derived from the resource URL:

| `resource` option | PRM path |
|---|---|
| `https://api.example.com/mcp` | `/.well-known/oauth-protected-resource/mcp` |
| `https://api.example.com` | `/.well-known/oauth-protected-resource` |
| `https://api.example.com/foo/bar` | `/.well-known/oauth-protected-resource/foo/bar` |

The handler is decorated with `@SkipAuth()` so the PRM document is reachable without credentials.

If you cannot use the bundled controller (for example because the resource URL is only known at runtime), skip it and expose the PRM yourself. Inject the resource and return the payload:

```ts
import { Inject } from "@nestjs/common";
import { AUTHPLANE_RESOURCE } from "@authplane/nestjs";
import type { AuthplaneResource } from "@authplane/sdk/core";

@Controller()
class PrmController {
  public constructor(
    @Inject(AUTHPLANE_RESOURCE) private readonly resource: AuthplaneResource,
  ) {}

  @Get("/.well-known/oauth-protected-resource/mcp")
  @SkipAuth()
  prm() {
    return this.resource.prmResponse();
  }
}
```

## Introspection and revocation

By default the adapter trusts signature + `exp`/`nbf`. To enable RFC 7662 introspection on every request (catches tokens revoked before expiry):

```ts
import { IntrospectionRevocation } from "@authplane/sdk/core";

AuthplaneModule.forRoot({
  issuer: "...",
  resource: "https://api.example.com/mcp",
  scopes: ["tools/read"],
  asCredentials: { clientId: "rs-client", clientSecret: "<secret>" },
  revocationChecker: IntrospectionRevocation.get(),
}),
```

`IntrospectionRevocation` is a singleton class from `@authplane/sdk/core` — obtain its instance with `IntrospectionRevocation.get()` and pass it through `revocationChecker`. Internally it's detected via `instanceof`, which flips `AuthplaneResource` into "introspect on every verify" mode: the underlying resource calls `authserver`'s introspection endpoint on each `verify()` and raises on `active: false`. This adds one round-trip per request; use only if eager revocation matters to your threat model.

You can also pass a custom `RevocationChecker` — an async function `(claims, rawToken) => Promise<boolean>` — for database-backed revocation lists.

## DPoP-bound tokens

DPoP is opt-in. Pass `inboundDPoP` with a `replayStore` to enable it (Mode 2 — Supported); the adapter ships with `InMemoryDPoPReplayStore` from `@authplane/sdk/core` for single-process deployments — use a Redis-backed implementation across multiple processes. Full control over DPoP knobs (`required`, `maxProofAgeSeconds`, `allowedProofAlgorithms`, `clockSkewSeconds`) lives on the same `inboundDPoP` bag.

```ts
import { InMemoryDPoPReplayStore } from "@authplane/sdk/core";

AuthplaneModule.forRoot({
  issuer: "...",
  resource: "...",
  scopes: ["tools/read"],
  inboundDPoP: { replayStore: new InMemoryDPoPReplayStore() },
}),
```

Once configured, requests carrying a `DPoP` header get full proof validation (method, URL, iat, nonce, replay) against the presented access token's confirmation claim. A missing or invalid proof produces 401 `invalid_token` with `WWW-Authenticate: DPoP …` (RFC 9449 §7.1).

When the resource has not been opted into DPoP (no `inboundDPoP`) and a request still carries a `DPoP` header, the core verifier rejects it with `DPoPNotSupported`. The challenge response carries `WWW-Authenticate: Bearer …` — RFC 9449 mandates the retry hint match the resource's actual support, and `DPoPNotSupported` is the carve-out where a `DPoPError` subclass produces a `Bearer` challenge.

### `htu` is pinned to the configured `resource`

> DPoP `htu` is anchored to the configured resource origin; only the request's path and query are taken from the inbound request.

## Custom fetch settings

Every outbound call (metadata, JWKS, introspection, revocation) routes through a `FetchSettings` instance. Tighten defaults:

```ts
import { FetchSettings } from "@authplane/sdk/core";

const tight = new FetchSettings({
  timeoutMs: 3000,
  allowedHosts: ["auth.example.com"],
});

AuthplaneModule.forRoot({
  issuer: "https://auth.example.com",
  resource: "https://api.example.com/mcp",
  scopes: ["tools/read"],
  fetchSettings: tight,
}),
```

See the [`@authplane/sdk` user guide](../../sdk/docs/user-guide.md#fetch-settings-and-ssrf-protection) for the full `FetchSettings` reference.

## Error handling

`AuthplaneExceptionFilter` is provided by `AuthplaneModule` but **not** registered globally. Mount it on a controller with `@UseFilters(AuthplaneExceptionFilter)`, or register it app-wide via either of:

```ts
// Bootstrap-time (most common)
app.useGlobalFilters(app.get(AuthplaneExceptionFilter));

// DI-driven
@Module({
  imports: [AuthplaneModule.forRoot({ ... })],
  providers: [{ provide: APP_FILTER, useExisting: AuthplaneExceptionFilter }],
})
```

The guard is treated the same way: declare it explicitly with `@UseGuards(AuthplaneAuthGuard)` on protected controllers, or wire it as a global via `APP_GUARD: { provide: APP_GUARD, useExisting: AuthplaneAuthGuard }` (don't forget `@SkipAuth()` on routes that must remain public, including the PRM controller — already annotated for you).

Once mounted, the filter only claims `AuthplaneError` (core) subclasses — unrelated exceptions (e.g. a user-thrown `HttpException`) keep flowing through NestJS's default exception handling. The RFC 6750 §3 shape — JSON body plus `WWW-Authenticate` challenge — is written regardless of whether the underlying transport is Express or Fastify:

| Error | HTTP | `WWW-Authenticate` |
|---|---|---|
| `TokenMissing` (no `Authorization`) | 401 | `Bearer error="invalid_token"` |
| `TokenExpired`, `InvalidSignature`, `InvalidClaims`, `TokenRevoked` | 401 | `Bearer error="invalid_token"` |
| `InsufficientScope` (module-level or `@RequireScopes`) | 403 | `Bearer error="insufficient_scope", scope="…"` |
| `DPoPProofMissing`, `InvalidDPoPProof`, `DPoPReplayDetected`, `DPoPBindingMismatch` | 401 | `DPoP error="invalid_token"` (RFC 9449 §7.1) |
| `DPoPNotSupported` | 401 | `Bearer error="invalid_token"` (resource not opted into DPoP) |

Every failure also includes `resource_metadata="<PRM URL>"` when the module has computed one, so clients following RFC 9728 can discover the authorization server automatically.

To customise the response shape, extend the filter and re-register it with a higher precedence than the one from the module:

```ts
@Catch()
class ChattyAuthFilter extends AuthplaneExceptionFilter {
  override catch(exception: unknown, host: ArgumentsHost): void {
    super.catch(exception, host);
    console.warn("[audit] auth failure", exception);
  }
}

@Module({
  imports: [AuthplaneModule.forRoot({ ... })],
  providers: [{ provide: APP_FILTER, useClass: ChattyAuthFilter }],
})
```

> No equivalent to MCP's URL elicitation. `@authplane/mcp` ships `wrapToolWithUrlElicitation` / `toUrlElicitationRequiredError` to translate a `ConsentRequiredError` (raised by a token exchange against `authserver`) into MCP's `-32042` response. NestJS has no analogous protocol hook — if a handler performs a token exchange and catches `ConsentRequiredError`, translate it yourself by throwing an `HttpException` that carries the `consent_url` in its body:
>
> ```ts
> try {
>   await client.exchangeToken(...);
> } catch (err) {
>   if (err instanceof ConsentRequiredError) {
>     throw new HttpException(
>       { error: "consent_required", consent_url: err.consentUrl },
>       401,
>     );
>   }
>   throw err;
> }
> ```

## Express vs. Fastify

The module works unchanged on both `@nestjs/platform-express` and `@nestjs/platform-fastify`. The integration suite runs every test twice — once per platform — so behaviour is verified on both. The `RequestAdapter` abstraction behind `AUTHPLANE_REQUEST_ADAPTER` hides the differences (`req.headers` vs `req.raw.headers`, `res.setHeader` vs `reply.header`, `res.status().json()` vs `reply.code().send()`).

If you embed the module in a custom transport (for example a GraphQL gateway that exposes its own request/response primitives), override the adapter via the `requestAdapter` option:

```ts
import { AUTH_INFO_REQUEST_KEY } from "@authplane/nestjs";

AuthplaneModule.forRoot({
  issuer: "...",
  resource: "...",
  scopes: ["..."],
  requestAdapter: {
    getHeader: (req, name) => /* ... */,
    getMethod: (req) => /* ... */,
    getPathAndQuery: (req) => /* ... */,
    // Must write under AUTH_INFO_REQUEST_KEY — the @AuthInfo() parameter
    // decorator reads this exact symbol off the request, not your own field.
    stashAuthInfo: (req, info) => {
      (req as Record<symbol, unknown>)[AUTH_INFO_REQUEST_KEY] = info;
    },
  },
}),
```

## Local example commands

Two runnable scripts ship with the package:

1. `examples/oauth-server.ts` — minimal one-file example:

   ```bash
   PORT=8090 \
   AUTHPLANE_ISSUER=http://127.0.0.1:9000 \
   AUTHPLANE_RESOURCE=http://127.0.0.1:8090/resource \
   npm run -w @authplane/nestjs example:oauth
   ```

2. `demo/server.ts` — multi-route calculator demo with per-route scope enforcement and introspection wired on. Run it via:

   ```bash
   cd packages/nestjs
   cp demo/.env.example demo/.env
   ./demo/run.sh
   ```

## Cleanup

The underlying `AuthplaneClient` owns timers for JWKS and metadata refresh. `AuthplaneModule` registers an `AuthplaneShutdownHook` that calls `await client.close()` from `OnApplicationShutdown`. Activate it with:

```ts
const app = await NestFactory.create(AppModule);
app.enableShutdownHooks();
```

That's the full integration — `SIGINT` / `SIGTERM` (or a manual `app.close()`) will flow through NestJS's lifecycle, trigger the hook, and stop the refresh timers so the process can exit cleanly.

> `AuthplaneResource` (available via `AUTHPLANE_RESOURCE`) does not own any timers — its `close()` is a no-op. Always let the shutdown hook close the `AuthplaneClient` instead.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-27

### Added

- `@authplane/hono` — `authplaneOnError()`, a ready-made `app.onError` handler that maps every `AuthplaneError` to its RFC 6750 §3 response, passes a Hono `HTTPException` through unchanged, and by default maps anything else to a `server_error` 500 (with an `onServerError` hook for structured logging). The factory also returns `auth.onError`, preconfigured with the SAME `realm` and `resource_metadata` URL as `auth.bearerAuth`, so the verification-path 401 and a handler-raised 403 cannot drift. It is generic over the app's `Env`, so it attaches to a `Bindings`-typed (Cloudflare Workers) app without a cast. `bearerAuth` now also guarantees the RFC 6750 §3 challenge for an `AuthplaneError` thrown by a guarded downstream route (e.g. `requireScope` raising `InsufficientScope`) with zero application wiring; opt out with `emitDownstreamChallenge: false`. New `realm` option, threaded into both paths.
- `@authplane/sdk` — `sanitiseHeaderValue` is exported from `@authplane/sdk/core`, so code that splices values into a `WWW-Authenticate` challenge through a header builder outside this SDK applies the same RFC 9110 §11.4 ruleset.

### Changed

- `@authplane/sdk` — the configured `issuer` is treated as an identity and preserved byte-for-byte (RFC 8414 §2/§3.3): the SDK no longer strips a trailing slash from the stored issuer, the token verifier's expected `iss`, or the metadata `issuer` comparison, and an issuer carrying a query or fragment component (including a bare `?` / `#`) is rejected at construction instead of being silently discarded. `.well-known` URL derivation still drops a terminating slash (RFC 8414 §3.1). **Migration**: if your configured issuer differs from your authorization server's published identifier by a trailing slash, correct the configuration — the SDK no longer reconciles them.
- `@authplane/mcp` — `@modelcontextprotocol/sdk` moved from a direct dependency to a peer dependency (`^1.29.0`), matching how the Hono and NestJS adapters declare their frameworks. The `OAuthTokenVerifier` seam relies on `instanceof` against the SDK's error classes, so the adapter and the host application must resolve to the same copy. On installers that don't auto-install peer dependencies (npm < 7, Yarn classic), add `@modelcontextprotocol/sdk` to your application's dependencies explicitly. Peers don't *guarantee* single-copy resolution either: if every auth failure surfaces as a 500 with no `WWW-Authenticate`, check for a duplicated install (`npm ls @modelcontextprotocol/sdk`).

### Fixed

- `@authplane/mcp` — `tokenVerifier` now works inside the MCP SDK's stock `requireBearerAuth` and other `OAuthTokenVerifier` hosts. `verifyAccessToken` rethrows in the SDK's error taxonomy (`InsufficientScopeError` → 403, `InvalidTokenError` → 401, `ServerError` → 500) instead of raw `AuthplaneError`s, which those hosts classified as 500-with-no-challenge — stalling MCP client discovery, which begins at 401 + `resource_metadata`. Pass `resourceMetadataUrl` to `requireBearerAuth`; the stock middleware only adds the `resource_metadata` hint when configured with it. 401/403 messages are sanitised against `WWW-Authenticate` quoted-string injection (RFC 9110 §11.4), which the SDK's own header builder does not do; the 500 message is a fixed generic string, since the SDK renders it verbatim to unauthenticated clients and core's 5xx messages can carry infrastructure detail. The original error is preserved on `error.cause` in all cases.
- **Migration** — `@authplane/mcp`: `AuthplaneTokenVerifier.verifyAccessToken` throws MCP SDK error classes again. Code that catches `AuthplaneError` from it should either match on the SDK classes, read `error.cause`, or call `verifyAccessTokenWithDpop`, which keeps the raw `AuthplaneError` contract (and is the only entry point that threads per-request DPoP context). The `bearerAuth` middleware is unaffected.

## [0.3.0] - 2026-07-24

### Added

- `@authplane/hono` — new Hono adapter: `authplaneHonoAuth()`, `bearerAuth` middleware (Bearer + DPoP, RFC 9449 §7.1), `requireScope` guard, and an RFC 9728 PRM handler.
- `@authplane/nestjs` — new NestJS adapter: `AuthplaneModule.forRoot()` / `forRootAsync()`, `AuthplaneAuthGuard`, `@SkipAuth()` / `@RequireScopes()` decorators, `AuthplaneExceptionFilter` (RFC 6750 §3), and a PRM controller (RFC 9728). Supports Express and Fastify.
- `@authplane/sdk` — `TokenCache` is now bounded by a configurable `maxEntries` cap (default `10_000`) with LRU eviction, via `AuthplaneClient.create({ cacheMaxEntries })`.
- `@authplane/sdk` — new `@authplane/sdk/core` helpers: `extractBearerToken`, `buildRequestUrl`, `pathAndQueryOf`, `extractDpopProof`, `oauthProtectedResourceMetadataPath`.

### Changed

- `@authplane/sdk` — `oauthProtectedResourceMetadataDocumentUrl(resource)` now normalises trailing slashes (RFC 9728 §3.1) and throws a typed `TypeError` on invalid URLs. **Migration**: drop any deliberate trailing slash from `resource` before upgrading — the canonical form is no-trailing-slash.
- `@authplane/mcp` — now accepts a DPoP-bound token presented under the `DPoP` scheme (RFC 9449 §7.1) instead of rejecting it with 401.
- `@authplane/fastmcp` — stricter RFC 6750 §2.1 `Authorization` parsing, consistent with the other adapters.

### Fixed

- `@authplane/mcp` — a non-URL `aud` claim now returns 401 `invalid_token` (RFC 8707) instead of a 500.

## [0.2.0] - 2026-05-22

- `@authplane/fastmcp`: support `fastmcp` 4.x in addition to 3.35+. Consumers using `OAuthProxy` directly must set `allowedRedirectUriPatterns` themselves — fastmcp 4.0 removed the default value (CWE-601 fix).
- `@authplane/sdk`: `wwwAuthenticate(error, options)` gains `resourceMetadataUrl` (RFC 9728 §5.1) and `scope` (RFC 6750) options, sanitises interpolated values against header injection (RFC 9110 §11.4), and emits the `Bearer` scheme for `DPoPNotSupported`.
- `@authplane/fastmcp` and `@authplane/mcp`: authentication failures now emit a per-error `WWW-Authenticate` challenge via `httpStatus` + `wwwAuthenticate` from `@authplane/sdk/core`. DPoP failures use the `DPoP` scheme (RFC 9449 §7.1); `resource_metadata` is always included and `scope` when `requiredScopes` is configured.
- `@authplane/mcp`: upstream authorization-server fetch failures (`JWKSFetchError`, `MetadataFetchError`) now return `503` with a `WWW-Authenticate` challenge (RFC 7235 §4.1) instead of a generic `500`. Rely on the HTTP status, not the response `error` field, when deciding whether to retry.
- **Migration** — `@authplane/fastmcp`: `AuthplaneTokenVerifier.verifyAccessToken` now propagates `AuthplaneError` instead of returning `undefined`; wrap direct `tokenVerifier` calls in try/catch.
- **Migration** — `@authplane/mcp`: `AuthplaneTokenVerifier.verifyAccessToken` now propagates `AuthplaneError` instead of the MCP SDK's `InvalidTokenError`; switch `instanceof InvalidTokenError` checks to `instanceof AuthplaneError`, or adopt the `bearerAuth` middleware.

## [0.1.0] - 2026-05-11

- Initial release.
- `@authplane/fastmcp` supports `fastmcp` 4.x in addition to 3.35+. The adapter only consumes `ServerOptions["authenticate"]` and `oauth.protectedResource.*`, which are byte-identical between 3.35.1 and 4.0.1. Consumers who use `OAuthProxy` directly must configure `allowedRedirectUriPatterns` themselves — fastmcp 4.0 removed the default value (CWE-601 fix); see the fastmcp v4.0.0 release notes.
- `@authplane/sdk` — `wwwAuthenticate(error, options)` accepts new `resourceMetadataUrl` (RFC 9728 §5.1) and `scope` (RFC 6750) options, sanitises every interpolated value against header injection (RFC 9110 §11.4), and emits the `Bearer` scheme for `DPoPNotSupported` (carve-out — although it extends `DPoPError`, the request was not DPoP-bound). Canonical error → status/challenge tables now live in the SDK user guide under "HTTP status and WWW-Authenticate challenge".
- `@authplane/fastmcp` and `@authplane/mcp` — every authentication failure now emits a spec-compliant per-error `WWW-Authenticate` challenge via `httpStatus` + `wwwAuthenticate` from `@authplane/sdk/core`. DPoP failures (replay, binding mismatch, missing/invalid proof) get the `DPoP` scheme per RFC 9449 §7.1; `resource_metadata` is always included and `scope` is included when `requiredScopes` is configured. Previously every failure collapsed to a generic `Bearer error="invalid_token", error_description="Invalid access token"`.
- **Migration — `@authplane/fastmcp`**: `AuthplaneTokenVerifier.verifyAccessToken` no longer swallows `AuthplaneError` and returns `undefined`; the underlying typed class propagates. Consumers wiring `tokenVerifier` directly should wrap in try/catch if they previously branched on the `undefined` sentinel.
- **Migration — `@authplane/mcp`**: `AuthplaneTokenVerifier.verifyAccessToken` no longer rewraps `AuthplaneError` as the MCP SDK's `InvalidTokenError`; the underlying typed class propagates. Consumers wiring `tokenVerifier` directly should switch `instanceof InvalidTokenError` checks to `instanceof AuthplaneError` and classify with `httpStatus(err)` / `wwwAuthenticate(err, options)` from `@authplane/sdk/core` — or move to the `bearerAuth` middleware the adapter ships.
- **Behaviour change — `@authplane/mcp` upstream-AS failures**: `JWKSFetchError` and `MetadataFetchError` previously fell through the adapter's catch and returned a generic 500 (`{ error: "server_error" }`). They now hit the shared funnel via `httpStatus(error)` and return **503** with `WWW-Authenticate: Bearer error="invalid_token"` (RFC 7235 §4.1 allows `WWW-Authenticate` on any response). The 503 is more accurate, but the `invalid_token` OAuth code in the body is a semantic mismatch since the failure is upstream, not in the client's token — **clients should rely on the HTTP status, not the `error` field, when deciding whether to retry with a fresh token.**

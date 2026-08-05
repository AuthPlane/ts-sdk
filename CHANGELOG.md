# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

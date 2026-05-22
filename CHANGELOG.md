# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-22

- `@authplane/fastmcp`: support `fastmcp` 4.x in addition to 3.35+. Consumers using `OAuthProxy` directly must set `allowedRedirectUriPatterns` themselves — fastmcp 4.0 removed the default value (CWE-601 fix).
- `@authplane/sdk`: `wwwAuthenticate(error, options)` gains `resourceMetadataUrl` (RFC 9728 §5.1) and `scope` (RFC 6750) options, sanitises interpolated values against header injection (RFC 9110 §11.4), and emits the `Bearer` scheme for `DPoPNotSupported`.
- `@authplane/fastmcp` and `@authplane/mcp`: authentication failures now emit a per-error `WWW-Authenticate` challenge via `httpStatus` + `wwwAuthenticate` from `@authplane/sdk/core`. DPoP failures use the `DPoP` scheme (RFC 9449 §7.1); `resource_metadata` is always included and `scope` when `requiredScopes` is configured.
- `@authplane/mcp`: upstream authorization-server fetch failures (`JWKSFetchError`, `MetadataFetchError`) now return `503` with a `WWW-Authenticate` challenge (RFC 7235 §4.1) instead of a generic `500`. Rely on the HTTP status, not the response `error` field, when deciding whether to retry.
- **Migration** — `@authplane/fastmcp`: `AuthplaneTokenVerifier.verifyAccessToken` now propagates `AuthplaneError` instead of returning `undefined`; wrap direct `tokenVerifier` calls in try/catch.
- **Migration** — `@authplane/mcp`: `AuthplaneTokenVerifier.verifyAccessToken` now propagates `AuthplaneError` instead of the MCP SDK's `InvalidTokenError`; switch `instanceof InvalidTokenError` checks to `instanceof AuthplaneError`, or adopt the `bearerAuth` middleware.

## [0.1.0] - 2026-05-11

- Initial release.

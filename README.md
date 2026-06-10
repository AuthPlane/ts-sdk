# Authplane TypeScript SDK

OAuth, JWT validation, and MCP-authentication primitives for Node.js. Ships framework adapters for Hono, NestJS, FastMCP, and the official MCP TypeScript SDK.

## Packages

| Package | Install | Purpose |
|---|---|---|
| [`@authplane/sdk`](packages/sdk) | `npm install @authplane/sdk` | JWT validation and OAuth protocol primitives. Ships the stateful `AuthplaneClient` (`@authplane/sdk/core`) plus stateless OAuth protocol helpers (`@authplane/sdk/auth`). |
| [`@authplane/mcp`](packages/mcp) | `npm install @authplane/sdk @authplane/mcp` | JWT validation adapter for the MCP TypeScript SDK |
| [`@authplane/fastmcp`](packages/fastmcp) | `npm install @authplane/sdk @authplane/fastmcp` | JWT validation adapter for FastMCP |
| [`@authplane/hono`](packages/hono) | `npm install @authplane/sdk @authplane/hono` | JWT validation middleware for the Hono web framework |
| [`@authplane/nestjs`](packages/nestjs) | `npm install @authplane/sdk @authplane/nestjs` | NestJS module: guard + decorators + exception filter + PRM controller |

## Requirements

- Node.js 22 LTS (or newer)
- TypeScript consumers: `moduleResolution` set to `bundler`, `node16`, or `nodenext` (required for the package `exports` subpaths)

## Quickstart

```ts
import { FastMCP } from "fastmcp";
import { authplaneFastMcpAuth } from "@authplane/fastmcp";

const auth = await authplaneFastMcpAuth({
  issuer: "http://localhost:9000",
  resource: "http://localhost:8090/mcp",
  scopes: ["tools/weather"],
});

const server = new FastMCP({
  name: "my-server",
  version: "1.0.0",
  authenticate: auth.authenticate,
});
```

For the MCP TypeScript SDK variant, see the [`@authplane/mcp` README](packages/mcp/README.md).

## Capabilities

### Standards and RFCs

- **OAuth 2.1** (draft-ietf-oauth-v2-1) — profile-aligned token validation defaults.
- **RFC 8414** — Authorization Server Metadata discovery.
- **RFC 9068** — JWT Profile for OAuth 2.0 Access Tokens (`typ: at+jwt`, required claims).
- **RFC 7662** — Token Introspection (can be wired as a revocation checker via `IntrospectionRevocation`).
- **RFC 7009** — Token Revocation.
- **RFC 8693** — Token Exchange.
- **RFC 9728** — OAuth Protected Resource Metadata (JSON builder and well-known URL).
- **RFC 9449** — DPoP, covering outbound proof generation (`DPoPProvider`) and inbound proof verification with replay-store hook.
- **RFC 8707** — Resource Indicators (honored by client credentials and token exchange).
- **RFC 6750** — Bearer Token Usage (adapters emit RFC-compliant `WWW-Authenticate` responses).
- **RFC 7234** — HTTP caching semantics on discovery responses (AS metadata + JWKS).
- **RFC 7519 / 7517** — JWT and JWKS.
- **RFC 7638** — JWK thumbprints (`jkt` for DPoP binding).

### Security

- Asymmetric-only signing (ES256, RS256 by default; extend `allowedAlgorithms` to accept others); `none` and HMAC algorithms rejected at construction time.
- Strict claim validation: exact `iss` match, `aud` membership, `typ: at+jwt`, required claims (`sub`, `client_id`, `exp`, `iat`, `jti`), configurable clock skew (30s default).
- SSRF hardening on every outbound fetch: HTTPS-only by default, blocks loopback, private networks, cloud metadata (169.254.0.0/16), multicast, reserved ranges. Dev-mode toggle relaxes these for local development only.
- Response size caps on metadata and JWKS fetches.
- DPoP (inbound): `htm`/`htu`/`ath` checks, `cnf.jkt` binding enforcement, optional caller-supplied replay store for JTI uniqueness.
- DPoP (outbound): proof generation with `use_dpop_nonce` retry support.
- Circuit breaker around AS interactions (default threshold 5 failures, cooldown 30s).
- Token caching for client-credentials responses with TTL buffer (default 30s before expiry).

### Framework integrations

- [`@authplane/mcp`](packages/mcp/README.md) — adapter for the official MCP TypeScript SDK.
- [`@authplane/fastmcp`](packages/fastmcp/README.md) — adapter for FastMCP.
- [`@authplane/hono`](packages/hono/README.md) — middleware for the Hono web framework (Bearer / DPoP, RFC 6750 `WWW-Authenticate`, PRM handler, scope enforcement).
- [`@authplane/nestjs`](packages/nestjs/README.md) — NestJS module: `AuthplaneAuthGuard`, `@SkipAuth()` / `@RequireScopes(...)` decorators, exception filter mapping to RFC 6750 §3 responses, and an RFC 9728 PRM controller. Works on Express and Fastify platform adapters.
- The MCP / FastMCP adapters integrate with Express / Node.js `http` through their respective transports; the Hono adapter is framework-native middleware; the NestJS adapter integrates with whatever platform NestJS is hosted on.

## Documentation

Each package ships its own README (overview) and User Guide (complete reference):

- **`@authplane/sdk`** — [README](packages/sdk/README.md) · [User Guide](packages/sdk/docs/user-guide.md)
- **`@authplane/mcp`** — [README](packages/mcp/README.md) · [User Guide](packages/mcp/docs/user-guide.md)
- **`@authplane/fastmcp`** — [README](packages/fastmcp/README.md) · [User Guide](packages/fastmcp/docs/user-guide.md)
- **`@authplane/hono`** — [README](packages/hono/README.md) · [User Guide](packages/hono/docs/user-guide.md)
- **`@authplane/nestjs`** — [README](packages/nestjs/README.md) · [User Guide](packages/nestjs/docs/user-guide.md)

Other docs:

- **[CHANGELOG.md](CHANGELOG.md)** — release history
- **[SECURITY.md](SECURITY.md)** — vulnerability reporting
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — for external contributors
- **[RELEASE_POLICY.md](RELEASE_POLICY.md)** — versioning and release flow

## License

Apache 2.0 — see [LICENSE](LICENSE).

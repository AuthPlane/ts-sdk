# `@authplane/mcp` — User Guide

Complete reference for the Authplane adapter for the official MCP TypeScript SDK. Starts with the quickstart and builds to advanced scenarios. For a short overview see the [package README](../README.md).

## Table of contents

- [Install](#install)
- [Quickstart](#quickstart)
- [`authplaneMcpAuth(options)` reference](#authplanemcpauthoptions-reference)
- [Scope enforcement](#scope-enforcement)
- [Per-tool scope enforcement with `requireScope`](#per-tool-scope-enforcement-with-requirescope)
- [URL elicitation for consent-required flows](#url-elicitation-for-consent-required-flows)
- [Introspection and revocation](#introspection-and-revocation)
- [DPoP-bound tokens](#dpop-bound-tokens)
- [Custom fetch settings](#custom-fetch-settings)
- [Error handling](#error-handling)
- [Cleanup](#cleanup)

## Install

```bash
npm install @authplane/sdk @authplane/mcp @modelcontextprotocol/sdk express zod
```

Requires Node 22 LTS or newer.

## Quickstart

A complete MCP server with Authplane auth and the Streamable HTTP transport:

```ts
import express from "express";
import crypto from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { authplaneMcpAuth } from "@authplane/mcp";
import { z } from "zod";

const server = new McpServer({ name: "my-server", version: "1.0.0" });

server.tool(
  "echo_message",
  "Echo message",
  { message: z.string() },
  async ({ message }) => ({ content: [{ type: "text", text: message }] }),
);

const auth = await authplaneMcpAuth({
  issuer: "http://localhost:9000",
  resource: "http://localhost:3000/mcp",
  scopes: ["tools/echo_message"],
});

const app = express();
app.use(express.json());
app.get(auth.protectedResourceMetadataPath, auth.protectedResourceMetadataHandler);

const transports = new Map<string, StreamableHTTPServerTransport>();
app.all("/mcp", auth.bearerAuth, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  if (sessionId && transports.has(sessionId)) {
    await transports.get(sessionId)!.handleRequest(req, res, req.body);
    return;
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
  });
  transports.set(transport.sessionId ?? crypto.randomUUID(), transport);
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000);
```

The adapter produces:

- an Express middleware (`bearerAuth`) that verifies tokens and attaches `req.auth`;
- an Express handler that serves RFC 9728 Protected Resource Metadata;
- an `AuthplaneResource` for direct use if you need lower-level access.

## `authplaneMcpAuth(options)` reference

### Options

| Field | Type | Purpose |
|---|---|---|
| `issuer` | `string` (required) | Authplane issuer URL (your `authserver`). |
| `resource` | `string` (required) | Resource URI tokens must be audience-bound to (`aud` claim). |
| `scopes` | `string[]` (optional) | All scopes this server supports. Used for PRM and, by default, as `requiredScopes`. |
| `requiredScopes` | `string[]` (optional) | Override of scopes enforced by `bearerAuth`. Defaults to `scopes` when absent (matches MCP SDK default). |
| `asCredentials` | `{ clientId, clientSecret }` (optional) | AS client credentials. Required when introspection/revocation is enabled. |
| `fetchSettings` | `FetchSettings` (optional) | Outbound fetch hardening (SSRF, timeouts, allowlists) applied to both AS metadata and JWKS fetches. Defaults are derived from `devMode`. |
| `jwksRefreshSeconds` | `number` (optional, default `300`) | JWKS cache TTL. |
| `metadataRefreshSeconds` | `number` (optional, default `3600`) | Metadata cache TTL. |
| `devMode` | `boolean` (optional, default `false`) | Relaxes HTTPS and private-host restrictions. Only for local dev. |
| `revocationChecker` | `RevocationChecker \| IntrospectionRevocation` (optional) | Enable real-time revocation checking. See [Introspection and revocation](#introspection-and-revocation). |
| `inboundDPoP` | `InboundDPoPOptions` (optional) | Per-resource inbound DPoP policy (RFC 9449 §7.1 + RFC 9728 §2). Presence is the on/off switch for advertising DPoP support in PRM and for accepting DPoP-bound tokens. See [DPoP-bound tokens](#dpop-bound-tokens). |
| `failClosed` | `boolean` (optional, default `false`) | When `true`, revocation-checker errors reject the token (`TokenRevoked`) instead of accepting it. |
| `allowedAlgorithms` | `string[]` (optional) | Allowed JWT `alg` values. Dangerous algorithms (`none`, `HS*`) are always rejected. Defaults to the SDK allow-list. |
| `clockSkewSeconds` | `number` (optional) | Applied to `exp`/`nbf`/`iat` checks. DPoP proof age uses `inboundDPoP.clockSkewSeconds` independently. |

`AuthplaneMcpAuthOptions` extends `Omit<AuthplaneResourceOptions, "scopes" | "resource">`, so `allowedAlgorithms`, `clockSkewSeconds`, `inboundDPoP`, `devMode`, `asCredentials`, `revocationChecker`, and `failClosed` are inherited from the underlying `AuthplaneResource` and forwarded as-is.

### Return value

| Field | Type | Purpose |
|---|---|---|
| `client` | `AuthplaneClient` | The underlying client constructed by the adapter. Call `client.close()` on shutdown. |
| `verifier` | `AuthplaneResource` | The resource primitive; call `verifier.verify(token)` directly if you need to bypass the middleware. |
| `tokenVerifier` | `AuthplaneTokenVerifier` | MCP SDK `OAuthTokenVerifier` implementation — use it if you're wiring middleware manually with `requireBearerAuth({ verifier: tokenVerifier, requiredScopes: [...] })`. |
| `bearerAuth` | `RequestHandler` | Ready-to-use Express middleware. Verifies token, enforces scopes, attaches `req.auth`. |
| `protectedResourceMetadataPath` | `string` | Express route path where the PRM should be served (e.g. `/.well-known/oauth-protected-resource/mcp`). |
| `protectedResourceMetadata` | `ProtectedResourceMetadata` | The PRM JSON payload. |
| `protectedResourceMetadataHandler` | `RequestHandler` | Express handler that serves the PRM. |

## Scope enforcement

By default, `bearerAuth` requires every scope in `options.scopes`. Override with `requiredScopes`:

```ts
const auth = await authplaneMcpAuth({
  issuer: "...",
  resource: "...",
  scopes: ["tools/read", "tools/write", "tools/admin"], // advertised in PRM
  requiredScopes: ["tools/read"],                       // enforced at the bearer-auth middleware
});
```

Tokens missing any of the `requiredScopes` are rejected with MCP's `InsufficientScopeError` (HTTP 403).

## Per-tool scope enforcement with `requireScope`

`bearerAuth` gates the transport; if you want finer-grained per-tool scope checks, call `requireScope` inside the tool:

```ts
import { requireScope } from "@authplane/mcp";

server.tool(
  "delete_thing",
  "Delete a thing",
  { id: z.string() },
  async ({ id }, extra) => {
    requireScope("tools/delete_thing", extra.authInfo);
    await deleteThing(id);
    return { content: [{ type: "text", text: `deleted ${id}` }] };
  },
);
```

`requireScope` throws if the scope is absent from `extra.authInfo?.scopes`.

## URL elicitation for consent-required flows

MCP defines error code `-32042` (`URL_ELICITATION_REQUIRED`) to signal that the user must visit a URL to finish authorization. The adapter handles this **automatically** — no per-tool wiring needed.

### How it works

`authplaneMcpAuth` wraps `client.exchange()` so that any `ConsentRequiredError` with a `consentUrl` is transparently translated to an MCP `-32042` error. Tool code stays clean:

```ts
server.tool(
  "exchange_for_calendar",
  schema,
  async (args, extra) => {
    // If the AS responds with consent_required + consentUrl, the
    // adapter maps it to -32042 automatically. No try/catch needed.
    const downstream = await auth.client.exchange({
      subjectToken: extra.authInfo?.token ?? "",
      scope: "calendar.read",
      resources: ["https://calendar.example.com"],
    });
    return { content: [{ type: "text", text: "ok" }] };
  },
);
```

The MCP client receives:

```json
{
  "code": -32042,
  "message": "Consent is required to proceed",
  "data": {
    "elicitations": [{
      "mode": "url",
      "url": "https://auth.company.com/consent?service=calendar",
      "elicitationId": "...uuid...",
      "message": "Consent is required to proceed (calendar: approval_pending)"
    }]
  }
}
```

Consent errors without a `consentUrl` pass through unchanged; non-consent errors are re-thrown as-is.

### Escape hatch

For custom consent flows outside `client.exchange()`, `toUrlElicitationRequiredError` is exported as a low-level primitive:

```ts
import { toUrlElicitationRequiredError } from "@authplane/mcp";

const mapped = toUrlElicitationRequiredError(error);
if (mapped) throw mapped;
// otherwise handle the original error
```

## Introspection and revocation

By default the adapter trusts signature + `exp`/`nbf`. To enable RFC 7662 introspection on every request (catches tokens revoked before expiry):

```ts
import { authplaneMcpAuth } from "@authplane/mcp";
import { IntrospectionRevocation } from "@authplane/sdk/core";

const auth = await authplaneMcpAuth({
  issuer: "...",
  resource: "...",
  scopes: ["tools/read"],
  asCredentials: { clientId: "rs-client", clientSecret: "<secret>" },
  revocationChecker: IntrospectionRevocation.get(),
});
```

`IntrospectionRevocation.get()` returns the marker singleton; the underlying `AuthplaneResource` calls `authserver`'s introspection endpoint on each `verify()`, and throws `TokenRevoked` (mapped to MCP's `InvalidTokenError`) when `active: false` is returned. This adds one round-trip per request; use only if eager revocation matters to your threat model.

You can also pass a custom `RevocationChecker` — an async function `(claims, rawToken) => Promise<boolean>` — for database-backed revocation lists.

## DPoP-bound tokens

The adapter expects the token in the `Authorization: Bearer <token>` header; anything else is rejected with `InvalidTokenError`. When the request also carries a `DPoP` proof header **and** the resource has opted into DPoP via `inboundDPoP`, the proof is verified against the token's `cnf.jkt` binding.

> **Note on the Authorization scheme.** RFC 9449 §7.1 recommends the `DPoP` scheme for DPoP-bound tokens, but the underlying MCP SDK's `requireBearerAuth` only accepts `Bearer`. Clients targeting MCP therefore must use `Authorization: Bearer <token>` with a separate `DPoP: <proof>` header. The `@authplane/fastmcp` adapter accepts both schemes.

### Three-mode DPoP enforcement

Whether DPoP is accepted, required, or rejected is decided per-resource by the presence and shape of `inboundDPoP`:

| Mode | `inboundDPoP` | Bearer-only token | DPoP-bound token (with proof) | DPoP signal on a non-bound token |
|---|---|---|---|---|
| **Required** | `{ required: true }` | rejected (`DPoPBindingMismatch`) | accepted | rejected |
| **Supported** | `{}` or `{ required: false }` | accepted | accepted | rejected as malformed |
| **Not configured** | omitted | accepted | rejected (`DPoPNotSupported`) | rejected (`DPoPNotSupported`) |

The PRM also reflects this: when `inboundDPoP` is configured the resource publishes both `dpop_signing_alg_values_supported` and `dpop_bound_access_tokens_required`. The required field is `true` only in Mode 1 (`required: true`); Mode 2 emits `false`. Mode 3 (no `inboundDPoP`) omits both fields entirely.

```ts
import { authplaneMcpAuth } from "@authplane/mcp";

// Mode 2 — Supported. Bearer and DPoP-bound tokens both accepted.
const auth = await authplaneMcpAuth({
  issuer: "https://auth.example.com",
  resource: "https://api.example.com/mcp",
  scopes: ["tools/read"],
  inboundDPoP: {},
});
```

```ts
// Mode 1 — Required. Bearer-only tokens rejected.
const auth = await authplaneMcpAuth({
  issuer: "https://auth.example.com",
  resource: "https://api.example.com/mcp",
  scopes: ["tools/read"],
  inboundDPoP: { required: true },
});
```

### `InboundDPoPOptions`

| Field | Type | Default | Purpose |
|---|---|---|---|
| `replayStore` | `DPoPReplayStore` | per-resource `InMemoryDPoPReplayStore` | Replay detector for accepted proof `jti`s. Use a shared store (Redis, database) for multi-process deployments. |
| `maxProofAgeSeconds` | `number` | `300` | Maximum proof age accepted from `iat`. |
| `clockSkewSeconds` | `number` | `30` | Allowable clock skew for proof time validation. |
| `allowedProofAlgorithms` | `readonly DPoPAlgorithm[]` | `["ES256", "RS256"]` | Accepted JOSE `alg` values; also advertised as `dpop_signing_alg_values_supported`. The narrowed type rejects unsupported alg names at compile time. |
| `required` | `boolean` | `false` | Promotes the resource to "Required" mode (bearer-only rejected). |

When `inboundDPoP` is configured, no per-request wiring is needed — the `bearerAuth` middleware automatically:

1. Extracts the `DPoP` proof header.
2. Reconstructs the absolute request URL as **configured-`resource` origin** (scheme + host + port from `options.resource`) **+ the dispatched request path** (`req.originalUrl` / `req.url`). Inbound `Host` and `X-Forwarded-Proto` headers are deliberately ignored: DPoP's cross-endpoint anti-replay (RFC 9449 §4.2) depends on the verifier comparing the proof's `htu` against an origin the operator controls, not one a requester or intermediary can influence.
3. Calls `resource.verify(token, { dpopRequest: { method, url, proof } })`. The replay store and proof tuning carried on `InboundDPoPOptions` are applied internally.

**Path-rewriting proxies break `htu` matching.** Because only the path comes from the request, a reverse proxy that rewrites the URL path (e.g. external `/api/mcp` → internal `/mcp`) will produce an `htu` mismatch — the proof was signed against the external URL the client saw, but the adapter only sees the rewritten internal path. RFC 9449 §4.2 acknowledges this; the mitigation is to forward the original request URL through the proxy unchanged rather than to derive the origin from headers.

For a custom `DPoPReplayStore` (Redis, etc.) see the [`@authplane/sdk` user guide](../../sdk/docs/user-guide.md#dpopreplaystore-interface).

## Custom fetch settings

Every outbound call (metadata, JWKS, introspection, revocation) routes through a `FetchSettings` instance. Tighten defaults:

```ts
import { FetchSettings } from "@authplane/sdk/core";

const tight = new FetchSettings({
  timeoutSeconds: 3,
  ssrfProtection: true,
  allowHttp: false,
});

const auth = await authplaneMcpAuth({
  issuer: "https://auth.example.com",
  resource: "https://mcp.example.com/mcp",
  scopes: ["tools/read"],
  fetchSettings: tight,
});
```

`fetchSettings` applies to both AS metadata discovery and JWKS fetches. See the [`@authplane/sdk` user guide](../../sdk/docs/user-guide.md#fetch-settings-and-ssrf-protection) for the full `FetchSettings` reference.

## Error handling

The adapter funnels every `AuthplaneError` (thrown by the underlying verifier and by the `bearerAuth` middleware's own checks) through `httpStatus(error)` + `wwwAuthenticate(error, { resourceMetadataUrl, scope })` from `@authplane/sdk/core`, so the wire-level mapping — Bearer vs DPoP scheme, 401 vs 403, the `DPoPNotSupported → Bearer` carve-out, header-value sanitisation — is defined once in the SDK and shared with `@authplane/fastmcp`.

See [**`@authplane/sdk` user guide — HTTP status and WWW-Authenticate challenge**](../../sdk/docs/user-guide.md#http-status-and-www-authenticate-challenge) for the canonical table.

The middleware emits a JSON body alongside the `WWW-Authenticate` header:

```json
{
  "error": "invalid_token",       // or "insufficient_scope"
  "error_description": "<the AuthplaneError.message>"
}
```

`resource_metadata="…"` is always included so clients can discover the AS; `scope="…"` is included when `requiredScopes` is configured. Non-Authplane errors fall through to a generic 500 (`error: "server_error"`).

## Cleanup

The underlying `AuthplaneClient` owns timers for JWKS and metadata refresh. On server shutdown call `close()` on the client so the process can exit cleanly:

```ts
await auth.client.close();
```

`auth.verifier.close()` exists for symmetry with `AuthplaneResource` but is a no-op — the resource does not own caches. Always close via `auth.client`.

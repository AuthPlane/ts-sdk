# `@authplane/fastmcp` — User Guide

Complete reference for the Authplane adapter for FastMCP. Starts with the quickstart and builds to advanced scenarios. For a short overview see the [package README](../README.md).

## Table of contents

- [Install](#install)
- [Quickstart](#quickstart)
- [`authplaneFastMcpAuth(options)` reference](#authplanefastmcpauthoptions-reference)
- [Session shape](#session-shape)
- [Scope enforcement](#scope-enforcement)
- [Resource URL from `baseUrl` + `mcpPath`](#resource-url-from-baseurl--mcppath)
- [Introspection and revocation](#introspection-and-revocation)
- [DPoP-bound tokens](#dpop-bound-tokens)
- [Custom fetch settings](#custom-fetch-settings)
- [URL elicitation for consent](#url-elicitation-for-consent)
- [Error handling](#error-handling)
- [Cleanup](#cleanup)

## Install

```bash
npm install @authplane/sdk @authplane/fastmcp fastmcp zod
```

Requires Node 22 LTS or newer.

## Quickstart

```ts
import { FastMCP, requireScopes } from "fastmcp";
import { z } from "zod";
import { authplaneFastMcpAuth, type AuthplaneFastMcpSession } from "@authplane/fastmcp";

const auth = await authplaneFastMcpAuth({
  issuer: "http://localhost:9000",
  resource: "http://localhost:8090/mcp",
  scopes: ["tools/weather"],
  devMode: true,
});

const server = new FastMCP<AuthplaneFastMcpSession>({
  name: "weather-server",
  version: "1.0.0",
  authenticate: auth.authenticate,
  oauth: auth.oauth,
});

server.addTool({
  name: "get_weather",
  description: "Get weather data by city",
  parameters: z.object({ city: z.string() }),
  canAccess: requireScopes("tools/weather"),
  execute: async ({ city }, { session }) => ({
    content: [{ type: "text", text: `${city} for ${session?.clientId}: 22C` }],
  }),
});

await server.start({
  transportType: "httpStream",
  httpStream: { port: 8090, endpoint: "/mcp" },
});
```

The adapter produces:

- a FastMCP `authenticate` callback that validates tokens and hydrates the session;
- a FastMCP `oauth` config publishing the RFC 9728 Protected Resource Metadata;
- an `AuthplaneResource` for direct low-level access when needed.

## `authplaneFastMcpAuth(options)` reference

### Options

| Field | Type | Purpose |
|---|---|---|
| `issuer` | `string` (required) | Authplane issuer URL (your `authserver`). |
| `resource` | `string` (required unless `baseUrl` given) | Resource URI tokens must be audience-bound to. |
| `baseUrl` | `string` (optional) | Alternative to `resource`. When combined with `mcpPath`, the resource is derived as `${baseUrl}${mcpPath}`. |
| `mcpPath` | `string` (optional, default `"/mcp"`) | Subpath appended to `baseUrl`. |
| `scopes` | `string[]` (optional) | All scopes this server supports. Used for PRM advertising. |
| `requiredScopes` | `string[]` (optional) | When set, the `authenticate` callback rejects tokens missing any scope in this list with HTTP 403 (`insufficient_scope`). |
| `asCredentials` | `{ clientId, clientSecret }` (optional) | AS client credentials. Required when introspection/revocation is enabled. |
| `fetchSettings` | `FetchSettings` (optional) | Outbound fetch hardening (SSRF, timeouts, allowlists) applied to both AS metadata and JWKS fetches. Defaults are derived from `devMode`. |
| `jwksRefreshSeconds` | `number` (optional, default `300`) | JWKS cache TTL. |
| `metadataRefreshSeconds` | `number` (optional, default `3600`) | Metadata cache TTL. |
| `devMode` | `boolean` (optional, default `false`) | Relaxes HTTPS / private-host restrictions. Only for local dev. |
| `revocationChecker` | `RevocationChecker \| IntrospectionRevocation` (optional) | Enable real-time revocation checking. |
| `inboundDPoP` | `InboundDPoPOptions` (optional) | Per-resource inbound DPoP policy (RFC 9449 §7.1 + RFC 9728 §2). Presence is the on/off switch for advertising DPoP support in PRM and for accepting DPoP-bound tokens. See [DPoP-bound tokens](#dpop-bound-tokens). |
| `failClosed` | `boolean` (optional, default `false`) | When `true`, revocation-checker errors reject the token (`TokenRevoked`) instead of accepting it. |
| `allowedAlgorithms` | `string[]` (optional) | Allowed JWT `alg` values. Dangerous algorithms (`none`, `HS*`) are always rejected. Defaults to the SDK allow-list. |
| `clockSkewSeconds` | `number` (optional) | Applied to `exp`/`nbf`/`iat` checks. DPoP proof age uses `inboundDPoP.clockSkewSeconds` independently. |

`AuthplaneFastMcpAuthOptions` extends `Omit<AuthplaneResourceOptions, "scopes" | "resource">`, so `allowedAlgorithms`, `clockSkewSeconds`, `inboundDPoP`, `devMode`, `asCredentials`, `revocationChecker`, and `failClosed` are inherited from the underlying `AuthplaneResource` and forwarded as-is.

### Return value

| Field | Type | Purpose |
|---|---|---|
| `client` | `AuthplaneClient` | The underlying client constructed by the adapter. Call `client.close()` on shutdown. |
| `verifier` | `AuthplaneResource` | Low-level primitive. Call `verifier.verify(token)` if you need to bypass the FastMCP authenticate callback. |
| `tokenVerifier` | `AuthplaneTokenVerifier` | Adapter wrapper around `AuthplaneResource.verify()` that returns `AuthplaneFastMcpSession \| undefined`. |
| `authenticate` | FastMCP `authenticate` callback | Plug into `new FastMCP({ authenticate: auth.authenticate, ... })`. Parses the bearer (or `DPoP ...`) header, verifies the token, and returns the session. |
| `oauth` | FastMCP `oauth` config | Plug into `new FastMCP({ oauth: auth.oauth, ... })`. Publishes the PRM. |
| `protectedResourceMetadata` | `ProtectedResourceMetadata` | The RFC 9728 JSON payload. |
| `protectedResourceMetadataUrl` | `string` | URL clients should fetch for the PRM. |

## Session shape

The session attached to each request is typed as `AuthplaneFastMcpSession`:

```ts
interface AuthplaneFastMcpSession {
  token: string;                       // raw bearer token
  clientId: string;                    // OAuth client id
  scopes: string[];                    // granted scopes
  expiresAt: number;                   // JWT exp (Unix seconds)
  claims: Record<string, unknown>;     // full decoded JWT payload
}
```

The convenience fields at the top (`clientId`, `scopes`, `expiresAt`) cover the common auth-gate checks; everything else the verifier extracted lives in `claims`:

```ts
server.addTool({
  name: "...",
  execute: async (args, { session }) => {
    const sub = session?.claims.sub as string;
    const jti = session?.claims.jti as string;
    const agentId = (session?.claims.agent_id as string) ?? "";
    console.log(`client=${session?.clientId} user=${sub}`);
    // ...
  },
});
```

Typing the `FastMCP` instance as `FastMCP<AuthplaneFastMcpSession>` gives you autocomplete on `session` throughout.

## Scope enforcement

**Global (all tools):** set `requiredScopes` on `authplaneFastMcpAuth`. The `authenticate` callback rejects tokens missing any of these with HTTP 403.

**Per tool:** use FastMCP's built-in `requireScopes` helper:

```ts
import { requireScopes } from "fastmcp";

server.addTool({
  name: "delete_thing",
  parameters: z.object({ id: z.string() }),
  canAccess: requireScopes("tools/delete_thing"),
  execute: async ({ id }) => { /* ... */ },
});
```

`canAccess` is evaluated per-tool-call against the session's scopes. Missing scopes produce FastMCP's standard "tool access denied" error.

## Resource URL from `baseUrl` + `mcpPath`

When you don't have a fixed `resource` URL at config time (e.g. the port is dynamic), provide `baseUrl` and optionally `mcpPath`; the adapter derives the resource itself:

```ts
const auth = await authplaneFastMcpAuth({
  issuer: "https://auth.example.com",
  baseUrl: `http://localhost:${PORT}`,
  mcpPath: "/mcp",           // optional, this is the default
  scopes: ["tools/weather"],
});
// → resource becomes `http://localhost:<PORT>/mcp`
```

This is convenient when wiring the MCP endpoint path through configuration. You can pass either `resource` OR `baseUrl`, not both.

## Introspection and revocation

```ts
import { authplaneFastMcpAuth } from "@authplane/fastmcp";
import { IntrospectionRevocation } from "@authplane/sdk/core";

const auth = await authplaneFastMcpAuth({
  issuer: "https://auth.example.com",
  resource: "https://mcp.example.com/mcp",
  scopes: ["tools/read"],
  asCredentials: { clientId: "rs-client", clientSecret: "<secret>" },
  revocationChecker: IntrospectionRevocation,
});
```

`IntrospectionRevocation` makes the adapter call `authserver`'s RFC 7662 introspection endpoint on every token verification; tokens with `active: false` are rejected. Adds one round-trip per authenticated request. Custom `RevocationChecker` callbacks are supported for DB-backed allowlists.

## DPoP-bound tokens

The adapter parses both `Authorization: Bearer <token>` and `Authorization: DPoP <token>` headers, and when a `DPoP` proof header is present it verifies the proof against the token's `cnf.jkt` binding — but only when the resource has opted in via `inboundDPoP`.

### Three-mode DPoP enforcement

Whether DPoP is accepted, required, or rejected is decided per-resource by the presence and shape of `inboundDPoP` (mirrors `python-sdk`):

| Mode | `inboundDPoP` | Bearer-only token | DPoP-bound token (with proof) | DPoP signal on a non-bound token |
|---|---|---|---|---|
| **Required** | `{ required: true }` | rejected (`DPoPBindingMismatch`) | accepted | rejected |
| **Supported** | `{}` or `{ required: false }` | accepted | accepted | rejected as malformed |
| **Not configured** | omitted | accepted | rejected (`DPoPNotSupported`) | rejected (`DPoPNotSupported`) |

The PRM also reflects this: when `inboundDPoP` is configured the resource publishes both `dpop_signing_alg_values_supported` and `dpop_bound_access_tokens_required`. The required field is `true` only in Mode 1 (`required: true`); Mode 2 emits `false`. Mode 3 (no `inboundDPoP`) omits both fields entirely.

```ts
import { authplaneFastMcpAuth } from "@authplane/fastmcp";

// Mode 2 — Supported. Bearer and DPoP-bound tokens both accepted.
const auth = await authplaneFastMcpAuth({
  issuer: "https://auth.example.com",
  resource: "https://api.example.com/mcp",
  scopes: ["tools/read"],
  inboundDPoP: {},
});
```

```ts
// Mode 1 — Required. Bearer-only tokens rejected.
const auth = await authplaneFastMcpAuth({
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

When `inboundDPoP` is configured, no per-request wiring is needed — the `authenticate` callback automatically:

1. Reads the `DPoP` header from the incoming `IncomingMessage`.
2. Reconstructs the absolute request URL as **configured-`resource` origin** (scheme + host + port from `options.resource` / `options.baseUrl`) **+ the dispatched request path** (`request.url`). Inbound `Host` and `X-Forwarded-Proto` headers are deliberately ignored: DPoP's cross-endpoint anti-replay (RFC 9449 §4.2) depends on the verifier comparing the proof's `htu` against an origin the operator controls, not one a requester or intermediary can influence.
3. Calls `resource.verify(token, { dpopRequest: { method, url, proof } })`. The replay store and proof tuning carried on `InboundDPoPOptions` are applied internally.

**Path-rewriting proxies break `htu` matching.** Because only the path comes from the request, a reverse proxy that rewrites the URL path (e.g. external `/api/mcp` → internal `/mcp`) will produce an `htu` mismatch — the proof was signed against the external URL the client saw, but the adapter only sees the rewritten internal path. RFC 9449 §4.2 acknowledges this; the mitigation is to forward the original request URL through the proxy unchanged rather than to derive the origin from headers.

Note: the verified proof details (`jkt`, `jti`, `iat`) live on the underlying `VerifiedClaims.dpopProof` produced by the verifier — they are not copied onto the FastMCP session. If a tool needs the bound key's thumbprint, read it from the `cnf.jkt` claim in `session.claims` (typed as `Record<string, unknown>`, so a cast is required):

```ts
function getBoundKeyThumbprint(session: AuthplaneFastMcpSession): string | undefined {
  const cnf = session.claims["cnf"] as { jkt?: string } | undefined;
  return cnf?.jkt;
}
```

The proof's `jti` and `iat` are not surfaced on the session; if you need them, call `verifier.verify()` directly to obtain a full `VerifiedClaims` with `dpopProof`.

DPoP error cases (missing/invalid/replayed proof, binding mismatch) surface as HTTP 401 with the `WWW-Authenticate` challenge from FastMCP.

## Custom fetch settings

Every outbound call (metadata, JWKS, introspection, revocation) routes through `FetchSettings`. Example:

```ts
import { FetchSettings } from "@authplane/sdk/core";

const tight = new FetchSettings({
  timeoutSeconds: 3,
  ssrfProtection: true,
  allowHttp: false,
});

const auth = await authplaneFastMcpAuth({
  issuer: "https://auth.example.com",
  resource: "https://mcp.example.com/mcp",
  scopes: ["tools/read"],
  fetchSettings: tight,
});
```

`fetchSettings` applies to both AS metadata discovery and JWKS fetches. See the [`@authplane/sdk` user guide](../../sdk/docs/user-guide.md#fetch-settings-and-ssrf-protection) for the complete `FetchSettings` reference.

## URL elicitation for consent

MCP defines error code `-32042` (`URL_ELICITATION_REQUIRED`) to signal that the user must visit a URL to finish authorization. The adapter handles this **automatically** — no per-tool wiring needed.

### How it works

`authplaneFastMcpAuth` wraps `client.exchange()` so that any `ConsentRequiredError` with a `consentUrl` is transparently translated to an MCP `-32042` error. Tool code stays clean:

```ts
server.addTool({
  name: "calendar",
  description: "Look up calendar events",
  parameters: z.object({ date: z.string() }),
  execute: async ({ date }, { session }) => {
    // If the AS responds with consent_required + consentUrl, the
    // adapter maps it to -32042 automatically. No try/catch needed.
    const downstream = await auth.client.exchange({
      subjectToken: session?.token ?? "",
      scope: "calendar.read",
      resources: ["https://calendar.example.com"],
    });
    return fetchCalendar(downstream.accessToken, date);
  },
});
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

> **Limitation — fastmcp swallows `McpError` from tool handlers.** As of fastmcp `3.35.0`, the tool-call dispatch catches every error that is not a `UserError` and wraps it as `{ isError: true, content: [...] }` in the tool result. That means an `UrlElicitationRequiredError` thrown from `client.exchange()` inside `execute()` reaches the client as a tool error, not as a JSON-RPC `-32042` response — the example payload above is the canonical shape, not what fastmcp 3.35.0 actually sends. To surface `-32042` end-to-end today, use the lower-level `@authplane/mcp` adapter (which goes through the official MCP SDK transport and propagates `McpError` as JSON-RPC). Track upstream resolution before relying on this path in production.

### Escape hatch

For custom consent flows outside `client.exchange()`, `toUrlElicitationRequiredError` is exported as a low-level primitive:

```ts
import { toUrlElicitationRequiredError } from "@authplane/fastmcp";

const mapped = toUrlElicitationRequiredError(error);
if (mapped) throw mapped;
// otherwise handle the original error
```

## Error handling

The adapter surfaces Authplane errors as standard HTTP responses via FastMCP:

| Authplane error | HTTP | `WWW-Authenticate` |
|---|---|---|
| `TokenMissing` | 401 | `Bearer realm="..."` |
| `TokenExpired`, `InvalidSignature`, `InvalidClaims`, `TokenRevoked` | 401 | `Bearer error="invalid_token"` |
| `InsufficientScope` (from `requiredScopes`) | 403 | `Bearer error="insufficient_scope"` |
| `DPoPProofMissing`, `InvalidDPoPProof`, `DPoPReplayDetected`, `DPoPBindingMismatch`, `DPoPNotSupported` | 401 | `Bearer error="invalid_token"` |

When the `authenticate` callback returns `undefined` (invalid token), FastMCP rejects the session with 401 and includes the PRM URL in the challenge so clients can discover the AS.

## Cleanup

The underlying `AuthplaneClient` owns timers for JWKS and metadata refresh. On server shutdown call `close()` on the client so the process can exit cleanly:

```ts
await auth.client.close();
```

`auth.verifier.close()` exists for symmetry with `AuthplaneResource` but is a no-op — the resource does not own caches. Always close via `auth.client`.

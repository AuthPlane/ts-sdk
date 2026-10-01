# `@authplane/mcp` — User Guide

Complete reference for the Authplane adapter for the official MCP TypeScript SDK. Starts with the quickstart and builds to advanced scenarios. For a short overview see the [package README](../README.md).

## Table of contents

- [Install](#install)
- [Quickstart](#quickstart)
- [`authplaneMcpAuth(options)` reference](#authplanemcpauthoptions-reference)
- [Where the PRM document lives](#where-the-prm-document-lives)
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
| `resourceMetadataUrl` | `string` (optional) | Absolute URL advertised as `resource_metadata=` on every challenge, overriding the URL derived from `resource`. See [Where the PRM document lives](#where-the-prm-document-lives). |
| `allowedAlgorithms` | `string[]` (optional) | Allowed JWT `alg` values. Dangerous algorithms (`none`, `HS*`) are always rejected. Defaults to the SDK allow-list. |
| `clockSkewSeconds` | `number` (optional) | Applied to `exp`/`nbf`/`iat` checks. DPoP proof age uses `inboundDPoP.clockSkewSeconds` independently. |

`AuthplaneMcpAuthOptions` extends `Omit<AuthplaneResourceOptions, "scopes" | "resource">`, so `allowedAlgorithms`, `clockSkewSeconds`, `inboundDPoP`, `devMode`, `asCredentials`, `revocationChecker`, and `failClosed` are inherited from the underlying `AuthplaneResource` and forwarded as-is.

### Return value

| Field | Type | Purpose |
|---|---|---|
| `client` | `AuthplaneClient` | The underlying client constructed by the adapter. Call `client.close()` on shutdown. |
| `verifier` | `AuthplaneResource` | The resource primitive; call `verifier.verify(token)` directly if you need to bypass the middleware. |
| `tokenVerifier` | `AuthplaneTokenVerifier` | MCP SDK `OAuthTokenVerifier` implementation — use it if you're wiring middleware manually with `requireBearerAuth({ verifier: tokenVerifier, requiredScopes: [...], resourceMetadataUrl })`, or handing a verifier to another MCP host framework. Set `resourceMetadataUrl` — without it the stock middleware omits the `resource_metadata` hint from 401 challenges and clients can't start discovery. Failures surface as MCP SDK error classes; see [Error handling](#error-handling). |
| `bearerAuth` | `RequestHandler` | Ready-to-use Express middleware. Verifies token, enforces scopes, attaches `req.auth`. |
| `protectedResourceMetadataPath` | `string` | Express route path where the PRM should be served (e.g. `/.well-known/oauth-protected-resource/mcp`). Always derived from `resource`, even when `resourceMetadataUrl` points elsewhere. |
| `protectedResourceMetadataUrl` | `string` | URL advertised as `resource_metadata=`. Pass it to `requireBearerAuth({ ..., resourceMetadataUrl })` when wiring the stock MCP SDK middleware, so both paths advertise the same document. |
| `protectedResourceMetadata` | `ProtectedResourceMetadata` | The PRM JSON payload. |
| `protectedResourceMetadataHandler` | `RequestHandler` | Express handler that serves the PRM. |

## Where the PRM document lives

RFC 9728 does not say who has to host the metadata document, only what a client finds when it follows the `resource_metadata` parameter of a `WWW-Authenticate` challenge. Two topologies work.

**(a) Resource-hosted — the default.** This server serves the document itself at the URL derived from `resource`, `/.well-known/oauth-protected-resource[/path]`, and every challenge points there. Nothing to configure. Mount `protectedResourceMetadataHandler` at `protectedResourceMetadataPath`, as the quickstart does.

**(b) AS-hosted.** `authserver` >= 0.2.0 serves an RFC 9728 document for every registered Resource at `<issuer>/.well-known/oauth-protected-resource/{ref}`, where `{ref}` is the Resource URI's path suffix (RFC 9728 §3.1) or its slug. Set `resourceMetadataUrl` to that URL and this server stops advertising its own; it only points at the AS's. Use it when the resource server cannot host well-known paths — a platform that owns `/.well-known`, a proxy that strips it, a resource mounted under a path it does not control.

Only the advertisement moves. `protectedResourceMetadataPath` and `protectedResourceMetadataHandler` are unchanged, so the local document keeps being served, and `protectedResourceMetadata.resource` still names this server's identifier. So the two documents can be served side by side during a migration, and switching back is a config change.

Whichever hosts it, RFC 9728 §3.3 binds the document to this server: the `resource` value **inside** the document must equal the URL clients call, byte for byte, or a conformant client discards the document — and the resource server then looks unreachable rather than misconfigured. So the Resource URI registered at the authorization server, the `resource` configured here, and this server's public URL must be the same string; a trailing slash or an `http`/`https` difference is enough to break it.


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

`requireScope` throws core `InsufficientScope` (from `@authplane/sdk/core`) if the scope is absent from `extra.authInfo?.scopes`, carrying the missing scope so a host that maps `AuthplaneError` answers `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="tools/delete_thing"`.

### Where the check runs decides whether the client gets a 403

**An in-handler `requireScope` cannot produce a 403 on the streamable-HTTP transport.** By the time a tool handler runs, the response has started and its status code is committed; the failure can only come back as a JSON-RPC error inside an HTTP 200. Nothing downstream can re-open the status line.

So there are two places to enforce a scope, and they are not interchangeable:

| Where | What the client sees | Use it for |
|---|---|---|
| Pre-dispatch — `bearerAuth`'s `requiredScopes`, or your own middleware ahead of the transport | `403` + `WWW-Authenticate: … error="insufficient_scope", scope="…"` | Any scope whose absence should make the client step up and retry |
| In a tool handler — `requireScope(scope, extra.authInfo)` | JSON-RPC error on HTTP 200 | Defence in depth: the call fails closed and the error names the scope |

If a per-tool scope is meant to trigger step-up, it has to be enforced pre-dispatch. The in-handler helper is a backstop for the case where middleware was misconfigured or a tool was added without its route-level gate — it is worth keeping, but it is not the step-up path.

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

**Operator step.** For each MCP server that exchanges for a downstream resource it does not itself act as, the operator must allowlist the exchanging client on the target Resource:

```http
PATCH /admin/resources/{id}
{"policy": {"exchange": {"allowed_client_ids": ["<exchanging-client-id>"]}}}
```

A client exchanging a token issued to itself, a fronted exchange and a Broker resource need nothing.

Two failure answers from the AS are policy, not outages, and neither counts toward the circuit breaker:

- `access_denied` (HTTP 403, `AccessDeniedError`) on a cross-client exchange means the operator has not allowlisted the exchanging client on the target Resource. Unlike `consent_required`, re-prompting the user will not fix it.
- `invalid_target` (HTTP 400, `InvalidTargetError`, RFC 8707 §2.2) means the `resource` string does not match a granted resource exactly — the comparison is byte for byte, so a trailing slash counts.

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

The introspecting client must be **confidential** (it needs a `clientSecret`) **and** either the client that was issued the token or a runtime-client of the Resource named in the token's `aud`. Since authserver 0.1.2 every other caller — a public (secret-less) client included — receives `{"active": false}`, which the SDK reads as "revoked", so a resource server introspecting with the wrong credentials silently rejects every token. Register the resource server on its Resource with:

```bash
authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>
```

A public client cannot introspect at all.

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

There are two entry points into verification, and each has its own error contract. Pick the one that matches who owns the HTTP response.

### `bearerAuth` — Authplane owns the response

The adapter funnels every `AuthplaneError` (thrown by the underlying verifier and by the `bearerAuth` middleware's own checks) through `httpStatus(error)` + `wwwAuthenticate(error, { resourceMetadataUrl, scope })` from `@authplane/sdk/core`, so the wire-level mapping — Bearer vs DPoP scheme, 401 vs 403, the `DPoPNotSupported → Bearer` carve-out, header-value sanitisation — is defined once in the SDK and shared with `@authplane/fastmcp`.

See [**`@authplane/sdk` user guide — HTTP status and WWW-Authenticate challenge**](../../sdk/docs/user-guide.md#http-status-and-www-authenticate-challenge) for the canonical table.

The middleware emits a JSON body alongside the `WWW-Authenticate` header:

```json
{
  "error": "invalid_token",       // or "insufficient_scope", "invalid_dpop_proof"
  "error_description": "The access token is missing or not valid for this resource"
}
```

`resource_metadata="…"` is always included so clients can discover the AS; `scope="…"` is included when `requiredScopes` is configured. Non-Authplane errors fall through to a generic 500 (`error: "server_error"`).

Body and challenge are built by the same core helpers, so they name one `error` code and carry one `error_description` — a fixed sentence chosen by that code, never the exception's message. Both halves reach a caller who by definition has not authenticated, and the SDK's messages name the failing detail: the unknown `kid`, the claim that did not validate, the `aud` the resource expects. The message stays on the exception for you to log. There is nothing left to strip in a wrapping middleware.

### `tokenVerifier` — a host framework owns the response

`tokenVerifier.verifyAccessToken(token)` is the `OAuthTokenVerifier` seam. Hosts that consume it — the MCP SDK's `requireBearerAuth`, and framework integrations built on the same interface — classify failures strictly by `instanceof` against the MCP SDK's own error classes, so this method rethrows in that taxonomy:

| Authplane error | Rethrown as | Host response |
|---|---|---|
| `InsufficientScope` | `InsufficientScopeError` | 403 `insufficient_scope` |
| Any error `httpStatus()` maps to 401 — `TokenMissing`, `TokenExpired`, `InvalidSignature`, `InvalidClaims`, `TokenRevoked`, `InvalidGrant`, and every `DPoPError` | `InvalidTokenError` | 401 `invalid_token` + `WWW-Authenticate` (carrying `resource_metadata` when the host sets `resourceMetadataUrl`) |
| `JWKSFetchError`, `MetadataFetchError`, `CircuitOpenError`, `VerifierRuntimeError` | `ServerError` | 500 `server_error` |

The MCP SDK has no 503 branch, so core's transient 503 conditions map to 500 through this seam. The original `AuthplaneError` is preserved on `error.cause` for logging. 401/403 messages are stripped of characters that would break out of a `WWW-Authenticate` quoted string, because the SDK's own header builder does not sanitise them; the 500 message is always the generic `Authorization server temporarily unavailable`, because the SDK renders it verbatim to unauthenticated clients and core's 5xx messages can carry infrastructure detail — read `error.cause` for the specifics.

Every DPoP failure surfaces under the `Bearer` scheme through this seam (`WWW-Authenticate: Bearer error="invalid_token"`); only `bearerAuth` can emit `DPoP`-scheme challenges.

Because the classification is `instanceof`-based, `@modelcontextprotocol/sdk` is a **peer dependency** of this package: your application and the adapter must resolve to the same copy. A duplicated nested install would turn every 401 into a 500 and stall client discovery — if you see that symptom, run `npm ls @modelcontextprotocol/sdk`. On installers that don't auto-install peers (npm < 7, Yarn classic), add the SDK to your application's dependencies explicitly.

`verifyAccessTokenWithDpop(token, dpopRequest?)` is the richer contract — it propagates raw `AuthplaneError` subclasses and is the only entry point that can thread per-request DPoP context. Use it when you build the challenge yourself, as `bearerAuth` does.

## Cleanup

The underlying `AuthplaneClient` owns timers for JWKS and metadata refresh. On server shutdown call `close()` on the client so the process can exit cleanly:

```ts
await auth.client.close();
```

`auth.verifier.close()` exists for symmetry with `AuthplaneResource` but is a no-op — the resource does not own caches. Always close via `auth.client`.

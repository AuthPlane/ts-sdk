# `@authplane/sdk` — User Guide

Complete reference for the core Authplane TypeScript SDK. Starts with the simplest use cases and builds up to advanced configuration. For a short overview see the [package README](../README.md).

## Table of contents

- [Install and import](#install-and-import)
- [Resource server: validating access tokens](#resource-server-validating-access-tokens)
  - [Minimal example](#minimal-example)
  - [Scope enforcement](#scope-enforcement)
  - [Claims available on `VerifiedClaims`](#claims-available-on-verifiedclaims)
- [Protected Resource Metadata (RFC 9728)](#protected-resource-metadata-rfc-9728)
- [Introspection and revocation](#introspection-and-revocation)
- [DPoP-bound tokens (RFC 9449)](#dpop-bound-tokens-rfc-9449)
  - [Verifying a DPoP proof on an inbound request](#verifying-a-dpop-proof-on-an-inbound-request)
  - [`DPoPReplayStore` interface](#dpopreplaystore-interface)
  - [Tuning DPoP acceptance](#tuning-dpop-acceptance)
  - [Client-side DPoP (obtaining DPoP-bound tokens)](#client-side-dpop-obtaining-dpop-bound-tokens)
- [OAuth client: obtaining tokens](#oauth-client-obtaining-tokens)
  - [Client credentials](#client-credentials)
  - [Token exchange (RFC 8693)](#token-exchange-rfc-8693)
  - [Introspection and revocation from the client](#introspection-and-revocation-from-the-client)
- [Single client model (`AuthplaneClient`)](#single-client-model-authplaneclient)
- [Fetch settings and SSRF protection](#fetch-settings-and-ssrf-protection)
- [Error types](#error-types)
- [HTTP status and WWW-Authenticate challenge](#http-status-and-www-authenticate-challenge)
- [Caching, circuit breaker, and cleanup](#caching-circuit-breaker-and-cleanup)

## Install and import

```bash
npm install @authplane/sdk
```

Requires Node.js 22 LTS or newer. Both subpath exports need one of `moduleResolution: "bundler" | "node16" | "nodenext"` in your `tsconfig.json`.

```ts
// Resource-server primitives
import { AuthplaneClient, AuthplaneResource, VerifiedClaims } from "@authplane/sdk/core";

// OAuth protocol primitives (leaf utilities)
import { exchange } from "@authplane/sdk/auth";
```

The two subpaths are independent — depend only on the one(s) you need.

## Resource server: validating access tokens

Use `@authplane/sdk/core` to validate bearer tokens presented to your resource server (an API, an MCP server, any HTTP service that requires authentication).

### Minimal example

```ts
import { AuthplaneClient } from "@authplane/sdk/core";

const client = await AuthplaneClient.create({
  issuer: "https://auth.example.com",
});

const resource = client.resource({
  resource: "https://api.example.com",
  scopes: ["read", "write"],
});

const claims = await resource.verify(bearerToken);
// claims is VerifiedClaims — all fields cryptographically verified
```

`AuthplaneClient.create()` performs RFC 8414 metadata discovery against the issuer and fetches the JWKS. The returned `client` caches both and refreshes them on a timer (5 minutes for JWKS, 1 hour for metadata by default).

`client.resource(...)` is cheap; call it once per protected resource you serve. It returns an `AuthplaneResource` that is pinned to the given `resource` URI and scope list, and holds a reference to the parent client's caches.

`resource.verify(token)` validates the signature, issuer, audience (`aud` must contain the configured `resource`), expiry (`exp`), not-before (`nbf`, if present), and JWT ID (`jti`). It returns a `VerifiedClaims` instance on success, or throws one of the [error types](#error-types) on failure.

The full signature is `verify(token, options?: { dpopRequest?: DPoPRequestContext })`. Pass `dpopRequest` to enforce RFC 9449 DPoP binding — see [DPoP-bound tokens](#dpop-bound-tokens-rfc-9449).

### Scope enforcement

`VerifiedClaims.requireScope(scope)` throws `InsufficientScope` if the scope is missing. Typical usage:

```ts
try {
  const claims = await resource.verify(token);
  claims.requireScope("tools/weather");
} catch (err) {
  // Map to HTTP 401 / 403 as appropriate
}
```

For multi-scope requirements, call `requireScope` once per scope, or check `claims.scopes` directly (it's `readonly string[]`).

### Claims available on `VerifiedClaims`

All fields are cryptographically verified and read-only.

| Field | Type | Source |
|---|---|---|
| `sub` | `string` | JWT `sub` claim — subject (user) ID |
| `clientId` | `string` | OAuth 2.1 client identifier |
| `scopes` | `readonly string[]` | JWT `scope` claim, split on whitespace |
| `issuer` | `string` | JWT `iss` — matches configured issuer |
| `audience` | `readonly string[]` | JWT `aud` — contains the configured `resource` |
| `expiresAt` | `number` | JWT `exp` (Unix seconds) |
| `issuedAt` | `number` | JWT `iat` (Unix seconds) |
| `jti` | `string` | JWT ID |
| `kid` | `string` | Key ID used to sign the token |
| `agentId` | `string` | Authplane extension `agent_id` (defaults to `""`) |
| `agentChain` | `readonly string[]` | Authplane extension `agent_chain` (defaults to `[]`) |
| `notBefore` | `number` | JWT `nbf` (defaults to `0` if absent) |
| `raw` | `Record<string, unknown>` | Full decoded payload |
| `dpopProof` | `VerifiedDPoPProof \| undefined` | Present only when DPoP validation ran |

Methods and accessors on `VerifiedClaims`:

| Member | Kind | Purpose |
|---|---|---|
| `requireScope(scope)` | method | Throws `InsufficientScope` if `scope` is not in `scopes`. |
| `hasScope(scope)` | method | Non-throwing equivalent of `requireScope` — returns `boolean`. |
| `hasClaim(key, value?)` | method | Presence check on `raw[key]`; with `value` also requires strict equality. |
| `act` | getter | RFC 8693 §4.1 immediate actor (`act` claim) when obtained via token exchange, or `undefined`. |
| `mayAct` | getter | **Deprecated** — authserver 0.2.0 no longer issues `may_act`; removed in the next minor. Always `undefined` against 0.2.0. |

## Protected Resource Metadata (RFC 9728)

Publish RFC 9728 metadata so clients can discover your resource's authorization server.

```ts
// Get the metadata JSON to serve at your well-known URL
const metadata = resource.prmResponse();

// Get the well-known URL clients should fetch
const url = resource.prmDocumentUrl();
// => "https://api.example.com/.well-known/oauth-protected-resource"
```

Wire this into any HTTP framework; the adapter packages (`@authplane/mcp`, `@authplane/fastmcp`) do this automatically. Manual Express example:

```ts
app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json(resource.prmResponse());
});
```

### Where the PRM document lives

RFC 9728 does not say who has to host the metadata document, only what a client finds when it follows the `resource_metadata` parameter of a `WWW-Authenticate` challenge. Two topologies work.

**(a) Resource-hosted — the default.** This server serves the document itself at the URL derived from `resource`, `/.well-known/oauth-protected-resource[/path]`, and every challenge points there. Nothing to configure. Serve `resource.prmResponse()` at `resource.prmDocumentUrl()` (or at `oauthProtectedResourceMetadataPath(resource)`); every adapter does this for you.

**(b) AS-hosted.** `authserver` >= 0.2.0 serves an RFC 9728 document for every registered Resource at `<issuer>/.well-known/oauth-protected-resource/{ref}`, where `{ref}` is the Resource URI's path suffix (RFC 9728 §3.1) or its slug. Set `resourceMetadataUrl` to that URL and this server stops advertising its own; it only points at the AS's. Use it when the resource server cannot host well-known paths — a platform that owns `/.well-known`, a proxy that strips it, a resource mounted under a path it does not control.

```ts
const resource = client.resource({
  resource: "https://api.example.com/mcp",
  scopes: ["read"],
  resourceMetadataUrl:
    "https://auth.example.com/.well-known/oauth-protected-resource/mcp",
});
```

Only the advertisement moves. `prmDocumentUrl()` keeps returning the derived URL — it is what the PRM route is mounted at — while `resource.resourceMetadataUrl()`, the accessor every challenge reads, returns the configured one. `prmResponse()` is unchanged. So the two documents can be served side by side during a migration, and switching back is a config change.

Whichever hosts it, RFC 9728 §3.3 binds the document to this server: the `resource` value **inside** the document must equal the URL clients call, byte for byte, or a conformant client discards the document — and the resource server then looks unreachable rather than misconfigured. So the Resource URI registered at the authorization server, the `resource` configured here, and this server's public URL must be the same string; a trailing slash or an `http`/`https` difference is enough to break it.

## Introspection and revocation

By default `AuthplaneResource.verify()` relies solely on the JWT signature + claims + `exp`/`nbf` to decide validity. For stricter scenarios where the AS may revoke tokens before expiry, combine verification with RFC 7662 introspection.

```ts
import { AuthplaneClient, IntrospectionRevocation } from "@authplane/sdk/core";

const client = await AuthplaneClient.create({
  issuer: "https://auth.example.com",
});

const resource = client.resource({
  resource: "https://api.example.com",
  scopes: ["read"],
  revocationChecker: IntrospectionRevocation.get(),
  asCredentials: { clientId: "rs-client", clientSecret: "<secret>" },
});
```

`IntrospectionRevocation.get()` returns the marker singleton that tells `AuthplaneResource.verify()` to call the AS's introspection endpoint on each token; if `active: false` comes back, `TokenRevoked` is thrown. The introspection request is authenticated with `asCredentials` configured on the resource itself — `auth` on `AuthplaneClient.create()` only powers token-acquisition flows (`clientCredentials`, `exchange`).

The introspecting client must be **confidential** (it needs a `clientSecret`) **and** either the client that was issued the token or a runtime-client of the Resource named in the token's `aud`. Since authserver 0.1.2 every other caller — a public (secret-less) client included — receives `{"active": false}`, which the SDK reads as "revoked", so a resource server introspecting with the wrong credentials silently rejects every token. Register the resource server on its Resource with:

```bash
authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>
```

A public client cannot introspect at all.

Constructing the resource without complete `asCredentials` logs a warning saying so; the first `active: false` on a token that passed local JWT verification logs a second one pointing at the runtime-client requirement (once per resource).

You can also pass a custom `RevocationChecker` function: `(claims, rawToken) => Promise<boolean>` — return `true` to reject.

### `failClosed` — availability vs. security for revocation errors

By default, if the revocation checker itself throws (introspection endpoint unreachable, user callback crashes), `verify()` logs a warning and **accepts** the token — availability over security. To invert the trade-off, set `failClosed: true` on the resource options; a throwing revocation checker will then raise `TokenRevoked`:

```ts
const resource = client.resource({
  resource: "https://api.example.com",
  scopes: ["read"],
  revocationChecker: IntrospectionRevocation.get(),
  asCredentials: { clientId: "rs-client", clientSecret: "<secret>" },
  failClosed: true, // reject on introspection transport errors
});
```

## DPoP-bound tokens (RFC 9449)

DPoP enforcement is **per-resource**, not per-request. To accept DPoP-bound tokens (or require them), opt the resource in by passing `inboundDPoP` to `client.resource(...)`. Three modes:

| Mode | `inboundDPoP` | Bearer-only token | DPoP-bound token (with proof) | DPoP signal on a non-bound token |
|---|---|---|---|---|
| **Required** | `{ required: true }` | rejected (`DPoPBindingMismatch`) | accepted | rejected |
| **Supported** | `{}` or `{ required: false }` | accepted | accepted | rejected as malformed |
| **Not configured** | omitted | accepted | rejected (`DPoPNotSupported`) | rejected (`DPoPNotSupported`) |

PRM advertising follows the same switch: when `inboundDPoP` is configured the resource publishes both `dpop_signing_alg_values_supported` and `dpop_bound_access_tokens_required`. The required field is `true` only in Mode 1 (`required: true`); Mode 2 emits `false`. Mode 3 (no `inboundDPoP`) omits both fields entirely.

### Verifying a DPoP proof on an inbound request

```ts
import {
  buildDPoPRequestContext,
  extractDpopHeaderValues,
} from "@authplane/sdk/core";

// Mode 2 — Supported. The resource allocates an in-memory replay store at
// construction; for multi-process deployments pass your own via inboundDPoP.replayStore.
const resource = client.resource({
  resource: "https://api.example.com",
  scopes: ["read"],
  inboundDPoP: {},
});

// `buildDPoPRequestContext` is the §4.3 boundary: it filters blanks and
// throws `MultipleDPoPProofs` when more than one non-blank value remains,
// so a request carrying two DPoP headers fails fast with a
// `DPoP error="invalid_dpop_proof"` challenge (RFC 9449 §7.1) instead of
// the verifier silently picking one. `extractDpopHeaderValues` normalises
// the framework-specific header shape (string | string[] | undefined)
// without losing duplicates.
const dpopRequest = buildDPoPRequestContext({
  method: request.method,                  // e.g. "POST"
  url: `${baseUrl}${request.path}`,        // absolute URL, used for htu match
  dpopHeaderValues: extractDpopHeaderValues(request.headers["dpop"]),
});

const claims = await resource.verify(bearerToken, { dpopRequest });
// claims.dpopProof.jkt is the verified public-key thumbprint;
// claims.dpopProof.jti and .iat are the proof's identifier and issued-at.
```

When a `dpopRequest` is provided to a DPoP-supporting resource, the verifier checks:

- The proof is a well-formed JWS signed with a supported EC or RSA key (`ES256`, `RS256`).
- The proof's `htm` matches the request method and `htu` matches the request URL.
- The proof's `ath` (access-token hash) matches the bearer token.
- The proof's `jti` has not been seen before by the resource's replay store.
- The token's `cnf.jkt` claim matches the proof's public-key thumbprint.

If `dpopRequest` is omitted altogether, `verify()` throws `DPoPBindingMismatch`. If `dpopRequest` is supplied but `proofs` is empty, `verify()` throws `DPoPProofMissing`. If `proofs` carries more than one non-blank value, `verify()` throws `MultipleDPoPProofs` and the resulting `WWW-Authenticate` challenge carries `DPoP error="invalid_dpop_proof"` per RFC 9449 §7.1. Other binding mismatches (proof's public-key thumbprint does not match the token's `cnf.jkt`, `htu`/`htm`/`ath` mismatch, etc.) throw `DPoPBindingMismatch`; replays throw `DPoPReplayDetected`. Sending a DPoP signal to a resource that did not opt into DPoP throws `DPoPNotSupported`.

### `InboundDPoPOptions`

| Field | Type | Default | Purpose |
|---|---|---|---|
| `replayStore` | `DPoPReplayStore` | per-resource `InMemoryDPoPReplayStore` | Replay detector for accepted proof `jti`s. Use a shared store (Redis, database) for multi-process deployments. |
| `maxProofAgeSeconds` | `number` | `300` | Maximum proof age accepted from `iat`. Shorter windows reduce the replay-store working set; longer windows tolerate clock skew. |
| `clockSkewSeconds` | `number` | `30` | Allowable clock skew for proof time validation. |
| `allowedProofAlgorithms` | `readonly DPoPAlgorithm[]` | `["ES256", "RS256"]` | Accepted JOSE `alg` values; also advertised as `dpop_signing_alg_values_supported`. The narrowed type rejects unsupported alg names at compile time. |
| `required` | `boolean` | `false` | Promotes the resource to "Required" mode (bearer-only rejected). |

### `DPoPReplayStore` interface

Implement your own store for Redis, Memcached, or any distributed cache:

```ts
import type { DPoPReplayStore } from "@authplane/sdk/core";

class RedisDPoPReplayStore implements DPoPReplayStore {
  async checkAndStore(jti: string, expiresAtSeconds: number): Promise<boolean> {
    // Return true if jti was newly stored, false if it was already present.
    // The check-and-store pair MUST be atomic (e.g. `SET NX EXAT`).
    const ttl = Math.max(1, expiresAtSeconds - Math.floor(Date.now() / 1000));
    const result = await redis.set(`dpop:${jti}`, "1", "EX", ttl, "NX");
    return result === "OK";
  }
}
```

Wire it via `inboundDPoP.replayStore`:

```ts
const resource = client.resource({
  resource: "https://api.example.com",
  scopes: ["read"],
  inboundDPoP: { replayStore: new RedisDPoPReplayStore() },
});
```

### Client-side DPoP (obtaining DPoP-bound tokens)

For clients that need to _obtain_ DPoP-bound tokens from the AS, use the DPoP provider primitives:

```ts
import {
  AuthplaneClient,
  DPoPKeyMaterial,
  DPoPProvider,
  InMemoryDPoPNonceStore,
} from "@authplane/sdk/core";

// Load your signing key from a PEM-encoded PKCS#8 private key.
// Supply one of the supported DPoP algorithms: "ES256" (default) or "RS256".
const keyMaterial = await DPoPKeyMaterial.fromPem(privateKeyPem, {
  algorithm: "ES256",
});

const dpopProvider = new DPoPProvider({
  keyMaterial,
  nonceStore: new InMemoryDPoPNonceStore(),
});

const client = await AuthplaneClient.create({
  issuer: "https://auth.example.com",
  auth: { clientId: "my-client", clientSecret: "<secret>" },
  dpopProvider,
});

// Token-endpoint calls now include DPoP proofs; issued tokens are key-bound.
const token = await client.clientCredentials(["api/read"]);
```

The provider transparently handles `use_dpop_nonce` challenges from RFC 9449 §8: each AS-issued `DPoP-Nonce` is stored per `scheme://host:port` key in the `DPoPNonceStore` and re-used on the next proof. If you need a durable or shared nonce cache (multi-process deployments), implement `DPoPNonceStore` yourself — the interface has just `get(key)` and `put(key, nonce)`. `InMemoryDPoPNonceStore` is bounded (LRU, default 128 entries) and suitable for single-process clients.

To construct `DPoPKeyMaterial` from an already-loaded key instead of a PEM, pass the private key object and a JWK representation of the public key directly to `new DPoPKeyMaterial({ privateKey, publicJwk, algorithm })`.

## OAuth client: obtaining tokens

Use `AuthplaneClient` as the single stateful client for OAuth operations (client credentials, token exchange, introspection, revocation). `@authplane/sdk/auth` now exposes stateless protocol primitives only.

### Client credentials

```ts
import { AuthplaneClient } from "@authplane/sdk/core";

const client = await AuthplaneClient.create({
  issuer: "https://auth.example.com",
  auth: { clientId: "my-client-id", clientSecret: "my-client-secret" },
});

const token = await client.clientCredentials(
  ["tools/read", "tools/write"],
  ["https://api.example.com"],
);
// token.accessToken, token.expiresIn, token.scope, ...
```

Scopes go in the first argument; resource indicators (RFC 8707) go in the second. **Always pass the resource indicators that match the resource server's `resource` URI** — otherwise the AS issues a token whose `aud` is the issuer URL, and `AuthplaneResource.verify()` will reject it with `InvalidClaims("unexpected aud claim value")`. Tokens are cached by the normalized scope/resource combination and reused until they fall within the configured TTL buffer (default 30 s before expiry).

### Token exchange (RFC 8693)

```ts
const exchanged = await client.exchange({
  subjectToken: incomingToken,
  resources: ["https://downstream.example.com"],
  scope: "tools/read",
  // actorToken + actorTokenType optional (produces a delegation chain)
});
```

Useful for service-to-service calls where a frontend API needs a narrowed or re-targeted token to call a downstream service.

**Operator step.** For each MCP server that exchanges for a downstream resource it does not itself act as, the operator must allowlist the exchanging client on the target Resource:

```http
PATCH /admin/resources/{id}
{"policy": {"exchange": {"allowed_client_ids": ["<exchanging-client-id>"]}}}
```

A client exchanging a token issued to itself, a fronted exchange and a Broker resource need nothing.

Two failure answers from the AS are policy, not outages, and neither counts toward the circuit breaker:

- `access_denied` (HTTP 403, `AccessDeniedError`) on a cross-client exchange means the operator has not allowlisted the exchanging client on the target Resource. Unlike `consent_required`, re-prompting the user will not fix it.
- `invalid_target` (HTTP 400, `InvalidTargetError`, RFC 8707 §2.2) means the `resource` string does not match a granted resource exactly — the comparison is byte for byte, so a trailing slash counts.

### Introspection and revocation from the client

```ts
const info = await client.introspect(token);
if (!info.active) { /* ... */ }

// RFC 9449 §6.2 exposes the DPoP confirmation thumbprint at the top
// level of the introspection response — the standardized location for
// opaque (non-JWT) DPoP-bound tokens. The SDK surfaces it as
// `info.cnfJkt`; when present, callers can match it against the proof
// public-key thumbprint to confirm the DPoP binding outside the JWT
// fast-path.
if (info.cnfJkt) {
  // info.cnfJkt is the base64url SHA-256 JWK thumbprint.
}

await client.revoke(token); // RFC 7009
```

## Single client model (`AuthplaneClient`)

`AuthplaneClient` is the only stateful client. It owns metadata/JWKS caches, token cache, and circuit breaker, and also performs OAuth operations when configured with `auth` (an `AuthProvider` or raw `ASCredentials`).

## Fetch settings and SSRF protection

Every outbound HTTP call (metadata, JWKS, introspection, revocation, token exchange) goes through a `FetchSettings` instance that enforces:

- Timeout (`timeoutSeconds`, default 10 s).
- SSRF protection (`ssrfProtection`, default `true`) — rejects URLs that resolve to private/loopback address space.
- HTTPS-only by default (`allowHttp: false`).
- Localhost and private-network opt-ins (`allowLocalhost`, `allowPrivateNetworks`, both default `false`).

### Dev mode

For local development against `http://localhost:9000` or `http://127.0.0.1:*`:

```ts
const client = await AuthplaneClient.create({
  issuer: "http://localhost:9000",
  devMode: true,
});
```

`devMode: true` relaxes the HTTPS requirement and allows private-address hosts, enabling the demo flows in `packages/{mcp,fastmcp}/demo`. **Never enable in production.**

### Custom fetch settings

```ts
import { FetchSettings } from "@authplane/sdk/core";

const tight = new FetchSettings({
  timeoutSeconds: 3,       // shorter than the 10 s default
  ssrfProtection: true,    // default; explicit for clarity
  allowHttp: false,        // default; reject plaintext HTTP
  allowLocalhost: false,   // default
  allowPrivateNetworks: false, // default
});

const client = await AuthplaneClient.create({
  issuer: "https://auth.example.com",
  fetchSettings: tight,
});
```

`fetchSettings` applies to both AS metadata discovery and JWKS fetches.

`FetchSettings.fromDevMode(true)` is a shortcut that inverts all of the opt-ins for local development (`allowHttp`, `allowLocalhost`, `allowPrivateNetworks` all `true`, SSRF protection disabled). **Never use in production.**

## Error types

All SDK errors extend `AuthplaneError`. Catch at the appropriate level and map to HTTP responses in your server.

**Validation errors** (thrown by `AuthplaneResource.verify`):

- `TokenMissing` — no bearer token supplied.
- `TokenExpired` — token past its `exp`.
- `InvalidSignature` — signature check failed (wrong key, tampered token).
- `InvalidClaims` — issuer/audience/`nbf` mismatch or malformed payload.
- `InsufficientScope` — required scope absent (thrown by `claims.requireScope`).
- `TokenRevoked` — revocation checker returned `true` (e.g. `IntrospectionRevocation` saw `active: false`).
- `JWKSFetchError`, `MetadataFetchError` — AS is unreachable or misconfigured.

**DPoP errors:**

- `DPoPProofMissing`, `InvalidDPoPProof`, `DPoPReplayDetected`, `DPoPBindingMismatch`, `DPoPNotSupported` (raised when a DPoP-bound token or proof header is presented to a resource that has not opted into DPoP via `inboundDPoP`).

**OAuth client errors** (thrown by `AuthplaneClient` token methods):

- `InvalidClientError`, `InvalidGrantError`, `InvalidRequestError`, `InvalidScopeError`, `UnauthorizedClientError`, `UnsupportedGrantTypeError`, `ConsentRequiredError`, `AccessDeniedError`, `InvalidTargetError`, `ServerError`.
- `AccessDeniedError` — `access_denied` (403) on a cross-client token exchange: the exchanging client is not allowlisted on the target Resource. An operator fix, not a user prompt (contrast `ConsentRequiredError`). Excluded from the circuit breaker.
- `InvalidTargetError` — `invalid_target` (400, RFC 8707 §2.2): the `resource` sent does not match a granted resource byte for byte. Excluded from the circuit breaker.
- `InvalidGrant` — top-level catch surface for token-exchange failures (subject/actor token rejected by the AS). Distinct from the `InvalidGrantError` OAuth-error subclass: `InvalidGrant` extends `AuthplaneError` directly and carries no OAuth `code` / `statusCode`. Maps to HTTP 401 via `httpStatus`.
- `CircuitOpenError` — circuit breaker is open (too many AS failures in a row).

The full error hierarchy is documented in `packages/sdk/src/core/errors.ts` and `packages/sdk/src/auth/errors.ts`.

## HTTP status and WWW-Authenticate challenge

For resource-server flows, two helpers turn the typed errors above into spec-compliant HTTP responses. Use them together — `httpStatus(error)` for the status code, `wwwAuthenticate(error, options)` for the `WWW-Authenticate` header value. Both `@authplane/mcp` and `@authplane/fastmcp` are thin wrappers around these.

### `httpStatus(error)`

Maps any `AuthplaneError` (and a few non-Authplane errors) to an HTTP status code:

| Error class | Status |
|---|---|
| `InsufficientScope` | 403 |
| `JWKSFetchError`, `MetadataFetchError`, `MissingMetadataEndpoint` | 503 |
| `TokenMissing`, `TokenExpired`, `InvalidSignature`, `InvalidClaims`, `TokenRevoked`, `InvalidGrant`, any `DPoPError` subclass | 401 |
| `VerifierRuntimeError`, any other (`Error`, `undefined`, …) | 500 |

### `wwwAuthenticate(error, options)`

Builds an RFC 6750 §3 `WWW-Authenticate` header value. Picks the right scheme (`Bearer` vs `DPoP`), the right `error=` code, and appends optional params:

| Error class | Scheme | `error=` |
|---|---|---|
| `TokenMissing`, `TokenExpired`, `InvalidSignature`, `InvalidClaims`, `TokenRevoked`, any other non-DPoP `AuthplaneError` | `Bearer` | `invalid_token` |
| `InsufficientScope` | `Bearer` | `insufficient_scope` |
| `DPoPProofMissing`, `InvalidDPoPProof`, `DPoPReplayDetected`, `DPoPBindingMismatch` | `DPoP` | `invalid_token` |
| `DPoPNotSupported` (carve-out) | `Bearer` | `invalid_token` |

`DPoPNotSupported` is the carve-out: although it extends `DPoPError`, the request was *not* DPoP-bound (the client presented a DPoP signal against a resource that does not accept DPoP), so the retry challenge must be `Bearer`. Subclass ordering in the implementation reflects this.

**Options:**

- `realm?: string` — appended as `realm="…"`.
- `resourceMetadataUrl?: string` — appended as `resource_metadata="…"` (RFC 9728 §5.1) so clients can discover the AS.
- `scope?: readonly string[]` — when non-empty, appended as `scope="…"` (RFC 6750), commonly paired with `insufficient_scope`.
- `verboseDescription?: boolean` — see below. Default `false`.

**`error_description` is fixed, not the exception message.** The challenge and the JSON error body both answer a caller who by definition has not authenticated, so the description is chosen by the `error=` code:

| `error=` | `error_description=` |
|---|---|
| `invalid_token` | `The access token is missing or not valid for this resource` |
| `insufficient_scope` | `The access token does not carry the scope this operation requires` |
| `invalid_dpop_proof` | `The DPoP proof is missing or not valid for this request` |

The SDK's own messages name the failing detail — the unknown `kid`, the claim that did not validate, the `typ` that was rejected — and an `aud` mismatch would hand the caller the exact audience string the resource expects, which is the value they would need in order to request a token for it. RFC 6750 §3 does not require `error_description` to be diagnostic; the `error=` code already carries what a conforming client acts on. The message stays on the exception, so log it server-side. `verboseDescription: true` restores the old behaviour for local debugging — it discloses SDK-internal detail to unauthenticated callers, so do not enable it in production.

This covers both halves of the response. `errorResponseBody(error, options?)` builds the JSON body from the same two decisions — the `error=` code above and the sentence it selects — so the body an adapter serves and the challenge beside it can never disagree, and neither carries the message. `@authplane/mcp`, `@authplane/hono` and `@authplane/nestjs` all serve it; write it yourself only if you are building an adapter, and pass `scheme` when you emit a multi-scheme challenge set so the one body names the half you want. `verboseDescription: true` restores the message there too, under the same warning.

**Sanitisation.** All interpolated values (`realm`, `resourceMetadataUrl`, joined `scope`, and a `verboseDescription` message) have CR / LF / `"` / `\` stripped before being spliced into the quoted-string parameter (RFC 9110 §11.4), so a crafted value cannot terminate the parameter or inject a new header field. Sanitisation is not a defence against disclosure, which is what the fixed descriptions above are for. The rule is exported as `sanitiseHeaderValue(value)` for code that splices values into a challenge through a header builder outside this SDK.

```ts
import { httpStatus, wwwAuthenticate, TokenExpired } from "@authplane/sdk/core";

try {
  await resource.verify(token);
} catch (error) {
  if (error instanceof AuthplaneError) {
    res
      .status(httpStatus(error))
      .set("WWW-Authenticate", wwwAuthenticate(error, {
        resourceMetadataUrl: "https://api.example.com/.well-known/oauth-protected-resource/mcp",
        scope: ["tools/admin"],
      }))
      .end();
  } else {
    res.status(500).end();
  }
}
```

### `wwwAuthenticateChallenges(error, options)`

`wwwAuthenticate` picks the scheme from the error's type, so it can only ever name one. A resource running inbound DPoP in optional mode accepts both `Bearer` and `DPoP` and should advertise both, so a DPoP-capable client can discover that sender-constrained tokens are taken here (RFC 9449 §7.1; §7.2 covers running the two side by side).

Two challenges cannot be comma-joined — the comma also separates parameters *inside* a challenge — so this returns one header value per scheme and the caller emits one header field per element:

```ts
import { wwwAuthenticateChallenges, httpStatus } from "@authplane/sdk/core";

res.status(httpStatus(error));
for (const challenge of wwwAuthenticateChallenges(error, {
  schemes: ["Bearer", "DPoP"],
  algs: inboundDPoP.allowedProofAlgorithms,
  resourceMetadataUrl: resource.prmDocumentUrl(),
})) {
  res.append("WWW-Authenticate", challenge);
}
```

It takes every `wwwAuthenticate` option plus two of its own:

- `schemes?: readonly string[]` — the schemes to advertise, in order. `Bearer` and `DPoP` are recognised case-insensitively and duplicates collapse. Omit it to derive the single scheme from the error, which returns exactly what `wwwAuthenticate` would, in a one-element array. An empty array or an unrecognised scheme throws a `TypeError` — the scheme is a bare RFC 7235 token, so an unusable value is refused rather than sanitised onto the wire.
- `algs?: readonly string[]` — the RFC 9449 §7.1 `algs` parameter, emitted on the `DPoP` challenge only and ignored when `DPoP` is not among `schemes`. Omitting the property omits the parameter; passing `undefined` means "the default set", the same meaning `InboundDPoPOptions.allowedProofAlgorithms` gives it, so `algs: options.allowedProofAlgorithms` is correct on an options object built from defaults. Values are validated against the supported set rather than escaped: escaping lets a comma through, and a comma is what a lenient client-side parser splits a joined challenge on.

The error selects the `error=` code per scheme the same way `wwwAuthenticate` does: `invalid_dpop_proof` is DPoP-specific, so a `Bearer` challenge emitted alongside a DPoP one keeps `invalid_token`.

## Caching, circuit breaker, and cleanup

- **Token cache.** `AuthplaneClient` caches client-credentials tokens (keyed by scope/resources). Configure TTL via `cacheTtlBufferSeconds` / `defaultTtlSeconds`.
- **JWKS / metadata cache.** `AuthplaneClient` refreshes JWKS every `jwksRefreshSeconds` (default 300) and metadata every `metadataRefreshSeconds` (default 3600). Both can be overridden. Refreshes are driven by traffic, not by a background timer: the first `verify()` (or AS-facing call) after the interval elapses pays for the refetch. A resource server that only verifies tokens therefore still tracks the AS. `jwks_uri` is read from the metadata document on every JWKS fetch rather than captured at construction, so a rotation takes effect on the next fetch with no window in which keys are still being pulled from the withdrawn URI. A token whose `kid` is absent from the cached JWKS re-reads metadata as well as the JWKS, so a rotation is followed on the request that first needs the new key rather than at the next interval boundary. That re-read is floored at one per `min(metadataRefreshSeconds, 60)` seconds, because the `kid` on an unverified token is attacker-controlled and the re-read bypasses the interval by design: without the floor, invalid tokens would drive discovery traffic at your AS one-for-one. Misses inside the floor fall back to an ordinary cache read, and the first miss after it re-reads immediately. Set `metadataRefreshSeconds: 0` to opt out.
- **Fetch-failure retry floor.** After a metadata or JWKS fetch fails, neither document is re-attempted for `fetchFailureBackoffSeconds` (default 30) — clamped per cache to `max(1, min(fetchFailureBackoffSeconds, refreshSeconds))`, so it never exceeds the cache's own refresh interval and never collapses to zero. In between, verifications are served from the last known good documents (an unreachable AS costs latency, not correctness); when nothing is cached yet, the retained failure surfaces immediately instead of stalling each caller on another doomed fetch. Without the floor, an AS outage amplifies into per-request latency on the resource server: once the refresh interval elapses, every wave of traffic pays the fetch timeout again — in-flight deduplication collapses concurrent callers, not the waves that follow. Any successful fetch closes the floor, and the first attempt it suppresses logs a `console.warn` naming the backing-off document (`metadata` or `JWKS`; once per floor window) so a backoff is distinguishable from a live outage. Raise the value if your AS is slow to come back and you would rather serve cached documents longer between probes; the floor is deliberately not fully disableable — except that a cache whose refresh interval is `0` (`metadataRefreshSeconds: 0` / `jwksRefreshSeconds: 0`, "re-read every time") opts out of the failure floor as well as the forced-read floor.
- **Circuit breaker.** `AuthplaneClient` opens a circuit after consecutive AS failures (default threshold 5, cooldown 30 s). While open, AS calls fail fast with `CircuitOpenError`. Successful calls after cooldown close the circuit.
- **Cleanup.** Call `await client.close()` on shutdown to stop timers and release resources. Adapters expose a `client` reference on their auth helper result so you can call `close()` from your server's shutdown hook.

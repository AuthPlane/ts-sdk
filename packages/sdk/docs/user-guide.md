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
| `mayAct` | getter | RFC 8693 §4.4 `may_act` — parties permitted to act on behalf of the subject, or `undefined`. |

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

- `InvalidClientError`, `InvalidGrantError`, `InvalidRequestError`, `InvalidScopeError`, `UnauthorizedClientError`, `UnsupportedGrantTypeError`, `ConsentRequiredError`, `ServerError`.
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

**Sanitisation.** All interpolated values (`error.message`, `realm`, `resourceMetadataUrl`, joined `scope`) have CR / LF / `"` / `\` stripped before being spliced into the quoted-string parameter (RFC 9110 §11.4), so a crafted error message cannot terminate the parameter or inject a new header field.

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

## Caching, circuit breaker, and cleanup

- **Token cache.** `AuthplaneClient` caches client-credentials tokens (keyed by scope/resources). Configure TTL via `cacheTtlBufferSeconds` / `defaultTtlSeconds`.
- **JWKS / metadata cache.** `AuthplaneClient` refreshes JWKS every `jwksRefreshSeconds` (default 300) and metadata every `metadataRefreshSeconds` (default 3600). Both can be overridden.
- **Circuit breaker.** `AuthplaneClient` opens a circuit after consecutive AS failures (default threshold 5, cooldown 30 s). While open, AS calls fail fast with `CircuitOpenError`. Successful calls after cooldown close the circuit.
- **Cleanup.** Call `await client.close()` on shutdown to stop timers and release resources. Adapters expose a `client` reference on their auth helper result so you can call `close()` from your server's shutdown hook.

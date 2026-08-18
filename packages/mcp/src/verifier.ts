import {
	AuthplaneError,
	type AuthplaneResource,
	type DPoPRequestContext,
	httpStatus,
	InvalidClaims,
	sanitiseHeaderValue,
} from "@authplane/sdk/core";
// Imported for their *runtime* identity, not just their shape: the SDK's
// `requireBearerAuth` classifies failures with `instanceof` against these
// exact constructors, so they must come from the same module instance the
// host loaded. `@modelcontextprotocol/sdk` is a peer dependency for that
// reason — a nested duplicate copy would silently downgrade every 401 to a
// 500. `ServerError` here is the MCP SDK's, not the identically named class
// `@authplane/sdk/core` re-exports for AS-side errors.
import {
	InsufficientScopeError,
	InvalidTokenError,
	ServerError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

/**
 * Translate an `AuthplaneError` into the MCP SDK error class that
 * `requireBearerAuth` maps to the right status and challenge.
 *
 * Both branches are derived from core's `httpStatus()` so the two adapters
 * can never drift:
 *
 * | Core `httpStatus()`                                   | SDK class                | Status |
 * | ----------------------------------------------------- | ------------------------ | ------ |
 * | 403 (`InsufficientScope`)                              | `InsufficientScopeError` | 403    |
 * | 401 (missing/expired/invalid/revoked token, any DPoP failure) | `InvalidTokenError` | 401 |
 * | everything else (JWKS/metadata fetch, circuit open, runtime) | `ServerError`      | 500    |
 *
 * The SDK has no 503 branch, so core's 503 transients (`JWKSFetchError`,
 * `MetadataFetchError`) land on `ServerError`/500 — the closest faithful
 * mapping through this seam.
 *
 * The 401/403 messages are core's, run through `sanitiseHeaderValue`: the
 * SDK's header builder splices `error.message` into the quoted-string
 * `error_description="…"` unsanitised, and core messages can carry quotes
 * (jose's `"exp" claim timestamp check failed`) that would truncate the
 * `resource_metadata` hint clients need to start discovery. The 500 message
 * is a fixed generic string instead — the SDK renders `ServerError.message`
 * verbatim in the unauthenticated response body, and core's 5xx messages can
 * embed infrastructure detail (fetch failures name the host they couldn't
 * reach). The original error stays on `.cause` either way.
 *
 * Non-`AuthplaneError` values pass through untouched: the SDK already turns
 * anything unrecognised into a 500, and keeping the original preserves the
 * stack trace for what is, by definition, an unexpected failure.
 */
function toMcpAuthError(error: unknown): unknown {
	if (!(error instanceof AuthplaneError)) {
		return error;
	}

	const status = httpStatus(error);
	const message = sanitiseHeaderValue(error.message);
	const mapped =
		status === 403
			? new InsufficientScopeError(message)
			: status === 401
				? new InvalidTokenError(message)
				: new ServerError("Authorization server temporarily unavailable");

	// The wire response only carries the sanitised (or generic) message; the
	// original core error stays reachable for host-side logging.
	mapped.cause = error;
	return mapped;
}

export class AuthplaneTokenVerifier implements OAuthTokenVerifier {
	public constructor(private readonly verifier: AuthplaneResource) {}

	/**
	 * `OAuthTokenVerifier` implementation — the seam foreign MCP hosts plug
	 * into (`requireBearerAuth`, and other `OAuthTokenVerifier`-based hosts).
	 *
	 * Failures are rethrown as MCP SDK error classes, because those hosts
	 * classify strictly by `instanceof`: a raw `AuthplaneError` reaching
	 * `requireBearerAuth` becomes a 500 with no `WWW-Authenticate`, and MCP
	 * discovery — which starts from `401` + `resource_metadata` — never
	 * begins. See {@link toMcpAuthError} for the mapping.
	 *
	 * Through this seam every DPoP failure — including `DPoPProofMissing` —
	 * surfaces as `Bearer error="invalid_token"`; only our own `bearerAuth`
	 * middleware (via the method below) can answer with a `DPoP`-scheme
	 * challenge.
	 *
	 * Callers wanting the untranslated `AuthplaneError` (to build their own
	 * challenge, or to distinguish DPoP failure modes) should use
	 * {@link AuthplaneTokenVerifier.verifyAccessTokenWithDpop} instead.
	 */
	public async verifyAccessToken(token: string): Promise<AuthInfo> {
		try {
			return await this.verifyAccessTokenWithDpop(token);
		} catch (error) {
			throw toMcpAuthError(error);
		}
	}

	/**
	 * Verifies an access token and projects the verified claims onto an
	 * MCP-SDK-shaped `AuthInfo`. `AuthplaneError` subclasses thrown by
	 * `verifier.verify()` propagate unchanged — the calling adapter
	 * (`bearerAuth` in `auth.ts`) is expected to classify them via the
	 * SDK's `httpStatus` / `wwwAuthenticate` helpers, so the wire-level
	 * scheme (Bearer vs DPoP), status (401 vs 403), and sanitisation
	 * live in one place across `@authplane/mcp` and
	 * `@authplane/fastmcp`.
	 *
	 * This is the richer of the two contracts and the only one that can
	 * thread per-request DPoP context; the plain
	 * {@link AuthplaneTokenVerifier.verifyAccessToken} above narrows its
	 * errors to what the MCP SDK understands.
	 */
	public async verifyAccessTokenWithDpop(
		token: string,
		dpopRequest?: DPoPRequestContext | undefined,
	): Promise<AuthInfo> {
		const claims = await this.verifier.verify(token, { dpopRequest });
		const audience = claims.audience[0];
		if (!audience) {
			throw new InvalidClaims("Token audience is missing");
		}

		// RFC 8707 resource indicators are URIs in practice but the OAuth
		// `aud` claim itself is just a string — a malformed value is a
		// token-validity problem (401), not an adapter bug (500). Wrap the
		// parse so `new URL()`'s TypeError can't escape as a 500.
		// Mirrors the `@authplane/hono` guard at packages/hono/src/verifier.ts.
		let resource: URL;
		try {
			resource = new URL(audience);
		} catch {
			throw new InvalidClaims("Token audience is not a valid URL");
		}

		return {
			token,
			clientId: claims.clientId,
			scopes: [...claims.scopes],
			expiresAt: claims.expiresAt,
			resource,
			extra: {
				sub: claims.sub,
				iss: claims.issuer,
				jti: claims.jti,
				kid: claims.kid,
			},
		};
	}
}

import {
	type AuthplaneResource,
	type DPoPRequestContext,
	InvalidClaims,
} from "@authplane/sdk/core";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

export class AuthplaneTokenVerifier implements OAuthTokenVerifier {
	public constructor(private readonly verifier: AuthplaneResource) {}

	public async verifyAccessToken(token: string): Promise<AuthInfo> {
		return this.verifyAccessTokenWithDpop(token);
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

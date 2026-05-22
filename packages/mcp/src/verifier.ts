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
		return {
			token,
			clientId: claims.clientId,
			scopes: [...claims.scopes],
			expiresAt: claims.expiresAt,
			resource: new URL(audience),
			extra: {
				sub: claims.sub,
				iss: claims.issuer,
				jti: claims.jti,
				kid: claims.kid,
			},
		};
	}
}

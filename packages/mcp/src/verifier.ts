import {
	AuthplaneError,
	type AuthplaneResource,
	type DPoPRequestContext,
} from "@authplane/sdk/core";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

export class AuthplaneTokenVerifier implements OAuthTokenVerifier {
	public constructor(private readonly verifier: AuthplaneResource) {}

	public async verifyAccessToken(token: string): Promise<AuthInfo> {
		return this.verifyAccessTokenWithDpop(token);
	}

	public async verifyAccessTokenWithDpop(
		token: string,
		dpopRequest?: DPoPRequestContext | undefined,
	): Promise<AuthInfo> {
		try {
			const claims = await this.verifier.verify(token, { dpopRequest });
			const audience = claims.audience[0];
			if (!audience) {
				throw new InvalidTokenError("Token audience is missing");
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
		} catch (error) {
			if (error instanceof AuthplaneError) {
				throw new InvalidTokenError(error.message);
			}
			throw error;
		}
	}
}

import type {
	AuthplaneResource,
	DPoPRequestContext,
} from "@authplane/sdk/core";

export interface AuthplaneFastMcpSession extends Record<string, unknown> {
	token: string;
	clientId: string;
	scopes: string[];
	expiresAt: number;
	claims: Record<string, unknown>;
}

export class AuthplaneTokenVerifier {
	public constructor(private readonly verifier: AuthplaneResource) {}

	/**
	 * Verify an access token and project the verified claims onto a
	 * FastMCP session. AuthplaneError subclasses propagate unchanged so
	 * the adapter can emit per-error `WWW-Authenticate` challenges
	 * matching the RFC 6750 / RFC 9449 contracts.
	 */
	public async verifyAccessToken(
		token: string,
		dpopRequest?: DPoPRequestContext | undefined,
	): Promise<AuthplaneFastMcpSession> {
		const claims = await this.verifier.verify(token, {
			dpopRequest,
		});
		return {
			token,
			clientId: claims.clientId,
			scopes: [...claims.scopes],
			expiresAt: claims.expiresAt,
			claims: { ...claims.raw },
		};
	}
}

import type { DPoPRequestContext } from "@authplane/sdk/core";
import { AuthplaneError, type AuthplaneResource } from "@authplane/sdk/core";

export interface AuthplaneFastMcpSession extends Record<string, unknown> {
	token: string;
	clientId: string;
	scopes: string[];
	expiresAt: number;
	claims: Record<string, unknown>;
}

export class AuthplaneTokenVerifier {
	public constructor(private readonly verifier: AuthplaneResource) {}

	public async verifyAccessToken(
		token: string,
		dpopRequest?: DPoPRequestContext | undefined,
	): Promise<AuthplaneFastMcpSession | undefined> {
		try {
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
		} catch (error) {
			if (error instanceof AuthplaneError) {
				return undefined;
			}
			throw error;
		}
	}
}

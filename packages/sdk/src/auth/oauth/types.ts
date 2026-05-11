export const GRANT_TYPE_TOKEN_EXCHANGE =
	"urn:ietf:params:oauth:grant-type:token-exchange";
export const TOKEN_TYPE_ACCESS_TOKEN =
	"urn:ietf:params:oauth:token-type:access_token";

export interface TokenExchangeOptions {
	subjectToken: string;
	subjectTokenType?: string;
	actorToken?: string;
	actorTokenType?: string;
	scope?: string;
	resources?: readonly string[];
	audiences?: readonly string[];
}

export interface TokenResponse {
	accessToken: string;
	tokenType: string;
	expiresIn: number;
	scope: string;
	refreshToken: string;
	issuedTokenType: string;
	cnfJkt: string;
	raw: Readonly<Record<string, unknown>>;
}

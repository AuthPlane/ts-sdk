import type { DPoPProvider } from "../dpop.js";
import { mapOAuthError } from "../errors.js";
import type { FetchSettings } from "../fetchSettings.js";
import { formPost } from "./http.js";
import { parseTokenResponse } from "./parsing.js";
import {
	GRANT_TYPE_TOKEN_EXCHANGE,
	TOKEN_TYPE_ACCESS_TOKEN,
	type TokenExchangeOptions,
	type TokenResponse,
} from "./types.js";

export async function exchange(options: {
	tokenEndpoint: string;
	exchange: TokenExchangeOptions;
	authHeader: Record<string, string>;
	fetchSettings: FetchSettings;
	dpopProvider?: DPoPProvider | undefined;
}): Promise<TokenResponse> {
	if (!options.exchange.subjectToken) {
		throw new Error("authplane: token exchange: subjectToken is required");
	}

	const subjectTokenType =
		options.exchange.subjectTokenType || TOKEN_TYPE_ACCESS_TOKEN;

	const formData: Array<[string, string]> = [
		["grant_type", GRANT_TYPE_TOKEN_EXCHANGE],
		["subject_token", options.exchange.subjectToken],
		["subject_token_type", subjectTokenType],
	];

	if (options.exchange.actorToken) {
		const actorTokenType =
			options.exchange.actorTokenType || TOKEN_TYPE_ACCESS_TOKEN;
		formData.push(["actor_token", options.exchange.actorToken]);
		formData.push(["actor_token_type", actorTokenType]);
	}

	if (options.exchange.scope) {
		formData.push(["scope", options.exchange.scope]);
	}

	for (const resource of options.exchange.resources ?? []) {
		if (resource) {
			formData.push(["resource", resource]);
		}
	}
	for (const audience of options.exchange.audiences ?? []) {
		if (audience) {
			formData.push(["audience", audience]);
		}
	}

	const response = await formPost({
		url: options.tokenEndpoint,
		formData,
		fetchSettings: options.fetchSettings,
		extraHeaders: options.authHeader,
		dpopProvider: options.dpopProvider,
	});
	if (response.statusCode < 200 || response.statusCode >= 300) {
		throw mapOAuthError("token exchange", response.statusCode, response.body);
	}
	return parseTokenResponse(response.body, {
		allowIssuedTokenType: true,
		expectDpop: options.dpopProvider !== undefined,
	});
}

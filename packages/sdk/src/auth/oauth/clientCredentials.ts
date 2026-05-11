import type { DPoPProvider } from "../dpop.js";
import { mapOAuthError } from "../errors.js";
import type { FetchSettings } from "../fetchSettings.js";
import { formPost } from "./http.js";
import { parseTokenResponse } from "./parsing.js";
import type { TokenResponse } from "./types.js";

export async function clientCredentialsGrant(options: {
	tokenEndpoint: string;
	scope?: string | undefined;
	resources?: readonly string[] | undefined;
	authHeader: Record<string, string>;
	fetchSettings: FetchSettings;
	dpopProvider?: DPoPProvider | undefined;
}): Promise<TokenResponse> {
	const formData: Array<[string, string]> = [
		["grant_type", "client_credentials"],
	];
	if (options.scope) {
		formData.push(["scope", options.scope]);
	}
	for (const resource of options.resources ?? []) {
		if (resource && resource.trim().length > 0) {
			formData.push(["resource", resource]);
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
		throw mapOAuthError(
			"client credentials",
			response.statusCode,
			response.body,
		);
	}

	return parseTokenResponse(response.body, {
		expectDpop: options.dpopProvider !== undefined,
	});
}

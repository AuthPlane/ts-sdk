import type { DPoPProvider } from "../dpop.js";
import { mapOAuthError } from "../errors.js";
import type { FetchSettings } from "../fetchSettings.js";
import { formPost } from "./http.js";

export async function revokeToken(options: {
	revocationEndpoint: string;
	token: string;
	authHeader: Record<string, string>;
	fetchSettings: FetchSettings;
	dpopProvider?: DPoPProvider | undefined;
	tokenTypeHint?: string | undefined;
}): Promise<void> {
	const formData: Record<string, string> = {
		token: options.token,
		token_type_hint: options.tokenTypeHint ?? "access_token",
	};

	const response = await formPost({
		url: options.revocationEndpoint,
		formData,
		fetchSettings: options.fetchSettings,
		extraHeaders: options.authHeader,
		dpopProvider: options.dpopProvider,
	});
	if (response.statusCode < 200 || response.statusCode >= 300) {
		throw mapOAuthError("revocation", response.statusCode, response.body);
	}
}

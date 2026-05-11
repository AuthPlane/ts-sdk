import type { FetchSettings } from "../auth/fetchSettings.js";
import { introspectToken } from "../auth/introspection.js";
import type { VerifiedClaims } from "./claims.js";
import { MetadataFetchError, MissingMetadataEndpoint } from "./errors.js";

export class IntrospectionChecker {
	private readonly fetchSettings: FetchSettings;
	private readonly authHeader: Record<string, string>;
	private getMetadata: (() => Promise<Record<string, unknown>>) | undefined;

	public constructor(
		getMetadata: (() => Promise<Record<string, unknown>>) | undefined,
		options: {
			fetchSettings: FetchSettings;
			clientId?: string | undefined;
			clientSecret?: string | undefined;
		},
	) {
		this.getMetadata = getMetadata;
		this.fetchSettings = options.fetchSettings;

		this.authHeader = {};
		if (options.clientId && options.clientSecret) {
			const encodedId = encodeURIComponent(options.clientId);
			const encodedSecret = encodeURIComponent(options.clientSecret);
			const encoded = Buffer.from(`${encodedId}:${encodedSecret}`).toString(
				"base64",
			);
			this.authHeader = { Authorization: `Basic ${encoded}` };
		}
	}

	public async check(
		_claims: VerifiedClaims,
		rawToken: string,
	): Promise<boolean> {
		if (!this.getMetadata) {
			throw new MetadataFetchError(
				"Introspection check: no metadata source configured",
			);
		}

		const metadata = await this.getMetadata();

		const introspectionEndpoint = metadata.introspection_endpoint;
		if (
			typeof introspectionEndpoint !== "string" ||
			introspectionEndpoint.length === 0
		) {
			throw new MissingMetadataEndpoint(
				"AS metadata missing 'introspection_endpoint'",
			);
		}

		const response = await introspectToken({
			introspectionEndpoint,
			token: rawToken,
			authHeader:
				Object.keys(this.authHeader).length > 0 ? this.authHeader : undefined,
			fetchSettings: this.fetchSettings,
		});

		return !response.active;
	}
}

import type { DPoPProvider } from "./dpop.js";
import { mapOAuthError } from "./errors.js";
import type { FetchSettings } from "./fetchSettings.js";
import { formPost } from "./oauth/http.js";

export interface IntrospectionResponse {
	active: boolean;
	scope: string;
	clientId: string;
	sub: string;
	tokenType: string;
	iss: string;
	aud: string | readonly string[] | null;
	exp: number | null;
	iat: number | null;
	jti: string;
	agentId: string;
	agentChain: readonly string[];
}

function parseOptionalNumber(value: unknown): number | null {
	if (typeof value !== "number") {
		return null;
	}
	return Number.isFinite(value) ? value : null;
}

function parseAud(value: unknown): string | readonly string[] | null {
	// RFC 7519 §4.1.3: aud may be a single string or an array of strings.
	// Preserve the server's form so callers can inspect both.
	if (typeof value === "string") {
		return value;
	}
	if (Array.isArray(value)) {
		return value.filter((v): v is string => typeof v === "string");
	}
	return null;
}

function parseIntrospectionResponse(
	data: Record<string, unknown>,
): IntrospectionResponse {
	const rawChain = data.agent_chain;
	const agentChain = Array.isArray(rawChain)
		? rawChain.map((x) => String(x))
		: [];

	return {
		active: Boolean(data.active ?? false),
		scope: typeof data.scope === "string" ? data.scope : "",
		clientId: typeof data.client_id === "string" ? data.client_id : "",
		sub: typeof data.sub === "string" ? data.sub : "",
		tokenType: typeof data.token_type === "string" ? data.token_type : "",
		iss: typeof data.iss === "string" ? data.iss : "",
		aud: parseAud(data.aud),
		exp: parseOptionalNumber(data.exp),
		iat: parseOptionalNumber(data.iat),
		jti: typeof data.jti === "string" ? data.jti : "",
		agentId: typeof data.agent_id === "string" ? data.agent_id : "",
		agentChain,
	};
}

export async function introspectToken(options: {
	introspectionEndpoint: string;
	token: string;
	authHeader?: Record<string, string> | undefined;
	fetchSettings: FetchSettings;
	dpopProvider?: DPoPProvider | undefined;
}): Promise<IntrospectionResponse> {
	const response = await formPost({
		url: options.introspectionEndpoint,
		formData: {
			token: options.token,
			token_type_hint: "access_token",
		},
		fetchSettings: options.fetchSettings,
		extraHeaders: options.authHeader,
		dpopProvider: options.dpopProvider,
	});

	if (response.statusCode < 200 || response.statusCode >= 300) {
		throw mapOAuthError("introspection", response.statusCode, response.body);
	}

	return parseIntrospectionResponse(response.body);
}

export class IntrospectionRevocation {
	private static readonly INSTANCE = new IntrospectionRevocation();
	private constructor() {}
	public static get(): IntrospectionRevocation {
		return IntrospectionRevocation.INSTANCE;
	}
}

export interface IntrospectionConfig {
	clientId?: string;
	clientSecret?: string;
}

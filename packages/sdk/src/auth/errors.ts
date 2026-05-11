export class AuthError extends Error {
	public readonly code: string;
	public readonly statusCode: number | null;

	public constructor(
		message = "Authorization server interaction failed.",
		options: { code?: string; statusCode?: number | null } = {},
	) {
		super(message);
		this.name = "AuthError";
		this.code = options.code ?? "";
		this.statusCode = options.statusCode ?? null;
	}
}

export class ProtocolError extends AuthError {
	public constructor(message = "OAuth/DPoP protocol message is malformed.") {
		super(message, { code: "protocol_error", statusCode: null });
		this.name = "ProtocolError";
	}
}

export class InvalidClientError extends AuthError {
	public constructor(message: string, statusCode: number | null = null) {
		super(message, { code: "invalid_client", statusCode });
		this.name = "InvalidClientError";
	}
}

export class UnauthorizedClientError extends AuthError {
	public constructor(message: string, statusCode: number | null = null) {
		super(message, { code: "unauthorized_client", statusCode });
		this.name = "UnauthorizedClientError";
	}
}

export class InvalidScopeError extends AuthError {
	public constructor(message: string, statusCode: number | null = null) {
		super(message, { code: "invalid_scope", statusCode });
		this.name = "InvalidScopeError";
	}
}

export class InvalidGrantError extends AuthError {
	public constructor(message: string, statusCode: number | null = null) {
		super(message, { code: "invalid_grant", statusCode });
		this.name = "InvalidGrantError";
	}
}

export class UnsupportedGrantTypeError extends AuthError {
	public constructor(message: string, statusCode: number | null = null) {
		super(message, { code: "unsupported_grant_type", statusCode });
		this.name = "UnsupportedGrantTypeError";
	}
}

export class InvalidRequestError extends AuthError {
	public constructor(message: string, statusCode: number | null = null) {
		super(message, { code: "invalid_request", statusCode });
		this.name = "InvalidRequestError";
	}
}

export class ConsentRequiredError extends AuthError {
	public readonly serviceId: string;
	public readonly causeDetail: string;
	public readonly consentUrl: string | null;

	public constructor(
		message: string,
		options: {
			serviceId: string;
			causeDetail: string;
			consentUrl?: string | null;
			oauthCode?: string;
			statusCode?: number | null;
		},
	) {
		super(message, {
			code: options.oauthCode ?? "consent_required",
			statusCode: options.statusCode ?? null,
		});
		this.name = "ConsentRequiredError";
		this.serviceId = options.serviceId;
		this.causeDetail = options.causeDetail;
		this.consentUrl = options.consentUrl ?? null;
	}

	/** Single-line description: `"<message> (<serviceId>: <causeDetail>)"`. */
	public describe(): string {
		const sid = this.serviceId || "unknown_service";
		const cause = this.causeDetail || this.message;
		return `${this.message} (${sid}: ${cause})`;
	}
}

export class ServerError extends AuthError {
	public constructor(
		message = "Authorization server returned an error.",
		statusCode: number | null = null,
	) {
		super(message, { code: "server_error", statusCode });
		this.name = "ServerError";
	}
}

export class DPoPNonceRequiredError extends AuthError {
	public constructor(
		message = "DPoP nonce required",
		public readonly nonce?: string,
	) {
		super(message, { code: "use_dpop_nonce", statusCode: 400 });
		this.name = "DPoPNonceRequiredError";
	}
}

export function mapOAuthError(
	operation: string,
	statusCode: number,
	data: Record<string, unknown>,
): AuthError {
	const oauthError = typeof data.error === "string" ? data.error : "";
	const description =
		typeof data.error_description === "string" ? data.error_description : "";

	const msg = description
		? `authplane: ${operation}: ${description}`
		: `authplane: ${operation}: ${oauthError || `HTTP ${statusCode}`}`;

	const errorMap: Record<string, (m: string, s: number) => AuthError> = {
		invalid_client: (m, s) => new InvalidClientError(m, s),
		unauthorized_client: (m, s) => new UnauthorizedClientError(m, s),
		invalid_scope: (m, s) => new InvalidScopeError(m, s),
		invalid_grant: (m, s) => new InvalidGrantError(m, s),
		unsupported_grant_type: (m, s) => new UnsupportedGrantTypeError(m, s),
		invalid_request: (m, s) => new InvalidRequestError(m, s),
	};

	if (statusCode >= 500) {
		return new ServerError(msg, statusCode);
	}

	const factory =
		oauthError && oauthError in errorMap ? errorMap[oauthError] : undefined;
	if (
		oauthError === "consent_required" ||
		oauthError === "interaction_required"
	) {
		const serviceId =
			(typeof data.service_id === "string" && data.service_id) ||
			(typeof data.service === "string" && data.service) ||
			(typeof data.resource === "string" && data.resource) ||
			"unknown_service";
		const causeDetail =
			typeof data.cause === "string" && data.cause.length > 0
				? data.cause
				: msg;
		const consentUrl =
			typeof data.consent_url === "string" && data.consent_url.length > 0
				? data.consent_url
				: null;
		return new ConsentRequiredError(msg, {
			serviceId,
			causeDetail,
			consentUrl,
			oauthCode: oauthError,
			statusCode,
		});
	}
	return factory
		? factory(msg, statusCode)
		: new AuthError(msg, { code: oauthError, statusCode });
}

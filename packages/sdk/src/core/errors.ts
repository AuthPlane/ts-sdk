import { ERROR_MESSAGES } from "./constants.js";

export class AuthplaneError extends Error {
	public constructor(message: string) {
		super(message);
		this.name = "AuthplaneError";
	}
}

export class VerifierRuntimeError extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.verifierRuntimeError) {
		super(message);
		this.name = "VerifierRuntimeError";
	}
}

export class TokenMissing extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.tokenMissing) {
		super(message);
		this.name = "TokenMissing";
	}
}

export class TokenExpired extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.tokenExpired) {
		super(message);
		this.name = "TokenExpired";
	}
}

export class InvalidSignature extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.invalidSignature) {
		super(message);
		this.name = "InvalidSignature";
	}
}

export class InvalidClaims extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.invalidClaims) {
		super(message);
		this.name = "InvalidClaims";
	}
}

export class InsufficientScope extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.insufficientScope) {
		super(message);
		this.name = "InsufficientScope";
	}
}

export class JWKSFetchError extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.jwksFetchError) {
		super(message);
		this.name = "JWKSFetchError";
	}
}

export class TokenRevoked extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.tokenRevoked) {
		super(message);
		this.name = "TokenRevoked";
	}
}

export class MetadataFetchError extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.metadataFetchError) {
		super(message);
		this.name = "MetadataFetchError";
	}
}

export class MissingMetadataEndpoint extends MetadataFetchError {
	public constructor(message = ERROR_MESSAGES.missingMetadataEndpoint) {
		super(message);
		this.name = "MissingMetadataEndpoint";
	}
}

// ---------------------------------------------------------------------------
// DPoP errors
// ---------------------------------------------------------------------------

export class DPoPError extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.dpopError) {
		super(message);
		this.name = "DPoPError";
	}
}

export class DPoPProofMissing extends DPoPError {
	public constructor(message = ERROR_MESSAGES.dpopProofMissing) {
		super(message);
		this.name = "DPoPProofMissing";
	}
}

export class InvalidDPoPProof extends DPoPError {
	public constructor(message = ERROR_MESSAGES.invalidDpopProof) {
		super(message);
		this.name = "InvalidDPoPProof";
	}
}

export class DPoPReplayDetected extends DPoPError {
	public constructor(message = ERROR_MESSAGES.dpopReplayDetected) {
		super(message);
		this.name = "DPoPReplayDetected";
	}
}

export class DPoPBindingMismatch extends DPoPError {
	public constructor(message = ERROR_MESSAGES.dpopBindingMismatch) {
		super(message);
		this.name = "DPoPBindingMismatch";
	}
}

/**
 * Raised when an inbound request carries more than one `DPoP` HTTP header.
 *
 * RFC 9449 §4.3 #1 is a MUST-level receiving-server check: "There is not
 * more than one `DPoP` HTTP request header field." Multiple headers signal
 * either a malformed client or an attempt to confuse the verifier about
 * which proof binds to the request, so the spec-correct response per §7.1
 * is `WWW-Authenticate: DPoP error="invalid_dpop_proof"`. The other
 * `DPoPError` subclasses in this SDK still emit `invalid_token` — only
 * this §4.3 error code carries `invalid_dpop_proof`. A broader sweep of
 * the DPoP error-code mapping is a separate change.
 *
 * Subclassing `DPoPError` keeps the `DPoP` challenge-scheme selection in
 * `wwwAuthenticate()`; the error-code override lives next to it.
 */
export class MultipleDPoPProofs extends DPoPError {
	public constructor(message = ERROR_MESSAGES.multipleDpopProofs) {
		super(message);
		this.name = "MultipleDPoPProofs";
	}
}

/**
 * Raised when a DPoP signal (header or `cnf.jkt`) is presented to a
 * resource that has not opted into inbound DPoP via {@link InboundDPoPOptions}.
 *
 * RFC 9449 §6 scopes proof validation to DPoP-supporting resources, so
 * silently falling back to bearer would drop sender-binding without the
 * caller noticing. Configure the resource with `inboundDPoP` to accept
 * DPoP-bound tokens; otherwise reject loudly.
 */
export class DPoPNotSupported extends DPoPError {
	public constructor(message = ERROR_MESSAGES.dpopNotSupported) {
		super(message);
		this.name = "DPoPNotSupported";
	}
}

export class CircuitOpenError extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.circuitOpenError) {
		super(message);
		this.name = "CircuitOpenError";
	}
}

/**
 * Raised when a token exchange (RFC 8693) fails because the subject or actor
 * token is invalid, expired, or otherwise not accepted by the authorization
 * server.
 *
 * Distinct from {@link InvalidGrantError}: that one is the OAuth-error-code
 * subclass mapped from `error: "invalid_grant"` in the AS response and extends
 * `AuthError`. `InvalidGrant` is a top-level `AuthplaneError` for the same
 * domain failure surfaced through token-exchange flows. Maps to HTTP 401.
 */
export class InvalidGrant extends AuthplaneError {
	public constructor(message = ERROR_MESSAGES.invalidGrant) {
		super(message);
		this.name = "InvalidGrant";
	}
}

/**
 * Map an SDK or OAuth error to the HTTP status code a resource server should
 * return.
 *
 * - 403 for {@link InsufficientScope}.
 * - 503 for {@link JWKSFetchError} and {@link MetadataFetchError} (the AS is
 *   temporarily unable to participate in token validation).
 * - 401 for authentication failures: missing / expired / invalid / revoked
 *   tokens and any DPoP error.
 * - 500 for internal / protocol errors and anything else.
 */
export function httpStatus(error: unknown): number {
	if (error instanceof InsufficientScope) {
		return 403;
	}
	if (error instanceof JWKSFetchError || error instanceof MetadataFetchError) {
		return 503;
	}
	if (
		error instanceof TokenMissing ||
		error instanceof TokenExpired ||
		error instanceof InvalidSignature ||
		error instanceof InvalidClaims ||
		error instanceof TokenRevoked ||
		error instanceof InvalidGrant ||
		error instanceof DPoPError
	) {
		return 401;
	}
	if (error instanceof VerifierRuntimeError) {
		return 500;
	}
	return 500;
}

/**
 * Sanitise a value spliced into a quoted-string parameter of the
 * `WWW-Authenticate` header (RFC 9110 §11.4). Strip CR, LF, double-quote
 * and backslash so a crafted error message (or operator-supplied
 * `resourceMetadataUrl` / `realm`) can't terminate the parameter or
 * inject a new header field.
 */
function sanitiseHeaderValue(value: string): string {
	return value.replace(/[\r\n"\\]+/g, " ").trim();
}

/**
 * Build an RFC 6750 §3 `WWW-Authenticate` header value.
 *
 * Maps SDK errors to the correct error code and authentication scheme:
 * - {@link InsufficientScope} → `insufficient_scope`
 * - {@link MultipleDPoPProofs} → `DPoP` scheme with `invalid_dpop_proof`
 *   (RFC 9449 §7.1 — the spec-defined error code for §4.3
 *   proof-validation failures)
 * - Other {@link DPoPError} subclasses → `DPoP` scheme with `invalid_token`
 *   (except {@link DPoPNotSupported}, see below)
 * - All other {@link AuthplaneError} → `Bearer` scheme with `invalid_token`
 *
 * `DPoPNotSupported` is the carve-out: although it extends `DPoPError`,
 * the request was *not* DPoP-bound — the client presented a DPoP signal
 * against a resource that does not accept DPoP, so the retry challenge
 * must be `Bearer`, not `DPoP`. The subclass branch order below is
 * load-bearing.
 *
 * Optional `options.resourceMetadataUrl` appends RFC 9728 §5.1
 * `resource_metadata="…"`. Optional `options.scope` appends RFC 6750
 * `scope="…"` when non-empty; commonly paired with `insufficient_scope`
 * but also valid alongside `invalid_token`.
 */
export function wwwAuthenticate(
	error: AuthplaneError,
	options: {
		realm?: string;
		resourceMetadataUrl?: string;
		scope?: readonly string[];
	} = {},
): string {
	const errorCode =
		error instanceof InsufficientScope
			? "insufficient_scope"
			: error instanceof MultipleDPoPProofs
				? "invalid_dpop_proof"
				: "invalid_token";
	const scheme =
		error instanceof DPoPNotSupported
			? "Bearer"
			: error instanceof DPoPError
				? "DPoP"
				: "Bearer";
	const parts: string[] = [];
	if (options.realm) {
		parts.push(`realm="${sanitiseHeaderValue(options.realm)}"`);
	}
	parts.push(`error="${errorCode}"`);
	parts.push(`error_description="${sanitiseHeaderValue(error.message)}"`);
	if (options.scope && options.scope.length > 0) {
		parts.push(`scope="${sanitiseHeaderValue(options.scope.join(" "))}"`);
	}
	if (options.resourceMetadataUrl) {
		parts.push(
			`resource_metadata="${sanitiseHeaderValue(options.resourceMetadataUrl)}"`,
		);
	}
	return `${scheme} ${parts.join(", ")}`;
}

// ---------------------------------------------------------------------------
// Auth client / OAuth errors (AS interactions)
// ---------------------------------------------------------------------------
export {
	AuthError,
	ConsentRequiredError,
	DPoPNonceRequiredError,
	InvalidClientError,
	InvalidGrantError,
	InvalidRequestError,
	InvalidScopeError,
	mapOAuthError,
	ProtocolError,
	ServerError,
	UnauthorizedClientError,
	UnsupportedGrantTypeError,
} from "../auth/errors.js";

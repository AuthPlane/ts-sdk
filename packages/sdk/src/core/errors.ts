import { SUPPORTED_DPOP_ALGORITHMS } from "../auth/dpop.js";
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
	/**
	 * The scope(s) whose absence caused the rejection, when the thrower knew
	 * them. `wwwAuthenticate()` falls back to this for the RFC 6750 §3
	 * `scope="…"` parameter: an `insufficient_scope` challenge that names no
	 * scope tells the client it was refused but not what to step up to, and
	 * the error message is no longer on the wire to imply it.
	 *
	 * Empty when the thrower had no specific scope to name — a middleware
	 * union check that passes its own configured scopes explicitly, say.
	 */
	public readonly requiredScopes: readonly string[];

	public constructor(
		message = ERROR_MESSAGES.insufficientScope,
		requiredScopes: readonly string[] = [],
	) {
		super(message);
		this.name = "InsufficientScope";
		this.requiredScopes = Object.freeze([...requiredScopes]);
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
 *
 * Exported so adapters that hand messages to header builders outside this
 * SDK (e.g. `@authplane/mcp`'s `OAuthTokenVerifier` seam, whose host splices
 * `error.message` into the challenge unsanitised) apply the same ruleset —
 * a tightened rule lands everywhere at once.
 */
export function sanitiseHeaderValue(value: string): string {
	return value.replace(/[\r\n"\\]+/g, " ").trim();
}

/**
 * Fixed, caller-safe `error_description` text, keyed by the RFC 6750 §3.1 /
 * RFC 9449 §7.1 error code.
 *
 * The challenge reaches a caller who by definition has not authenticated, so
 * the description is chosen by the error code and never taken from the
 * exception message. The SDK's own messages name the failing detail — the
 * unknown `kid`, the claim that did not validate, the `typ` that was rejected
 * — and an `aud` mismatch in particular would hand the caller the exact
 * audience string the resource expects, which is the value they would need in
 * order to request a token for it. RFC 6750 §3 does not require
 * `error_description` to be diagnostic: the `error` code already carries
 * everything a conforming client needs to decide what to do next.
 * {@link sanitiseHeaderValue} is not a defence here — it prevents header
 * injection, not disclosure; a sanitised `kid` is still a `kid`.
 *
 * The descriptions carry no comma. A comma inside a quoted-string is legal
 * RFC 7235, but it is also the separator between challenge parameters and
 * between header values, so keeping it out of the one parameter whose text we
 * choose leaves nothing for a lenient client-side parser to split on.
 */
const SAFE_ERROR_DESCRIPTIONS: Readonly<Record<string, string>> = {
	invalid_token: "The access token is missing or not valid for this resource",
	insufficient_scope:
		"The access token does not carry the scope this operation requires",
	invalid_dpop_proof: "The DPoP proof is missing or not valid for this request",
};

/**
 * Fallback for an error code added without a matching entry above. Kept
 * deliberately contentless for the same reason the table exists.
 */
const FALLBACK_ERROR_DESCRIPTION = "The request could not be authenticated";

/** Authentication scheme this SDK can advertise in a challenge. */
export type ChallengeScheme = "Bearer" | "DPoP";

/**
 * Schemes accepted from a caller, canonicalised. Unlike the quoted challenge
 * parameters, the scheme is a bare RFC 7235 token, so an unrecognised value is
 * rejected outright rather than sanitised into the header.
 */
const SUPPORTED_SCHEMES: Readonly<Record<string, ChallengeScheme>> = {
	bearer: "Bearer",
	dpop: "DPoP",
};

/** The RFC 6750 §3.1 error code to advertise for `error` under `scheme`. */
function errorCodeFor(error: AuthplaneError, scheme: ChallengeScheme): string {
	if (error instanceof InsufficientScope) {
		return "insufficient_scope";
	}
	// RFC 9449 §7.1 prescribes `invalid_dpop_proof` for §4.3 cardinality
	// rejections, not the `invalid_token` the other DPoPError shapes use. The
	// code is defined for the DPoP scheme, so a Bearer challenge emitted
	// alongside it keeps `invalid_token` rather than naming a code Bearer does
	// not define.
	if (error instanceof MultipleDPoPProofs && scheme === "DPoP") {
		return "invalid_dpop_proof";
	}
	return "invalid_token";
}

/**
 * The single scheme that matches `error`'s type.
 *
 * `DPoPNotSupported` is the carve-out: although it extends `DPoPError`, the
 * request was *not* DPoP-bound — the client presented a DPoP signal against a
 * resource that does not accept DPoP, so the retry challenge must be `Bearer`.
 * The branch order below is load-bearing.
 */
function schemeFor(error: AuthplaneError): ChallengeScheme {
	if (error instanceof DPoPNotSupported) {
		return "Bearer";
	}
	return error instanceof DPoPError ? "DPoP" : "Bearer";
}

/**
 * The fixed sentence for `errorCode`, with no transform applied. Split out of
 * {@link descriptionFor} because the challenge and the JSON body need the same
 * text under different escaping rules: the header path runs it through
 * {@link sanitiseHeaderValue}, the body path hands it to `JSON.stringify`.
 */
function safeDescriptionFor(errorCode: string): string {
	return SAFE_ERROR_DESCRIPTIONS[errorCode] ?? FALLBACK_ERROR_DESCRIPTION;
}

function descriptionFor(
	error: AuthplaneError,
	errorCode: string,
	verbose: boolean,
): string {
	if (verbose) {
		return sanitiseHeaderValue(error.message);
	}
	return safeDescriptionFor(errorCode);
}

/** Canonicalise and de-duplicate `schemes`, preserving caller order. */
function normaliseSchemes(schemes: readonly string[]): ChallengeScheme[] {
	const normalised: ChallengeScheme[] = [];
	for (const scheme of schemes) {
		// Object.hasOwn, not a bare index: SUPPORTED_SCHEMES is an object literal,
		// so `constructor`, `tostring` and above all `__proto__` resolve to
		// inherited members rather than undefined, skip the guard below, and put a
		// non-token value straight into the scheme position of the header.
		// noUncheckedIndexedAccess types this `ChallengeScheme | undefined`, which
		// is exactly the case where the type lies.
		const key = scheme.trim().toLowerCase();
		const canonical = Object.hasOwn(SUPPORTED_SCHEMES, key)
			? SUPPORTED_SCHEMES[key]
			: undefined;
		if (canonical === undefined) {
			throw new TypeError(
				`Unsupported authentication scheme ${JSON.stringify(scheme)}; only ${JSON.stringify(
					Object.values(SUPPORTED_SCHEMES),
				)} can be advertised`,
			);
		}
		if (!normalised.includes(canonical)) {
			normalised.push(canonical);
		}
	}
	if (normalised.length === 0) {
		throw new TypeError(
			"schemes must be non-empty; omit it to derive the scheme from the error",
		);
	}
	return normalised;
}

/**
 * Resolve `algs` to the exact set to advertise, rejecting what cannot be.
 *
 * Three inputs, three defined meanings:
 *
 * - the property absent — omit the parameter. This is what every caller that
 *   does not care about `algs` relies on, so it has to be the default.
 * - the property present and `undefined` — the default set, the same meaning
 *   `InboundDPoPOptions.allowedProofAlgorithms` gives it. This is what
 *   makes the documented `algs: options.allowedProofAlgorithms` call correct
 *   on an options object built from defaults, where that field *is*
 *   `undefined`: it would otherwise advertise nothing at all. Presence is read
 *   off the object rather than off the value because those are the only two
 *   states TypeScript cannot collapse into one.
 * - an array — validated, not sanitised. These are bare RFC 7235 tokens, the
 *   same shape as the scheme, so they get the same treatment: an unusable
 *   value is refused rather than quietly rewritten. Escaping alone lets a
 *   comma through, and a comma is the one character the surrounding code works
 *   to keep out of parameter text so that a lenient client-side parser has
 *   nothing to split on. An empty array stays "omit the parameter".
 */
function resolveAlgs(options: {
	algs?: readonly string[] | undefined;
}): readonly string[] {
	if (!Object.hasOwn(options, "algs")) {
		return [];
	}
	const algs = options.algs;
	if (algs === undefined) {
		return SUPPORTED_DPOP_ALGORITHMS;
	}
	// Defense in depth for JSON-config callers that cast at the boundary: a
	// bare string is iterable, so it would join into `algs="E S 2 5 6"` — a
	// challenge advertising algorithms that do not exist, from which a
	// conforming client concludes it cannot sign a proof at all.
	if (typeof algs === "string") {
		throw new TypeError(
			`algs must be an array of algorithm names, not a bare string (${JSON.stringify(algs)}); pass [${JSON.stringify(algs)}] to advertise a single algorithm`,
		);
	}
	const supported = SUPPORTED_DPOP_ALGORITHMS as readonly string[];
	const unsupported = algs.filter((alg) => !supported.includes(alg));
	if (unsupported.length > 0) {
		throw new TypeError(
			`Unsupported DPoP proof algorithms ${JSON.stringify(unsupported)}; only ${JSON.stringify(SUPPORTED_DPOP_ALGORITHMS)} can be advertised`,
		);
	}
	return algs;
}

/**
 * Fall back to {@link InsufficientScope.requiredScopes} when the caller passed
 * no `scope`. An explicit argument always wins, including an empty one — a
 * middleware that knows its own required scopes has said what it wants.
 */
function resolveScope(
	error: AuthplaneError,
	scope: readonly string[] | undefined,
): readonly string[] | undefined {
	if (
		scope === undefined &&
		error instanceof InsufficientScope &&
		error.requiredScopes.length > 0
	) {
		return error.requiredScopes;
	}
	return scope;
}

/** Assemble one `WWW-Authenticate` header value for a single scheme. */
function buildChallenge(
	error: AuthplaneError,
	scheme: ChallengeScheme,
	options: {
		realm: string | undefined;
		resourceMetadataUrl: string | undefined;
		scope: readonly string[] | undefined;
		algs: readonly string[];
		verboseDescription: boolean;
	},
): string {
	const errorCode = errorCodeFor(error, scheme);
	const parts: string[] = [];
	if (options.realm) {
		parts.push(`realm="${sanitiseHeaderValue(options.realm)}"`);
	}
	parts.push(`error="${errorCode}"`);
	parts.push(
		`error_description="${descriptionFor(error, errorCode, options.verboseDescription)}"`,
	);
	if (options.scope && options.scope.length > 0) {
		parts.push(`scope="${sanitiseHeaderValue(options.scope.join(" "))}"`);
	}
	if (options.resourceMetadataUrl) {
		parts.push(
			`resource_metadata="${sanitiseHeaderValue(options.resourceMetadataUrl)}"`,
		);
	}
	// RFC 9449 §7.1 defines `algs` for the DPoP challenge only, so a Bearer
	// challenge in the same set never carries it. No escaping: `resolveAlgs`
	// has already refused anything that is not one of the supported bare
	// tokens, so there is nothing to escape.
	if (scheme === "DPoP" && options.algs.length > 0) {
		parts.push(`algs="${options.algs.join(" ")}"`);
	}
	return `${scheme} ${parts.join(", ")}`;
}

/** Options shared by both challenge builders. */
export interface ChallengeOptions {
	/** RFC 7235 `realm`, emitted on every challenge when non-empty. */
	realm?: string;
	/** RFC 9728 §5.1 `resource_metadata`, emitted on every challenge. */
	resourceMetadataUrl?: string;
	/**
	 * RFC 6750 §3 `scope`, space-joined, emitted when non-empty. Falls back to
	 * {@link InsufficientScope.requiredScopes} when not passed.
	 */
	scope?: readonly string[];
	/**
	 * Development-only. Restores the previous behaviour of copying the
	 * exception message into `error_description`. It discloses SDK-internal
	 * detail (the unknown `kid`, the claim that failed, the expected
	 * audience) to unauthenticated callers, so do not enable it in
	 * production. Defaults to `false`.
	 */
	verboseDescription?: boolean;
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
 *   (except {@link DPoPNotSupported}, which retries as `Bearer`)
 * - All other {@link AuthplaneError} → `Bearer` scheme with `invalid_token`
 *
 * `error_description` is a fixed, caller-safe sentence chosen by the error
 * code — the exception's own message is never placed on the wire, because the
 * challenge is served to a caller who has not authenticated. The message stays
 * on the exception for the resource server to log.
 *
 * Optional `options.resourceMetadataUrl` appends RFC 9728 §5.1
 * `resource_metadata="…"`. Optional `options.scope` appends RFC 6750
 * `scope="…"` when non-empty; commonly paired with `insufficient_scope`
 * but also valid alongside `invalid_token`. Every interpolated value is
 * sanitised against header injection (RFC 9110 §11.4).
 *
 * A resource that accepts more than one scheme — inbound DPoP in optional
 * mode accepts both `Bearer` and `DPoP` — cannot be described by a single
 * header value; use {@link wwwAuthenticateChallenges} for that.
 */
export function wwwAuthenticate(
	error: AuthplaneError,
	options: ChallengeOptions = {},
): string {
	return buildChallenge(error, schemeFor(error), {
		realm: options.realm,
		resourceMetadataUrl: options.resourceMetadataUrl,
		scope: resolveScope(error, options.scope),
		algs: [],
		verboseDescription: options.verboseDescription ?? false,
	});
}

/** Options for {@link wwwAuthenticateChallenges}. */
export interface ChallengesOptions extends ChallengeOptions {
	/**
	 * The schemes to advertise, in the order they should appear. `Bearer` and
	 * `DPoP` are recognised, case-insensitively; duplicates collapse. Omit it
	 * to derive the single scheme from the error's type, which returns exactly
	 * what {@link wwwAuthenticate} would, in a one-element array.
	 */
	schemes?: readonly string[];
	/**
	 * JOSE `alg` values accepted for DPoP proofs, emitted as the RFC 9449 §7.1
	 * `algs` parameter on the `DPoP` challenge only, and ignored when `DPoP` is
	 * not among `schemes`. Pass `options.allowedProofAlgorithms` straight
	 * through: `undefined` there means "the default set", and means the same
	 * here, so an options object built from defaults advertises the algorithms
	 * it actually accepts rather than nothing. Omitting the property omits the
	 * parameter. Values are validated against the supported set, so an unusable
	 * one throws rather than reaching the wire.
	 */
	algs?: readonly string[] | undefined;
}

/**
 * Build one RFC 6750 §3 challenge per authentication scheme the resource
 * accepts.
 *
 * {@link wwwAuthenticate} picks the scheme from the error's type, so it can
 * only ever name one. A resource running inbound DPoP in optional mode accepts
 * both `Bearer` and `DPoP` and should advertise both, so that a DPoP-capable
 * client can discover that sender-constrained tokens are taken here
 * (RFC 9449 §7.1; §7.2 covers running the two schemes side by side).
 *
 * Two challenges cannot be joined with a comma: the comma is also the
 * separator *between parameters inside* a challenge, so the result cannot be
 * parsed unambiguously. RFC 7235 §4.1 permits the comma-joined form but warns
 * about parsing it, so separate `WWW-Authenticate` header values are the
 * interoperable choice: this returns an array and the caller emits one header
 * value per element.
 *
 * ```ts
 * for (const challenge of wwwAuthenticateChallenges(error, {
 *   schemes: ["Bearer", "DPoP"],
 *   algs: inboundDPoP.allowedProofAlgorithms,
 * })) {
 *   res.append("WWW-Authenticate", challenge);
 * }
 * ```
 *
 * The error selects the error code the same way {@link wwwAuthenticate} does,
 * per scheme: `invalid_dpop_proof` is DPoP-specific, so a `Bearer` challenge
 * emitted alongside a DPoP one keeps `invalid_token`.
 *
 * @throws TypeError If `schemes` is empty or names a scheme this SDK cannot
 * advertise, or if `algs` names an algorithm it cannot accept.
 */
export function wwwAuthenticateChallenges(
	error: AuthplaneError,
	options: ChallengesOptions = {},
): string[] {
	const schemes =
		options.schemes === undefined
			? [schemeFor(error)]
			: normaliseSchemes(options.schemes);
	const algs = resolveAlgs(options);
	const scope = resolveScope(error, options.scope);
	return schemes.map((scheme) =>
		buildChallenge(error, scheme, {
			realm: options.realm,
			resourceMetadataUrl: options.resourceMetadataUrl,
			scope,
			algs,
			verboseDescription: options.verboseDescription ?? false,
		}),
	);
}

/** The RFC 6750 §3 JSON error body an adapter serves alongside the challenge. */
export interface ErrorResponseBody {
	/** RFC 6750 §3.1 / RFC 9449 §7.1 error code — the same one the challenge names. */
	error: string;
	/** Fixed, caller-safe sentence chosen by {@link ErrorResponseBody.error}. */
	error_description: string;
}

/** Options for {@link errorResponseBody}. */
export interface ErrorBodyOptions {
	/**
	 * The scheme whose error code the body should name. Defaults to the single
	 * scheme that matches the error's own type — the same default
	 * {@link wwwAuthenticate} applies — so the body and the challenge agree
	 * without the caller restating it. Pass it explicitly only when emitting a
	 * multi-scheme challenge set, where the codes can differ per scheme and the
	 * one body has to pick one.
	 */
	scheme?: ChallengeScheme;
	/**
	 * Development-only. Restores the previous behaviour of copying the
	 * exception message into `error_description`. It discloses SDK-internal
	 * detail (the unknown `kid`, the claim that failed, the expected audience)
	 * to unauthenticated callers, so do not enable it in production. Defaults
	 * to `false`.
	 */
	verboseDescription?: boolean;
}

/**
 * Build the RFC 6750 §3 JSON error body for `error`.
 *
 * The body and the `WWW-Authenticate` challenge travel in the same response to
 * the same unauthenticated caller, so they are composed from the same two
 * decisions: {@link wwwAuthenticate}'s error code, and the fixed sentence that
 * code selects. The exception's own message never reaches the wire — it names
 * the failing detail (the unknown `kid`, the claim that did not validate, the
 * `aud` the resource expects, which is the value a caller would need in order
 * to request a token for it), and a client reads whichever half it finds, so
 * fixing only the challenge would leave the disclosure intact while making it
 * look closed. The message stays on the exception for the resource server to
 * log.
 *
 * Adapters should serve this rather than assembling `{ error, error_description }`
 * themselves: hand-rolled copies picked the code with a two-way
 * `InsufficientScope ? … : "invalid_token"` branch, which named `invalid_token`
 * in the body while the challenge above it said `invalid_dpop_proof`.
 */
export function errorResponseBody(
	error: AuthplaneError,
	options: ErrorBodyOptions = {},
): ErrorResponseBody {
	const errorCode = errorCodeFor(error, options.scheme ?? schemeFor(error));
	return {
		error: errorCode,
		// Raw, not sanitised: sanitiseHeaderValue exists for the quoted-string
		// rules of a header, and applying it here would mangle a verbose message
		// that JSON escaping already handles correctly.
		error_description: options.verboseDescription
			? error.message
			: safeDescriptionFor(errorCode),
	};
}

// ---------------------------------------------------------------------------
// Auth client / OAuth errors (AS interactions)
// ---------------------------------------------------------------------------
export {
	AccessDeniedError,
	AuthError,
	ConsentRequiredError,
	DPoPNonceRequiredError,
	InvalidClientError,
	InvalidGrantError,
	InvalidRequestError,
	InvalidScopeError,
	InvalidTargetError,
	mapOAuthError,
	ProtocolError,
	ServerError,
	UnauthorizedClientError,
	UnsupportedGrantTypeError,
} from "../auth/errors.js";

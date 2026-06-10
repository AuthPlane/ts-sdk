import { TokenMissing } from "./errors.js";

/**
 * Extract the bearer token from an `Authorization` header value.
 *
 * Accepts the canonical `Bearer <token>` form (RFC 6750 §2.1,
 * case-insensitive on the scheme) and the `DPoP <token>` form (RFC 9449
 * §7.1) so DPoP-bound tokens can arrive under either scheme name.
 *
 * Parsing is strict: exactly one ASCII space between scheme and token, no
 * trailing whitespace-separated fields. RFC 6750 §2.1 mandates that the
 * credentials field be exactly the `b64token`, so anything else is either a
 * client bug or a smuggling attempt.
 *
 * All three failure modes (absent header, unsupported scheme, malformed
 * token) raise the same `TokenMissing` — collapsing "no credentials" and
 * "bad credentials" into one type is intentional. The wire-level
 * distinction lives in `wwwAuthenticate()` / `httpStatus()`, not in the
 * exception class.
 *
 * @throws TokenMissing when the header is missing or empty.
 * @throws TokenMissing when the scheme is not `Bearer` / `DPoP`, the token
 *   part is empty, or the header carries extra fields.
 */
export function extractBearerToken(
	authorizationHeader: string | undefined,
): string {
	if (!authorizationHeader) {
		throw new TokenMissing("Missing Authorization header");
	}

	const match = /^(Bearer|DPoP) ([^\s]+)$/iu.exec(authorizationHeader);
	if (!match) {
		throw new TokenMissing(
			"Invalid Authorization header format, expected 'Bearer TOKEN' or 'DPoP TOKEN'",
		);
	}
	return match[2] as string;
}

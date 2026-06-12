import { ProtocolError } from "../errors.js";
import { TOKEN_TYPE_ACCESS_TOKEN, type TokenResponse } from "./types.js";

export function parseTokenResponse(
	data: Record<string, unknown>,
	options: { allowIssuedTokenType?: boolean; expectDpop?: boolean } = {},
): TokenResponse {
	const accessToken =
		typeof data.access_token === "string" ? data.access_token : "";
	const tokenType = typeof data.token_type === "string" ? data.token_type : "";
	const expiresInRaw = data.expires_in;
	const expiresIn =
		expiresInRaw === undefined
			? 0
			: (() => {
					if (typeof expiresInRaw !== "number") {
						throw new ProtocolError(
							"authplane: token response expires_in must be a non-negative integer when present",
						);
					}
					if (
						!Number.isFinite(expiresInRaw) ||
						!Number.isInteger(expiresInRaw)
					) {
						throw new ProtocolError(
							"authplane: token response expires_in must be a non-negative integer when present",
						);
					}
					if (expiresInRaw < 0) {
						throw new ProtocolError(
							"authplane: token response expires_in must be a non-negative integer when present",
						);
					}
					return expiresInRaw;
				})();
	const scope = typeof data.scope === "string" ? data.scope : "";
	const refreshToken =
		typeof data.refresh_token === "string" ? data.refresh_token : "";
	const issuedTokenType =
		typeof data.issued_token_type === "string" ? data.issued_token_type : "";

	if (!accessToken || !tokenType) {
		throw new ProtocolError(
			"authplane: token response missing required fields",
		);
	}
	if (tokenType !== "Bearer" && tokenType !== "DPoP") {
		throw new ProtocolError("authplane: token response unsupported token_type");
	}
	// RFC 9449 §5: when a DPoP proof was sent with the request, the response
	// token_type MUST be "DPoP". A "Bearer" response means the AS ignored the
	// proof and the token is NOT sender-constrained — accepting it would be a
	// confused deputy.
	if (options.expectDpop && tokenType.toLowerCase() !== "dpop") {
		throw new ProtocolError(
			`authplane: DPoP proof was sent but token_type is '${tokenType}', not 'DPoP'; the authorization server may have ignored the DPoP proof (RFC 9449 §5)`,
		);
	}
	if (options.allowIssuedTokenType) {
		// RFC 8693 §2.2.1: issued_token_type is REQUIRED in token-exchange
		// success responses. Missing or unsupported values indicate an
		// AS that is not complying with the token-exchange contract.
		if (!issuedTokenType) {
			throw new ProtocolError(
				"authplane: token exchange response missing required 'issued_token_type' (RFC 8693 §2.2.1)",
			);
		}
		if (issuedTokenType !== TOKEN_TYPE_ACCESS_TOKEN) {
			throw new ProtocolError(
				`authplane: unsupported issued_token_type '${issuedTokenType}'; only access_token is supported`,
			);
		}
	}

	return {
		accessToken,
		tokenType,
		expiresIn,
		scope,
		refreshToken,
		issuedTokenType,
		raw: Object.freeze({ ...data }),
	};
}

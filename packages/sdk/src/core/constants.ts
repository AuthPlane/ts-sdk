export const ALLOWED_ALGORITHMS = ["RS256", "ES256"] as const;

export const CLOCK_SKEW_SECONDS = 30;
export const JWKS_REFRESH_SECONDS = 300;
export const METADATA_REFRESH_SECONDS = 3600;
export const DEV_MODE = false;

export const JWKS_MAX_SIZE_BYTES = 65_536;
export const METADATA_MAX_SIZE_BYTES = 131_072;

export const FETCH_TIMEOUT_SECONDS = 10;
export const FETCH_SSRF_PROTECTION = true;
export const FETCH_ALLOW_HTTP = false;
export const FETCH_ALLOW_LOCALHOST = false;
export const FETCH_ALLOW_PRIVATE_NETWORKS = false;

export const DEV_FETCH_SSRF_PROTECTION = false;
export const DEV_FETCH_ALLOW_HTTP = true;
export const DEV_FETCH_ALLOW_LOCALHOST = true;
export const DEV_FETCH_ALLOW_PRIVATE_NETWORKS = true;

export const INTROSPECTION_MAX_SIZE_BYTES = 65_536;

export const ERROR_MESSAGES: {
	tokenMissing: string;
	tokenExpired: string;
	tokenRevoked: string;
	invalidSignature: string;
	invalidClaims: string;
	insufficientScope: string;
	jwksFetchError: string;
	metadataFetchError: string;
	verifierRuntimeError: string;
	protocolError: string;
	missingMetadataEndpoint: string;
	dpopError: string;
	dpopProofMissing: string;
	invalidDpopProof: string;
	dpopReplayDetected: string;
	dpopBindingMismatch: string;
	dpopNotSupported: string;
	multipleDpopProofs: string;
	authError: string;
	serverError: string;
	circuitOpenError: string;
	invalidGrant: string;
} = {
	tokenMissing: "No token provided for validation.",
	tokenExpired: "Token has expired.",
	tokenRevoked: "Token has been revoked.",
	invalidSignature: "Token signature verification failed.",
	invalidClaims: "Token claims validation failed.",
	insufficientScope: "Token missing required scope.",
	jwksFetchError: "Failed to fetch JWKS and no cache is available.",
	metadataFetchError: "Failed to fetch authorization server metadata.",
	verifierRuntimeError: "Verifier runtime failure.",
	protocolError: "OAuth/DPoP protocol message is malformed.",
	missingMetadataEndpoint:
		"Authorization server metadata missing required endpoint.",
	dpopError: "DPoP verification failed.",
	dpopProofMissing: "DPoP proof is required but missing.",
	invalidDpopProof: "Invalid DPoP proof.",
	dpopReplayDetected: "DPoP proof replay detected.",
	dpopBindingMismatch: "DPoP proof does not match token binding.",
	dpopNotSupported:
		"Resource is not configured for DPoP. Pass `inboundDPoP: { ... }` to client.resource(...) to enable DPoP validation.",
	multipleDpopProofs:
		"Request carries more than one DPoP proof; RFC 9449 §4.3 forbids it.",
	authError: "Authorization server interaction failed.",
	serverError: "Authorization server returned an error.",
	circuitOpenError: "Circuit breaker is open; request temporarily blocked.",
	invalidGrant:
		"Token exchange failed: subject or actor token is invalid, expired, or otherwise not accepted.",
};

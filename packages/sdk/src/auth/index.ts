/**
 * OAuth protocol primitives — bare implementations without caching or resilience.
 */

export {
	type DPoPAlgorithm,
	DPoPKeyMaterial,
	type DPoPNonceStore,
	DPoPProvider,
	InMemoryDPoPNonceStore,
	normalizeHtu,
	sha256Base64Url,
} from "./dpop.js";
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
} from "./errors.js";
export type { FetchSettingsInit } from "./fetchSettings.js";
export { FetchSettings } from "./fetchSettings.js";
export {
	type IntrospectionConfig,
	type IntrospectionResponse,
	IntrospectionRevocation,
	introspectToken,
} from "./introspection.js";
export { clientCredentialsGrant } from "./oauth/clientCredentials.js";
export { revokeToken } from "./oauth/revocation.js";
export { exchange } from "./oauth/tokenExchange.js";
export type {
	TokenExchangeOptions,
	TokenResponse,
} from "./oauth/types.js";
export {
	GRANT_TYPE_TOKEN_EXCHANGE,
	TOKEN_TYPE_ACCESS_TOKEN,
} from "./oauth/types.js";
export type { ASCredentials } from "./types.js";

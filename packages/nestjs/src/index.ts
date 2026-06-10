// Public barrel for @authplane/nestjs.
//
// Re-exports every symbol the user-guide documents. Internal helpers stay
// un-exported so the published surface area is exactly what the guide
// describes.

// --- Module + composition ------------------------------------------------
export { AuthplaneModule } from "./module/authplane.module.js";
export { AuthplaneShutdownHook } from "./module/authplane.shutdown-hook.js";
export {
	AUTHPLANE_CLIENT,
	AUTHPLANE_MODULE_OPTIONS,
	AUTHPLANE_REQUEST_ADAPTER,
	AUTHPLANE_RESOURCE,
	AUTHPLANE_TOKEN_VERIFIER,
} from "./module/authplane.tokens.js";
export type {
	AuthplaneAsyncRegistrationHints,
	AuthplaneModuleAsyncOptions,
	AuthplaneModuleOptions,
	AuthplaneOptionsFactory,
} from "./module/authplane.options.js";

// --- Guard, filter, decorators -------------------------------------------
export { AuthplaneAuthGuard } from "./application/authplane.guard.js";
export { AuthplaneExceptionFilter } from "./application/authplane.exception-filter.js";
export {
	AuthInfo,
	RequireScopes,
	SkipAuth,
} from "./application/decorators.js";
export {
	METADATA_KEY_REQUIRED_SCOPES,
	METADATA_KEY_SKIP_AUTH,
} from "./application/metadata-keys.js";

// --- Infrastructure escape hatches ---------------------------------------
export {
	AUTH_INFO_REQUEST_KEY,
	defaultRequestAdapter,
	type RequestAdapter,
	REQUIRED_SCOPES_REQUEST_KEY,
} from "./infrastructure/request-adapter.js";

// --- Re-exports of core types referenced in AuthplaneModuleOptions -------
// Surfaced here so the user-guide options table doesn't force readers to
// chase imports across `@authplane/sdk/core`. Matches the `@authplane/mcp` /
// `@authplane/fastmcp` re-export pattern.
export {
	type ASCredentials,
	AuthplaneError,
	type AuthProvider,
	DPoPProvider,
	InsufficientScope,
	TokenExpired,
	TokenMissing,
	VerifiedClaims,
} from "@authplane/sdk/core";

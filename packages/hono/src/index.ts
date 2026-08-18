export {
	type AuthplaneHonoAuth,
	type AuthplaneHonoAuthOptions,
	authplaneHonoAuth,
} from "./authplaneHonoAuth.js";
export {
	type AuthplaneOnErrorOptions,
	authplaneOnError,
} from "./authplaneOnError.js";
export { type BearerAuthOptions, bearerAuth } from "./bearerAuth.js";
export { protectedResourceMetadataHandler } from "./prmHandler.js";
export { requireScope } from "./requireScope.js";
export {
	type HonoAuthVariables,
	type HonoAuthVariables as Variables,
	REQUIRED_SCOPE_CONTEXT_KEY,
} from "./types.js";

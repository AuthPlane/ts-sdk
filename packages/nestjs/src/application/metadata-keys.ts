/**
 * Reflector metadata keys for the `@authplane/nestjs` decorator family.
 *
 * Kept in one place so the guard and the decorators never drift apart: the
 * guard reads exactly the keys the decorators write.
 */

/** Key under which `@RequireScopes(...)` stores the required-scopes array. */
export const METADATA_KEY_REQUIRED_SCOPES = "authplane:requiredScopes";

/** Key under which `@SkipAuth()` marks a handler / controller as public. */
export const METADATA_KEY_SKIP_AUTH = "authplane:skipAuth";

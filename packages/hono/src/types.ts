import type { VerifiedClaims } from "@authplane/sdk/core";

/**
 * Shape expected in Hono's `Variables` generic so that `c.get("auth")` returns
 * a {@link VerifiedClaims} instead of `unknown`.
 *
 * Use it when constructing the app:
 *
 * ```ts
 * import type { HonoAuthVariables } from "@authplane/hono";
 * const app = new Hono<{ Variables: HonoAuthVariables }>();
 * ```
 *
 * The adapter also re-exports this under the short name `Variables` for
 * callers who prefer the inline form `new Hono<{ Variables: Variables }>()`.
 *
 * `authplaneRequiredScope` is internal plumbing: `requireScope(c, scope)`
 * stashes the offending scope here before throwing core `InsufficientScope`,
 * and an `onError` handler can read it via
 * {@link REQUIRED_SCOPE_CONTEXT_KEY} to populate the `scope="…"` parameter
 * on the `WWW-Authenticate` challenge without parsing the error message.
 */
export type HonoAuthVariables = {
	auth: VerifiedClaims;
	authplaneRequiredScope?: string;
};

/**
 * Key under which `requireScope(c, scope)` stashes the required scope on the
 * Hono context before throwing `InsufficientScope`. An `onError` bridge can
 * read it via `c.get(REQUIRED_SCOPE_CONTEXT_KEY)` to surface it in the
 * `WWW-Authenticate` challenge.
 */
export const REQUIRED_SCOPE_CONTEXT_KEY = "authplaneRequiredScope" as const;

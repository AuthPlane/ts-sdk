import { InsufficientScope, type VerifiedClaims } from "@authplane/sdk/core";
import type { Context } from "hono";

import { type HonoAuthVariables, REQUIRED_SCOPE_CONTEXT_KEY } from "./types.js";

/**
 * Assert the current request's verified token carries `scope`; throw core
 * {@link InsufficientScope} otherwise.
 *
 * Call this at the top of a route handler to enforce scope requirements that
 * are finer-grained than what `bearerAuth` can enforce globally — for example,
 * guarding a single tool within a larger MCP server:
 *
 * ```ts
 * import { requireScope } from "@authplane/hono";
 *
 * app.post("/mcp/tools/add", (c) => {
 *   requireScope(c, "tools/add");
 *   // … tool body …
 * });
 * ```
 *
 * Apps using this helper should pair it with a Hono `onError` handler that
 * funnels `AuthplaneError` through core's `httpStatus()` + `wwwAuthenticate()`.
 * The factory returned by `authplaneHonoAuth` does NOT install a global error
 * handler, to keep application-level error-handling choices with the app
 * owner.
 *
 * If `bearerAuth` never ran for this request (so `c.get("auth")` returns
 * undefined) the helper raises {@link InsufficientScope} as well — that way a
 * forgotten `app.use(bearerAuth)` fails closed instead of open.
 */
export function requireScope(
	c: Context<{ Variables: HonoAuthVariables }>,
	scope: string,
): void {
	// `HonoAuthVariables.auth` is typed non-optional because the documented
	// contract is "call this AFTER bearerAuth has populated the context." The
	// runtime cast widens it back to `| undefined` so a forgotten
	// `app.use(bearerAuth)` fails closed with InsufficientScope instead of a
	// TypeError dereferencing `.scopes` on undefined.
	const auth = c.var.auth as VerifiedClaims | undefined;
	if (auth?.hasScope(scope)) return;
	// Stash the offending scope so an `onError` bridge can surface it in the
	// WWW-Authenticate challenge without having to parse the error message.
	c.set(REQUIRED_SCOPE_CONTEXT_KEY, scope);
	if (!auth) {
		// Fail-closed for a forgotten `app.use(bearerAuth)`: no claims to
		// delegate to, so synthesise the error directly.
		throw new InsufficientScope(`Missing required scope: ${scope}`);
	}
	// Auth present but lacks the scope: delegate to the core helper so the
	// `InsufficientScope` message carries the missing scope and the scopes
	// the token does have — same wording every other adapter emits.
	auth.requireScope(scope);
}

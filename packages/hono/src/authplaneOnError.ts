import { AuthplaneError } from "@authplane/sdk/core";
import type { ErrorHandler } from "hono";
import { HTTPException } from "hono/http-exception";

import {
	type AuthplaneChallengeOptions,
	writeAuthplaneErrorResponse,
	writeServerErrorResponse,
} from "./errorResponse.js";
import type { HonoAuthVariables } from "./types.js";

/**
 * Options for {@link authplaneOnError}. Every field is optional — the handler
 * works with zero configuration and only enriches the challenge when told how.
 */
export interface AuthplaneOnErrorOptions extends AuthplaneChallengeOptions {
	/**
	 * What to do with a non-`AuthplaneError` that reaches the handler.
	 *
	 * - `"server_error"` (default): emit an RFC 6749 `server_error` 500 with a
	 *   fixed `"Internal Server Error"` description and `console.error` the
	 *   original error server-side. Because `app.onError(handler)` REPLACES
	 *   Hono's built-in error handler, this default keeps a copy-pasted
	 *   `app.onError(authplaneOnError())` safe: a route `TypeError` / DB failure
	 *   surfaces as a clean 500 instead of an unhandled rejection, the stack is
	 *   still logged, and the raw error message is never echoed to the caller.
	 * - `"rethrow"`: re-throw the error unchanged so an outer/app-level error
	 *   handler can take it. Only choose this when another handler sits behind
	 *   `authplaneOnError()` — otherwise the re-thrown error escapes uncaught.
	 *
	 * A Hono `HTTPException` (and any `HTTPResponseError`) is never subject to
	 * this fallback: it carries its own status, body, and headers, so the
	 * handler returns `error.getResponse()` unchanged — mirroring the Hono
	 * built-in handler this replaces.
	 */
	readonly fallback?: "server_error" | "rethrow";
	/**
	 * Sink for the original error when the `"server_error"` fallback fires.
	 * Defaults to `console.error`. Override to route the error into a structured
	 * logger instead of stdout/stderr — the client still receives the same fixed
	 * `server_error` 500, only the server-side log destination changes.
	 */
	readonly onServerError?: (error: unknown) => void;
}

/**
 * Build a Hono `onError` handler that funnels every {@link AuthplaneError}
 * through core's `httpStatus()` + `wwwAuthenticate()`, emitting the RFC 6750 §3
 * response (including the `insufficient_scope` challenge with the per-route
 * scope stashed by `requireScope()`).
 *
 * This is the recommended one-liner for application-level auth error handling:
 *
 * ```ts
 * import { authplaneOnError } from "@authplane/hono";
 *
 * app.onError(authplaneOnError());
 * ```
 *
 * As written this is safe on its own: a non-`AuthplaneError` falls through to
 * the default `fallback: "server_error"`, which emits the same clean 500 as the
 * middleware — so replacing Hono's built-in error handler does not leave route
 * `TypeError`s / DB failures unhandled. Pass `fallback: "rethrow"` to restore
 * the re-throw behaviour when you deliberately chain an outer handler behind
 * this one.
 *
 * A Hono `HTTPException` is exempt from the fallback: since this handler
 * replaces the built-in one, it reproduces the built-in's first step and returns
 * `error.getResponse()`, so an `HTTPException(404)` — or a 401 challenge from
 * Hono's own `basicAuth`/`bearerAuth`/`jwt`/`bodyLimit`/`timeout` middleware —
 * keeps its status and headers instead of degrading to a 500.
 *
 * The handler is generic over the Hono `Env` so it also typechecks on a
 * `Bindings`-typed app (the standard Cloudflare Workers shape,
 * `new Hono<{ Bindings: Env; Variables: HonoAuthVariables }>()`); the only
 * constraint is that `Variables` carries {@link HonoAuthVariables}.
 */
export function authplaneOnError<E extends { Variables: HonoAuthVariables }>(
	options: AuthplaneOnErrorOptions = {},
): ErrorHandler<E> {
	const {
		fallback = "server_error",
		onServerError = console.error,
		...challengeOptions
	} = options;
	return (error, c) => {
		if (error instanceof AuthplaneError) {
			return writeAuthplaneErrorResponse(c, error, challengeOptions);
		}
		// `app.onError(handler)` REPLACES Hono's built-in handler, which returns
		// `err.getResponse()` for an `HTTPException`/`HTTPResponseError` before
		// anything else. Preserve that: a route's `throw new HTTPException(404)` —
		// and Hono's own `basicAuth`/`bearerAuth`/`jwt`/`bodyLimit`/`timeout`
		// middleware that throw `HTTPException` — must keep their status, body, and
		// headers (e.g. a `basic-auth` 401 `WWW-Authenticate` challenge) instead of
		// collapsing to a generic `server_error` 500.
		if (error instanceof HTTPException) {
			return error.getResponse();
		}
		if (fallback === "rethrow") {
			throw error;
		}
		// This is an arbitrary application error (ECONNREFUSED, an ORM error
		// naming a column, a signed URL, …). Because `app.onError(handler)`
		// REPLACED Hono's built-in handler, nothing else will log it — so keep
		// the stack server-side here, and ship the client a FIXED description so
		// the raw message never leaks to an unauthenticated caller.
		onServerError(error);
		return writeServerErrorResponse(c, "Internal Server Error");
	};
}

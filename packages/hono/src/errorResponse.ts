import {
	type AuthplaneError,
	httpStatus,
	InsufficientScope,
	wwwAuthenticate,
} from "@authplane/sdk/core";
import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";

import { type HonoAuthVariables, REQUIRED_SCOPE_CONTEXT_KEY } from "./types.js";

/**
 * Knobs that tune the RFC 6750 §3 challenge emitted for an
 * {@link AuthplaneError}. Every field is optional so both the `bearerAuth`
 * catch and the standalone {@link authplaneOnError} handler can share the same
 * mapping while supplying only what they know.
 */
export interface AuthplaneChallengeOptions {
	/** Protection realm (RFC 6750 §3) emitted as `realm="…"`. */
	readonly realm?: string | undefined;
	/** RFC 9728 PRM document URL emitted as `resource_metadata="…"`. */
	readonly resourceMetadataUrl?: string | undefined;
	/**
	 * Middleware-level required scopes. Used as the `scope="…"` fallback for an
	 * {@link InsufficientScope} only when `requireScope()` did not stash a
	 * per-route scope on the context.
	 */
	readonly requiredScopes?: readonly string[] | undefined;
}

/**
 * Map an {@link AuthplaneError} to its RFC 6750 §3 response — status code from
 * core `httpStatus()` and a `WWW-Authenticate` challenge from core
 * `wwwAuthenticate()`. Shared by the `bearerAuth` middleware catch and the
 * {@link authplaneOnError} handler so the two paths emit byte-identical
 * responses.
 *
 * For an {@link InsufficientScope} the `scope="…"` parameter carries the
 * PER-ROUTE scope stashed by `requireScope()` when present, so the challenge
 * tells the client exactly which scope the failing route needs — not the
 * middleware-level required-scope union.
 */
export function writeAuthplaneErrorResponse<
	E extends { Variables: HonoAuthVariables },
>(
	c: Context<E>,
	error: AuthplaneError,
	options: AuthplaneChallengeOptions = {},
): Response {
	const wwwOptions: Parameters<typeof wwwAuthenticate>[1] = {};
	if (options.realm) wwwOptions.realm = options.realm;
	if (options.resourceMetadataUrl) {
		wwwOptions.resourceMetadataUrl = options.resourceMetadataUrl;
	}
	const scope = resolveChallengeScope(c, error, options.requiredScopes);
	if (scope.length > 0) {
		wwwOptions.scope = scope;
	}

	const errorCode =
		error instanceof InsufficientScope ? "insufficient_scope" : "invalid_token";
	// Build the whole Response in one `c.json` call — the `WWW-Authenticate`
	// header rides its headers argument rather than a separate `c.header()`
	// mutation, so the challenge and the body are set at a single construction
	// site. (This is not a side-effect-free write: `c.json` still reads and
	// merges `c.res` and any headers already prepared on the context. The value
	// is that both the returned-response paths and the `c.res = …` assignment
	// path go through the same builder instead of a mutate-then-return sequence.)
	return c.json(
		{ error: errorCode, error_description: error.message },
		httpStatus(error) as ContentfulStatusCode,
		{ "WWW-Authenticate": wwwAuthenticate(error, wwwOptions) },
	);
}

/**
 * Emit the RFC 6749 `server_error` 500 used for an internal fault. Shared by the
 * `bearerAuth` verification-path catch and the default `authplaneOnError`
 * fallback so an unexpected error surfaces as the SAME clean JSON 500 on both
 * paths instead of an unhandled rejection. The `error_description` is supplied
 * explicitly by the caller and never derived from the error here — callers that
 * face untrusted application errors (the `authplaneOnError` fallback) pass a
 * fixed `"Internal Server Error"` so a raw error message is never echoed to the
 * client, while the middleware's own verification-fault path may pass its
 * message.
 */
export function writeServerErrorResponse<
	E extends { Variables: HonoAuthVariables },
>(c: Context<E>, description: string): Response {
	return c.json(
		{
			error: "server_error",
			error_description: description,
		},
		500,
	);
}

/**
 * Pick the scope list for the challenge. An {@link InsufficientScope} raised by
 * `requireScope()` stashes the exact offending scope on the context — prefer
 * it so the challenge is per-route accurate. Fall back to the middleware-level
 * required-scope union for scope failures that did not go through
 * `requireScope()` (e.g. the `bearerAuth` global scope gate).
 */
function resolveChallengeScope<E extends { Variables: HonoAuthVariables }>(
	c: Context<E>,
	error: AuthplaneError,
	requiredScopes: readonly string[] | undefined,
): readonly string[] {
	if (error instanceof InsufficientScope) {
		const perRouteScope = c.get(REQUIRED_SCOPE_CONTEXT_KEY);
		if (perRouteScope) return [perRouteScope];
	}
	return requiredScopes ?? [];
}

import {
	AuthplaneError,
	type AuthplaneResource,
	buildDPoPRequestContext,
	type DPoPRequestContext,
	extractBearerToken,
	extractDpopHeaderValues,
	buildRequestUrl,
	httpStatus,
	InsufficientScope,
	pathAndQueryOf,
	wwwAuthenticate,
} from "@authplane/sdk/core";
import type { Context, MiddlewareHandler } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";

import type { HonoAuthVariables } from "./types.js";

/**
 * Input options for {@link bearerAuth}.
 */
export interface BearerAuthOptions {
	/**
	 * Core resource verifier responsible for cryptographic validation of the
	 * access token. The middleware calls `verifier.verify()` directly and
	 * stores the resulting {@link VerifiedClaims} on the Hono context.
	 */
	readonly verifier: AuthplaneResource;
	/**
	 * Scopes that must ALL be present on the verified token for the request
	 * to continue. When empty or omitted, scope enforcement is skipped.
	 */
	readonly requiredScopes?: readonly string[];
	/**
	 * Protection realm (RFC 6750 §3). When provided, emitted as `realm="…"`
	 * in every `WWW-Authenticate` challenge. Typically the resource URL.
	 */
	readonly realm?: string;
	/**
	 * Absolute URL to the Protected Resource Metadata document (RFC 9728).
	 * When provided, emitted as `resource_metadata="…"` on every
	 * `WWW-Authenticate` challenge so clients can discover the authorization
	 * server.
	 */
	readonly resourceMetadataUrl?: string;
	/**
	 * Origin (scheme + authority) of the configured resource. Used as the
	 * trusted source of truth for the DPoP `htu` URL — must be
	 * `new URL(options.resource).origin`. The middleware never reads
	 * `X-Forwarded-*` or `Host` to compute `htu`: those are attacker-controlled
	 * inputs in many deployments and letting them steer `htu` would neuter
	 * RFC 9449 cross-endpoint anti-replay.
	 */
	readonly resourceOrigin: string;
}

/**
 * Build a Hono middleware that enforces Authplane-issued Bearer tokens on the
 * requests it guards.
 *
 * Contract:
 *
 * 1. Extract the Bearer token from the `Authorization` header (RFC 6750 §2.1,
 *    case-insensitive scheme; RFC 9449 §7.1 `DPoP` scheme also accepted).
 * 2. Delegate cryptographic verification to {@link AuthplaneResource.verify}.
 *    Expiry (with the resource's configured `clockSkewSeconds` tolerance) and
 *    every other claim check are enforced by core.
 * 3. Enforce `requiredScopes` (if any) via `claims.requireScopes()` — the
 *    AND-style multi-scope helper on core `VerifiedClaims`.
 * 4. On success, stash the verified claims on the Hono context under `auth`
 *    so downstream handlers can read them via `c.get("auth")`.
 *
 * On failure the middleware short-circuits with an RFC 6750 §3 response.
 * Every {@link AuthplaneError} is funneled through core's `httpStatus()` +
 * `wwwAuthenticate()`, matching `@authplane/mcp` / `@authplane/fastmcp`.
 */
export function bearerAuth(
	options: BearerAuthOptions,
): MiddlewareHandler<{ Variables: HonoAuthVariables }> {
	const {
		verifier,
		requiredScopes = [],
		realm,
		resourceMetadataUrl,
		resourceOrigin,
	} = options;

	return async (c, next) => {
		try {
			const token = extractBearerToken(c.req.header("authorization"));
			const dpopRequest = buildDpopRequestContext(c, resourceOrigin);
			const claims = await verifier.verify(token, { dpopRequest });

			claims.requireScopes(requiredScopes);

			c.set("auth", claims);
			await next();
			return;
		} catch (error) {
			return respondWithError(c, error, {
				requiredScopes,
				realm,
				resourceMetadataUrl,
			});
		}
	};
}

function buildDpopRequestContext(
	c: Context<{ Variables: HonoAuthVariables }>,
	resourceOrigin: string,
): DPoPRequestContext | undefined {
	// Hono's Fetch-style `Headers.get` joins duplicate same-name headers
	// into a single comma-separated value; `extractDpopHeaderValues`
	// hands that string to the core factory, which re-splits on `,` so
	// RFC 9449 §4.3 #1 (no more than one DPoP header) surfaces as
	// `MultipleDPoPProofs`. JWS compact-serialised proofs never contain
	// a literal `,`, so split-on-comma is sound.
	const dpopHeaderValues = extractDpopHeaderValues(c.req.header("dpop"));
	if (dpopHeaderValues.length === 0) return undefined;

	const url = buildRequestUrl({
		pathAndQuery: pathAndQueryOf(c.req.url),
		resourceOrigin,
	});

	return buildDPoPRequestContext({
		method: c.req.method,
		url,
		dpopHeaderValues,
	});
}

interface ErrorResponseContext {
	readonly requiredScopes: readonly string[];
	readonly realm?: string | undefined;
	readonly resourceMetadataUrl?: string | undefined;
}

function respondWithError(
	c: Context<{ Variables: HonoAuthVariables }>,
	error: unknown,
	ctx: ErrorResponseContext,
): Response {
	if (error instanceof AuthplaneError) {
		const wwwOptions: Parameters<typeof wwwAuthenticate>[1] = {};
		if (ctx.realm) wwwOptions.realm = ctx.realm;
		if (ctx.resourceMetadataUrl) {
			wwwOptions.resourceMetadataUrl = ctx.resourceMetadataUrl;
		}
		if (ctx.requiredScopes.length > 0) {
			wwwOptions.scope = ctx.requiredScopes;
		}
		c.header("WWW-Authenticate", wwwAuthenticate(error, wwwOptions));

		const errorCode =
			error instanceof InsufficientScope
				? "insufficient_scope"
				: "invalid_token";
		return c.json(
			{ error: errorCode, error_description: error.message },
			httpStatus(error) as ContentfulStatusCode,
		);
	}

	return c.json(
		{
			error: "server_error",
			error_description:
				error instanceof Error ? error.message : "Internal Server Error",
		},
		500,
	);
}

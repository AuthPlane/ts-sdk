import {
	AuthplaneError,
	type AuthplaneResource,
	buildDPoPRequestContext,
	buildRequestUrl,
	type DPoPRequestContext,
	extractBearerToken,
	extractDpopHeaderValues,
	pathAndQueryOf,
	type VerifiedClaims,
} from "@authplane/sdk/core";
import type { Context, MiddlewareHandler } from "hono";

import {
	writeAuthplaneErrorResponse,
	writeServerErrorResponse,
} from "./errorResponse.js";
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
	/**
	 * Whether the middleware may write its own RFC 6750 §3 challenge for an
	 * {@link AuthplaneError} thrown by a downstream (guarded-route) handler.
	 * Default `true` — the adapter guarantees the challenge with zero app
	 * wiring. Set `false` to opt out: an app that installs its own `onError`
	 * (or otherwise shapes the response) then keeps full control of a
	 * downstream `AuthplaneError` response, even when that response carries no
	 * `WWW-Authenticate` header. The pre-`next()` verification path (token
	 * extraction, `verify()`, the global scope gate) is unaffected — those
	 * failures always emit the challenge.
	 */
	readonly emitDownstreamChallenge?: boolean;
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
 *
 * The downstream handler is guarded too, so the adapter guarantees the
 * `insufficient_scope` challenge with ZERO application wiring — no `app.onError`
 * bridge required. An `AuthplaneError` thrown by a guarded route (most commonly
 * `requireScope()` raising `InsufficientScope`) is turned into the same
 * challenge response here. For an `InsufficientScope` the challenge's
 * `scope="…"` carries the PER-ROUTE scope stashed by `requireScope()`, not the
 * middleware-level required-scope union. Non-`AuthplaneError` failures are left
 * untouched so genuine application errors keep flowing to the app's own error
 * handling instead of being masked as an auth response.
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
		emitDownstreamChallenge = true,
	} = options;
	const challengeOptions = { requiredScopes, realm, resourceMetadataUrl };

	return async (c, next) => {
		let claims: VerifiedClaims;
		try {
			const token = extractBearerToken(c.req.header("authorization"));
			const dpopRequest = buildDpopRequestContext(c, resourceOrigin);
			claims = await verifier.verify(token, { dpopRequest });
			claims.requireScopes(requiredScopes);
		} catch (error) {
			return respondToVerificationError(c, error, challengeOptions);
		}

		c.set("auth", claims);

		try {
			await next();
		} catch (error) {
			// Hono normally routes a downstream throw to the app-level error
			// handler and resolves `next()` (see the `c.error` handling below);
			// `next()` only rejects here when that error handler itself throws
			// — e.g. an app `onError` re-throwing the error it was handed. Emit
			// the challenge for an `AuthplaneError` (unless the app opted out via
			// `emitDownstreamChallenge: false`, which keeps full control of the
			// downstream response); re-throw anything else untouched.
			if (emitDownstreamChallenge && error instanceof AuthplaneError) {
				return writeAuthplaneErrorResponse(c, error, challengeOptions);
			}
			throw error;
		}

		// A downstream throw is caught by Hono's `compose()` and dispatched to the
		// app-level error handler, which resolves `next()` and leaves the offending
		// error on `c.error`. Guarantee the RFC 6750 §3 challenge for a scope (or
		// other auth) failure raised inside the guarded route — but only when the
		// current response has no challenge yet, so an app `onError` (e.g.
		// `authplaneOnError()`) that already produced one is not double-handled.
		//
		// TRIPWIRE: this branch relies on Hono leaving the downstream error on
		// `c.error` (rather than rejecting `next()`) after its default/app error
		// handler runs. If a future Hono minor changes that dispatch, the
		// "downstream requireScope challenge (zero app wiring)" tests in
		// tests/bearerAuth.test.ts fail — start debugging a broken zero-config
		// guarantee there.
		//
		// `emitDownstreamChallenge: false` opts out entirely, leaving whatever
		// response the app produced for the downstream `AuthplaneError` intact.
		const downstreamError = c.error;
		if (
			emitDownstreamChallenge &&
			downstreamError instanceof AuthplaneError &&
			!c.res.headers.has("WWW-Authenticate")
		) {
			c.res = writeAuthplaneErrorResponse(c, downstreamError, challengeOptions);
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

/**
 * Map an error raised on the verification path (token extraction, DPoP context
 * building, `verifier.verify()`, or the global scope gate) to a response. An
 * {@link AuthplaneError} funnels through the shared challenge helper; anything
 * else is an internal fault surfaced as a generic 500.
 *
 * Not every non-`AuthplaneError` here is the adapter's own: `verifier.verify()`
 * drives app-supplied collaborators (`revocationChecker`, the inbound DPoP
 * `replayStore`), so a raw failure like a Redis `ECONNREFUSED` can reach this
 * point carrying an infrastructure detail. So the message is never echoed to
 * the (unauthenticated) caller — the client gets a FIXED description and the
 * original error is logged server-side, mirroring the `authplaneOnError`
 * fallback.
 */
function respondToVerificationError(
	c: Context<{ Variables: HonoAuthVariables }>,
	error: unknown,
	ctx: ErrorResponseContext,
): Response {
	if (error instanceof AuthplaneError) {
		return writeAuthplaneErrorResponse(c, error, ctx);
	}

	// Keep the stack server-side and ship a fixed description so an
	// infrastructure message (e.g. a `revocationChecker` / `replayStore` Redis
	// `ECONNREFUSED` naming an internal host) never leaks to the caller.
	console.error(error);
	return writeServerErrorResponse(c, "Internal Server Error");
}

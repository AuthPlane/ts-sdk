import {
	AuthplaneClient,
	AuthplaneError,
	type AuthplaneResource,
	type AuthplaneResourceOptions,
	buildDPoPRequestContext,
	type DPoPProvider,
	extractBearerToken,
	errorResponseBody,
	extractDpopHeaderValues,
	type FetchSettings,
	InsufficientScope,
	type ProtectedResourceMetadata,
	httpStatus,
	wwwAuthenticate,
} from "@authplane/sdk/core";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { RequestHandler } from "express";
import { toUrlElicitationRequiredError } from "./urlElicitation.js";
import { AuthplaneTokenVerifier } from "./verifier.js";

/**
 * Throw if the current request token is missing a required scope.
 *
 * Call at the top of a tool handler to enforce per-tool scope requirements:
 *
 * ```ts
 * server.tool("add", async (params, extra) => {
 *   requireScope("tools/add", extra.authInfo);
 *   return { content: [{ type: "text", text: String(params.a + params.b) }] };
 * });
 * ```
 *
 * Raises core {@link InsufficientScope}, carrying the missing scope, so a host
 * that maps `AuthplaneError` before dispatch — `authplaneOnError` in the Hono
 * adapter, the NestJS exception filter — answers with `403` and
 * `WWW-Authenticate: Bearer error="insufficient_scope", scope="<this scope>"`,
 * which is the challenge a client steps up from. A plain `Error` reached none
 * of those mappings and surfaced as a JSON-RPC internal error or a generic
 * 500. `bearerAuth` is not one of those hosts for this throw — see below.
 *
 * **Where this runs matters.** Called inside a tool handler on the
 * streamable-HTTP transport, the response has already begun and its status
 * code is committed, so the failure can only come back as a JSON-RPC error on
 * an HTTP 200 — no 403, no challenge, no step-up. Enforcement that must
 * trigger step-up belongs pre-dispatch, at `bearerAuth`'s `requiredScopes`
 * (or your own middleware) where the status line has not been written yet.
 * In-handler, treat this as a defence-in-depth backstop: it fails the call
 * closed and names the scope in the error, but it cannot produce the 403.
 */
export function requireScope(
	scope: string,
	authInfo: AuthInfo | undefined,
): void {
	if (!authInfo?.scopes?.includes(scope)) {
		throw new InsufficientScope(`Missing required scope: ${scope}`, [scope]);
	}
}

export interface AuthplaneMcpAuthOptions
	extends Omit<AuthplaneResourceOptions, "scopes" | "resource"> {
	issuer: string;
	resource: string;
	scopes?: string[];
	requiredScopes?: string[];
	/**
	 * Outbound fetch hardening applied to both AS metadata and JWKS fetches.
	 * Defaults are derived from `devMode`.
	 */
	fetchSettings?: FetchSettings;
	jwksRefreshSeconds?: number;
	metadataRefreshSeconds?: number;
	/**
	 * Outbound DPoP provider for AS-facing calls (introspection, token
	 * exchange, revocation). When set, requests to the AS are accompanied by
	 * a DPoP proof and `cnf.jkt`-bound tokens are minted.
	 */
	dpopProvider?: DPoPProvider;
	/**
	 * Buffer subtracted from token TTLs before the outbound token cache
	 * considers an entry expired (seconds). Default `30`.
	 */
	cacheTtlBufferSeconds?: number;
	/**
	 * Fallback outbound-token cache TTL used when the AS response does not
	 * include expiry metadata (seconds). Default `3600`.
	 */
	defaultTtlSeconds?: number;
	/**
	 * Maximum number of entries kept in the outbound token cache before
	 * least-recently-used eviction kicks in. Default `10_000`. Override on
	 * hosts with very high subject-token cardinality — token-exchange cache
	 * keys include the subject token, so this is the bound that actually
	 * limits memory growth.
	 */
	cacheMaxEntries?: number;
	/**
	 * Number of consecutive transient AS failures before the circuit breaker
	 * opens. Default `5`.
	 */
	circuitBreakerThreshold?: number;
	/**
	 * Cooldown before the open circuit breaker allows a half-open probe
	 * request (seconds). Default `30`.
	 */
	circuitBreakerCooldownSeconds?: number;
}

export interface AuthplaneMcpAuth {
	client: AuthplaneClient;
	verifier: AuthplaneResource;
	tokenVerifier: AuthplaneTokenVerifier;
	bearerAuth: RequestHandler;
	protectedResourceMetadataPath: string;
	/**
	 * URL advertised as `resource_metadata` on every challenge this adapter
	 * emits. Pass it to the MCP SDK's own `requireBearerAuth({ verifier,
	 * requiredScopes, resourceMetadataUrl })` when wiring that middleware
	 * instead of `bearerAuth`, so both paths advertise the same document.
	 */
	protectedResourceMetadataUrl: string;
	protectedResourceMetadata: ProtectedResourceMetadata;
	protectedResourceMetadataHandler: RequestHandler;
}

/**
 * Build the wiring needed to enable Authplane auth on an MCP server.
 *
 * Wires up the resource verifier, bearer middleware, and PRM handler:
 *
 * - Creates an `AuthplaneResource` configured with issuer, resource, and scopes
 * - Performs RFC 8414 metadata discovery and JWKS fetching
 * - Exposes `tokenVerifier` (an `OAuthTokenVerifier` implementation) for users
 *   who want to wire MCP's `requireBearerAuth` themselves
 * - Ships an Express `bearerAuth` handler that re-implements the SDK's
 *   bearer-auth middleware (Authorization parsing, DPoP-header extraction,
 *   scope checks, `WWW-Authenticate`, 401/403/500) so it can thread
 *   per-request DPoP context into `verifier.verify()` — `requireBearerAuth`
 *   in the upstream SDK has no hook for that.
 * - Serves RFC 9728 Protected Resource Metadata (PRM) at the URL derived from `resource`
 *
 * The `scopes` list represents all scopes this MCP server supports. When
 * `requiredScopes` is not provided explicitly, it defaults to the same list
 * so that the bearer-auth handler treats the supported scopes as required
 * scopes, matching the official MCP SDK behaviour.
 */
export async function authplaneMcpAuth(
	options: AuthplaneMcpAuthOptions,
): Promise<AuthplaneMcpAuth> {
	const { requiredScopes, scopes, issuer, resource, ...verifierOptions } =
		options;
	const resolvedScopes = scopes ?? [];
	const resolvedRequiredScopes = requiredScopes ?? resolvedScopes;

	const client = await AuthplaneClient.create({
		issuer,
		auth: options.asCredentials,
		// Forward devMode / fetch settings so local demos can use `http://...`.
		devMode: verifierOptions.devMode,
		fetchSettings: options.fetchSettings,
		jwksRefreshSeconds: verifierOptions.jwksRefreshSeconds,
		metadataRefreshSeconds: verifierOptions.metadataRefreshSeconds,
		cacheTtlBufferSeconds: options.cacheTtlBufferSeconds,
		defaultTtlSeconds: options.defaultTtlSeconds,
		cacheMaxEntries: options.cacheMaxEntries,
		circuitBreakerThreshold: options.circuitBreakerThreshold,
		circuitBreakerCooldownSeconds: options.circuitBreakerCooldownSeconds,
		dpopProvider: options.dpopProvider,
	});

	const resourceOptions: AuthplaneResourceOptions = {
		resource,
		scopes: resolvedScopes,
	};
	if (options.revocationChecker !== undefined) {
		resourceOptions.revocationChecker = options.revocationChecker;
	}
	if (options.allowedAlgorithms !== undefined) {
		resourceOptions.allowedAlgorithms = options.allowedAlgorithms;
	}
	if (options.clockSkewSeconds !== undefined) {
		resourceOptions.clockSkewSeconds = options.clockSkewSeconds;
	}
	if (options.inboundDPoP !== undefined) {
		resourceOptions.inboundDPoP = options.inboundDPoP;
	}
	if (verifierOptions.devMode !== undefined) {
		resourceOptions.devMode = verifierOptions.devMode;
	}
	if (options.asCredentials !== undefined) {
		resourceOptions.asCredentials = options.asCredentials;
	}
	if (options.resourceMetadataUrl !== undefined) {
		resourceOptions.resourceMetadataUrl = options.resourceMetadataUrl;
	}

	const verifier = client.resource(resourceOptions);
	const tokenVerifier = new AuthplaneTokenVerifier(verifier);
	// Two different URLs on purpose. The challenge advertises whatever the
	// resource is configured to advertise (`resourceMetadataUrl()`: the
	// override when set, the derived URL otherwise); the route this adapter
	// mounts the document at is always the derived one, since that is where a
	// client that follows the *default* advertisement looks.
	const resourceMetadataUrl = verifier.resourceMetadataUrl();
	const protectedResourceMetadataPath = new URL(verifier.prmDocumentUrl())
		.pathname;
	const protectedResourceMetadata = verifier.prmResponse();

	// DPoP `htu` (RFC 9449 §4.2) is the request target URI — origin + path.
	// The origin (scheme + host + port) is operator-controlled and comes from
	// the configured `resource`; deriving it from inbound `Host` /
	// `X-Forwarded-Proto` would let an intermediary (or, when the app is
	// reachable directly, the requester) decide which `htu` the proof is
	// checked against, neutering DPoP's cross-endpoint anti-replay.
	const parsedResource = new URL(resource);
	const resourceOrigin = `${parsedResource.protocol}//${parsedResource.host}`;
	const resourceDefaultPath = parsedResource.pathname || "/";

	const protectedResourceMetadataHandler: RequestHandler = (_req, res) => {
		res.json(protectedResourceMetadata);
	};

	const bearerAuth: RequestHandler = async (req, res, next) => {
		const effectiveRequiredScopes = resolvedRequiredScopes;
		try {
			// Express middleware: parse Authorization, DPoP, and build an absolute
			// URL for DPoP `htu` verification. The MCP SDK's OAuthTokenVerifier
			// API takes a raw token string; there is no upstream hook that
			// supplies a pre-parsed token while also threading per-request DPoP
			// binding — so extraction stays here. Routes through the core
			// `extractBearerToken` helper so the strictness (and the
			// `DPoP` scheme carve-out per RFC 9449 §7.1) match
			// `@authplane/fastmcp`, `@authplane/hono`, and
			// `@authplane/nestjs` byte-for-byte. `Authorization` is in
			// Node's fixed de-dup-to-last-value allowlist (alongside
			// `host`, `content-type`, etc.), so `req.headers.authorization`
			// is `string | undefined` on real wire traffic — never an
			// array. The `Array.isArray` guard is defense against the
			// `string[]` shape that only arrives from `req.rawHeaders` or
			// hand-built fixtures; we collapse it to `undefined` so the
			// core helper raises `TokenMissing` instead of accepting a
			// hand-crafted multi-value bag.
			const rawAuth = req.headers.authorization;
			const token = extractBearerToken(
				Array.isArray(rawAuth) ? undefined : rawAuth,
			);

			// Node lowercases header names and types the value as
			// `string | string[] | undefined`. In practice
			// `http.IncomingMessage.headers` comma-folds duplicate same-name
			// values for everything except a fixed allow-list (only
			// `set-cookie` arrays naturally; `authorization`, `host`, etc.
			// dedupe to the last value), so two `DPoP` headers on the wire
			// arrive here as the single string `"proofA, proofB"`. The array
			// branch still happens for callers that hand-craft `req.headers`
			// or for adapters that surface `req.rawHeaders` directly, so
			// `extractDpopHeaderValues` accepts both shapes. The core
			// factory's comma-split is what catches the folded form — JWS
			// compact serialisation is base64url + `.` and never contains a
			// literal `,`, so any comma is necessarily a merged duplicate
			// and `MultipleDPoPProofs` fires. The catch below funnels that
			// through `wwwAuthenticate()` to emit the `DPoP` challenge.
			const dpopHeaderValues = extractDpopHeaderValues(req.headers.dpop);

			// Origin from configured `resource` (not request headers); only the
			// path varies per-request. `Host` and `X-Forwarded-Proto` are
			// intentionally ignored for `htu` reconstruction.
			const pathAndQuery = req.originalUrl ?? req.url ?? resourceDefaultPath;
			const url = `${resourceOrigin}${pathAndQuery}`;

			const dpopRequest =
				dpopHeaderValues.length > 0
					? buildDPoPRequestContext({
							method: req.method ?? "POST",
							url,
							dpopHeaderValues,
						})
					: undefined;
			const authInfo: AuthInfo = await tokenVerifier.verifyAccessTokenWithDpop(
				token,
				dpopRequest,
			);

			if (effectiveRequiredScopes.length > 0) {
				const hasAllScopes = effectiveRequiredScopes.every((scope) =>
					authInfo.scopes.includes(scope),
				);
				if (!hasAllScopes) {
					// Carry the scopes on the error: that is what makes the
					// requiredScopes fallback in wwwAuthenticate reachable from
					// here, and it matches VerifiedClaims.requireScopes.
					throw new InsufficientScope(
						"Insufficient scope",
						effectiveRequiredScopes,
					);
				}
			}

			// No expiry re-check here: core `resource.verify()` already enforces
			// `exp` with the configured `clockSkewSeconds` tolerance (and
			// throws `TokenExpired`). The previous middleware-level
			// `authInfo.expiresAt < Date.now() / 1000` re-check did the same
			// thing *without* the clock-skew tolerance, so it could reject
			// tokens core deemed valid — `@authplane/hono` and
			// `@authplane/nestjs` deleted the same pattern when their
			// adapters were thinned out onto the same core helpers.
			(req as typeof req & { auth?: AuthInfo }).auth = authInfo;
			next();
		} catch (error) {
			// Funnel every AuthplaneError through the SDK's helpers so the
			// scheme (Bearer/DPoP), status (401/403), and sanitisation are
			// expressed once across `@authplane/mcp` and
			// `@authplane/fastmcp`, exercised by the conformance suite.
			if (error instanceof AuthplaneError) {
				res.set(
					"WWW-Authenticate",
					wwwAuthenticate(error, {
						resourceMetadataUrl,
						// Passed only when non-empty so the error's own
						// requiredScopes can fill in — an explicit array,
						// empty included, wins over the fallback. The throw
						// site above now carries them too, so the two agree
						// whichever way the error arrives. Matches the Hono
						// and NestJS mappings.
						...(effectiveRequiredScopes.length > 0
							? { scope: effectiveRequiredScopes }
							: {}),
					}),
				);
				// Body and challenge are composed from the same core helpers, so
				// the code they name agrees and neither carries the exception's
				// own message to a caller who has not authenticated.
				res.status(httpStatus(error)).json(errorResponseBody(error));
			} else {
				// Fallback to a generic 500. The description is a fixed string:
				// this branch catches whatever the surrounding application threw,
				// so the message is not the SDK's to vouch for.
				res.status(500).json({
					error: "server_error",
					error_description: "Internal Server Error",
				});
			}
		}
	};

	return {
		client: wrapClientForElicitation(client),
		verifier,
		tokenVerifier,
		bearerAuth,
		protectedResourceMetadataPath,
		protectedResourceMetadataUrl: resourceMetadataUrl,
		protectedResourceMetadata,
		protectedResourceMetadataHandler,
	};
}

/**
 * Wraps `client.exchange` so that `ConsentRequiredError` with a
 * `consentUrl` is automatically translated to MCP `-32042`
 * (`UrlElicitationRequiredError`). Tool authors never need to
 * handle consent mapping — it happens transparently.
 */
function wrapClientForElicitation(client: AuthplaneClient): AuthplaneClient {
	const originalExchange = client.exchange.bind(client);
	client.exchange = async (...args) => {
		try {
			return await originalExchange(...args);
		} catch (e) {
			const mapped = toUrlElicitationRequiredError(e);
			if (mapped) {
				(mapped as Error).cause = e;
				throw mapped;
			}
			throw e;
		}
	};
	return client;
}

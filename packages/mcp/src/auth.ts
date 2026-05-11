import {
	AuthplaneClient,
	type AuthplaneResource,
	type AuthplaneResourceOptions,
	type DPoPProvider,
	type FetchSettings,
	type ProtectedResourceMetadata,
} from "@authplane/sdk/core";
import {
	InsufficientScopeError,
	InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
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
 */
export function requireScope(
	scope: string,
	authInfo: AuthInfo | undefined,
): void {
	if (!authInfo?.scopes?.includes(scope)) {
		throw new Error(`Missing required scope: ${scope}`);
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
	 * Defaults are derived from `devMode`. Java/Python parity.
	 */
	fetchSettings?: FetchSettings;
	jwksRefreshSeconds?: number;
	metadataRefreshSeconds?: number;
	/**
	 * Outbound DPoP provider for AS-facing calls (introspection, token
	 * exchange, revocation). When set, requests to the AS are accompanied by
	 * a DPoP proof and `cnf.jkt`-bound tokens are minted. Python parity with
	 * `authplane_mcp_auth(dpop=...)`.
	 */
	dpopProvider?: DPoPProvider;
	/**
	 * Buffer subtracted from token TTLs before the outbound token cache
	 * considers an entry expired (seconds). Default `30`. Python parity
	 * with `cache_ttl_buffer_seconds`.
	 */
	cacheTtlBufferSeconds?: number;
	/**
	 * Fallback outbound-token cache TTL used when the AS response does not
	 * include expiry metadata (seconds). Default `3600`. Python parity with
	 * `default_ttl_seconds`.
	 */
	defaultTtlSeconds?: number;
	/**
	 * Number of consecutive transient AS failures before the circuit breaker
	 * opens. Default `5`. Python parity with `circuit_breaker_threshold`.
	 */
	circuitBreakerThreshold?: number;
	/**
	 * Cooldown before the open circuit breaker allows a half-open probe
	 * request (seconds). Default `30`. Python parity with
	 * `circuit_breaker_cooldown_seconds`.
	 */
	circuitBreakerCooldownSeconds?: number;
}

export interface AuthplaneMcpAuth {
	client: AuthplaneClient;
	verifier: AuthplaneResource;
	tokenVerifier: AuthplaneTokenVerifier;
	bearerAuth: RequestHandler;
	protectedResourceMetadataPath: string;
	protectedResourceMetadata: ProtectedResourceMetadata;
	protectedResourceMetadataHandler: RequestHandler;
}

/**
 * Build the wiring needed to enable Authplane auth on an MCP server.
 *
 * Mirrors the Python `authplane_mcp_auth()` helper:
 *
 * - Creates an `AuthplaneResource` configured with issuer, resource, and scopes
 * - Performs RFC 8414 metadata discovery and JWKS fetching
 * - Exposes `tokenVerifier` (an `OAuthTokenVerifier` implementation) for users
 *   who want to wire MCP's `requireBearerAuth` themselves
 * - Ships an Express `bearerAuth` handler that re-implements the SDK's
 *   bearer-auth middleware (Authorization parsing, DPoP-header extraction,
 *   scope checks, `WWW-Authenticate`, 401/403/500) so it can thread
 *   per-request DPoP context into `verifier.verify()` — `requireBearerAuth`
 *   in the upstream SDK has no hook for that (see AP-244)
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

	const verifier = client.resource(resourceOptions);
	const tokenVerifier = new AuthplaneTokenVerifier(verifier);
	const resourceMetadataUrl = verifier.prmDocumentUrl();
	const protectedResourceMetadataPath = new URL(resourceMetadataUrl).pathname;
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
			// Express middleware: we parse Authorization, DPoP, and build an absolute URL for
			// DPoP `htu` verification. The MCP SDK's OAuthTokenVerifier API takes a raw token
			// string; there is no upstream hook that supplies a pre-parsed token while also
			// threading per-request DPoP binding — so extraction stays here (AP-244).
			const authHeader = req.headers.authorization;
			if (!authHeader || Array.isArray(authHeader)) {
				throw new InvalidTokenError("Missing Authorization header");
			}

			const [rawType, token] = authHeader.split(" ");
			const type = rawType?.toLowerCase();
			if (!token || type !== "bearer") {
				throw new InvalidTokenError(
					"Invalid Authorization header format, expected 'Bearer TOKEN'",
				);
			}

			// Extract DPoP proof header (FastMCP/SDK uses `dpop` / `DPoP` in practice).
			// Note: DPoP proof verification requires htu/method matching the incoming HTTP request.
			let dpopProof: string | undefined;
			for (const [key, value] of Object.entries(req.headers)) {
				if (key.toLowerCase() !== "dpop") continue;
				if (typeof value === "string" && value.length > 0) dpopProof = value;
			}

			// Origin from configured `resource` (not request headers); only the
			// path varies per-request. `Host` and `X-Forwarded-Proto` are
			// intentionally ignored for `htu` reconstruction (AP-412).
			const pathAndQuery =
				req.originalUrl ?? req.url ?? resourceDefaultPath;
			const url = `${resourceOrigin}${pathAndQuery}`;

			const dpopRequest =
				dpopProof !== undefined
					? {
							method: req.method ?? "POST",
							url,
							proof: dpopProof,
						}
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
					throw new InsufficientScopeError("Insufficient scope");
				}
			}

			if (
				typeof authInfo.expiresAt !== "number" ||
				Number.isNaN(authInfo.expiresAt)
			) {
				throw new InvalidTokenError("Token has no expiration time");
			} else if (authInfo.expiresAt < Date.now() / 1000) {
				throw new InvalidTokenError("Token has expired");
			}

			(req as typeof req & { auth?: AuthInfo }).auth = authInfo;
			next();
		} catch (error) {
			const requiredScopes = effectiveRequiredScopes;
			const resourceMetadataUrl_ = resourceMetadataUrl;

			const buildWwwAuthHeader = (errorCode: string, message: string) => {
				let header = `Bearer error="${errorCode}", error_description="${message}"`;
				if (requiredScopes.length > 0) {
					header += `, scope="${requiredScopes.join(" ")}"`;
				}
				if (resourceMetadataUrl_) {
					header += `, resource_metadata="${resourceMetadataUrl_}"`;
				}
				return header;
			};

			if (error instanceof InvalidTokenError) {
				res.set(
					"WWW-Authenticate",
					buildWwwAuthHeader(error.errorCode, error.message),
				);
				res.status(401).json(error.toResponseObject());
			} else if (error instanceof InsufficientScopeError) {
				res.set(
					"WWW-Authenticate",
					buildWwwAuthHeader(error.errorCode, error.message),
				);
				res.status(403).json(error.toResponseObject());
			} else {
				// Fallback to a generic 500.
				res.status(500).json({
					error: "server_error",
					error_description:
						error instanceof Error ? error.message : "Internal Server Error",
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

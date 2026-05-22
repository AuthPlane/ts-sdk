import { AsyncLocalStorage } from "node:async_hooks";
import type { IncomingMessage } from "node:http";
import {
	AuthplaneClient,
	AuthplaneError,
	type AuthplaneResource,
	type AuthplaneResourceOptions,
	type DPoPProvider,
	type DPoPRequestContext,
	type FetchSettings,
	InsufficientScope,
	type ProtectedResourceMetadata,
	TokenMissing,
	httpStatus,
	wwwAuthenticate,
} from "@authplane/sdk/core";
import type { ServerOptions } from "fastmcp";
import { toUrlElicitationRequiredError } from "./urlElicitation.js";
import {
	type AuthplaneFastMcpSession,
	AuthplaneTokenVerifier,
} from "./verifier.js";

/**
 * Async-local context that scopes the per-request `verifyAccessToken` cache.
 *
 * Production code never touches this directly. Node's `http.Server` creates
 * a fresh async context per HTTP request, so the first `authenticate` call
 * inside that context uses `enterWith` to plant a fresh store, and any
 * subsequent `authenticate` calls within the same request (FastMCP invokes
 * the callback twice as of 3.35.x) see the same store via async-chain
 * propagation. Different requests get distinct async contexts and therefore
 * distinct stores — no cross-request leakage is possible regardless of how
 * FastMCP wraps, replaces, or proxies the `IncomingMessage`.
 *
 * @internal Exported only so tests can simulate the per-request boundary
 * Node provides automatically. A vitest test body shares one async context
 * across all of its calls, so tests must wrap each "simulated request" in
 * `_authenticateRequestContext.run({}, async () => ...)` to mimic prod.
 */
export const _authenticateRequestContext = new AsyncLocalStorage<{
	promise?: Promise<AuthplaneFastMcpSession>;
}>();

export interface AuthplaneFastMcpAuthOptions
	extends Omit<AuthplaneResourceOptions, "scopes" | "resource"> {
	issuer: string;
	resource?: string;
	baseUrl?: string;
	mcpPath?: string;
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

export interface AuthplaneFastMcpAuth {
	client: AuthplaneClient;
	verifier: AuthplaneResource;
	tokenVerifier: AuthplaneTokenVerifier;
	authenticate: NonNullable<
		ServerOptions<AuthplaneFastMcpSession>["authenticate"]
	>;
	oauth: NonNullable<ServerOptions<AuthplaneFastMcpSession>["oauth"]>;
	protectedResourceMetadata: ProtectedResourceMetadata;
	protectedResourceMetadataUrl: string;
}

function deriveResource(baseUrl: string, mcpPath: string): string {
	const base = baseUrl.replace(/\/+$/, "");
	const path = mcpPath.replace(/^\/+/, "") || "mcp";
	return `${base}/${path}`;
}

function getBearerToken(request: IncomingMessage): string | undefined {
	const authHeader = request.headers.authorization;
	if (!authHeader || Array.isArray(authHeader)) {
		return undefined;
	}
	const trimmed = authHeader.trim();
	const lower = trimmed.toLowerCase();

	const bearerPrefix = "bearer ";
	if (lower.startsWith(bearerPrefix)) {
		return trimmed.slice(bearerPrefix.length).trim();
	}

	const dpopPrefix = "dpop ";
	if (lower.startsWith(dpopPrefix)) {
		return trimmed.slice(dpopPrefix.length).trim();
	}

	return undefined;
}

function getDpopProof(request: IncomingMessage): string | undefined {
	// `IncomingMessage.headers` lowercases keys in Node, but FastMCP may wrap/transform.
	// Do a case-insensitive scan to reliably find `DPoP`.
	const headers = request.headers;
	for (const [key, value] of Object.entries(headers)) {
		if (key.toLowerCase() !== "dpop") continue;
		if (typeof value === "string" && value.length > 0) return value;
	}
	return undefined;
}

function buildDpopRequestContext(
	request: IncomingMessage,
	resourceOrigin: string,
	resourceDefaultPath: string,
): DPoPRequestContext | undefined {
	const proof = getDpopProof(request);
	if (proof === undefined) {
		return undefined;
	}

	// DPoP `htu` (RFC 9449 §4.2) is the request target URI — origin + path.
	// The origin (scheme + host + port) is operator-controlled and comes
	// from the configured `resource`; deriving it from inbound `Host` /
	// `X-Forwarded-Proto` would let an intermediary (or, when the app is
	// reachable directly, the requester) decide which `htu` the proof is
	// checked against, neutering DPoP's cross-endpoint anti-replay
	// Only the path varies per-request.
	const pathAndQuery = request.url ?? resourceDefaultPath;
	const url = `${resourceOrigin}${pathAndQuery}`;

	return {
		method: (request.method ?? "POST").toUpperCase(),
		url,
		proof,
	};
}

export async function authplaneFastMcpAuth(
	options: AuthplaneFastMcpAuthOptions,
): Promise<AuthplaneFastMcpAuth> {
	const resource =
		options.resource ??
		(options.baseUrl !== undefined
			? deriveResource(options.baseUrl, options.mcpPath ?? "/mcp")
			: null);
	if (resource == null) {
		throw new Error(
			"authplaneFastMcpAuth: provide either 'resource' or 'baseUrl' (and optionally 'mcpPath')",
		);
	}

	const {
		baseUrl: _bu,
		mcpPath: _mp,
		requiredScopes: _rs,
		...verifierOptions
	} = options;

	const client = await AuthplaneClient.create({
		issuer: options.issuer,
		auth: options.asCredentials,
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
		scopes: options.scopes ?? [],
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
	const protectedResourceMetadata = verifier.prmResponse();
	const protectedResourceMetadataUrl = verifier.prmDocumentUrl();

	const parsedResource = new URL(resource);
	const resourceOrigin = `${parsedResource.protocol}//${parsedResource.host}`;
	const resourceDefaultPath = parsedResource.pathname || "/";

	const defaultRequiredScopes = options.requiredScopes ?? [];

	// Per-request verification cache via Node's `AsyncLocalStorage`. FastMCP
	// can — and as of 3.35.x does — invoke `authenticate` more than once per
	// HTTP request. Without this cache the second invocation re-enters
	// `AuthplaneResource.verify()` with the same DPoP proof, which the inbound
	// replay store then rejects as `DPoPReplayDetected`, breaking
	// `inboundDPoP: { required: true }`. The async-local store carries the
	// in-flight `verifyAccessToken` promise across the request's async chain
	// so both invocations collapse onto a single verify(). The boundary is
	// Node's per-request async context (one per HTTP request, fresh on each
	// 'request' event) — no shared keying on `IncomingMessage` identity, so
	// FastMCP wrapping/replacing the request object between invocations does
	// not break the cache. The store dies with the request's async context,
	// so cross-request replay protection is preserved.
	// Build a `Response` for an AuthplaneError using the shared
	// `httpStatus` + `wwwAuthenticate` helpers from `@authplane/sdk/core`.
	// Both adapters (`@authplane/mcp` and `@authplane/fastmcp`) funnel
	// every error path through this so the wire-level contract is
	// expressed once, in the SDK, and pinned by the conformance suite.
	const challengeResponse = (error: AuthplaneError): Response =>
		new Response(null, {
			status: httpStatus(error),
			headers: {
				"WWW-Authenticate": wwwAuthenticate(error, {
					resourceMetadataUrl: protectedResourceMetadataUrl,
					scope: defaultRequiredScopes,
				}),
			},
		});

	const authenticate: NonNullable<
		ServerOptions<AuthplaneFastMcpSession>["authenticate"]
	> = async (request) => {
		const token = getBearerToken(request);
		if (!token) {
			throw challengeResponse(
				new TokenMissing("Missing or invalid Authorization header"),
			);
		}

		let store = _authenticateRequestContext.getStore();
		if (store === undefined) {
			store = {};
			_authenticateRequestContext.enterWith(store);
		}
		if (store.promise === undefined) {
			const dpopContext = buildDpopRequestContext(
				request,
				resourceOrigin,
				resourceDefaultPath,
			);
			store.promise = tokenVerifier.verifyAccessToken(token, dpopContext);
		}
		let session: AuthplaneFastMcpSession;
		try {
			session = await store.promise;
		} catch (err) {
			if (err instanceof AuthplaneError) {
				// Surface the underlying class so DPoP failures get the DPoP
				// challenge scheme and scope failures get 403, instead of
				// every authentication error collapsing to a generic
				// "Invalid access token" 401. The cached rejection from the
				// ALS-scoped promise re-throws on every replay within the
				// same request (FastMCP double-`authenticate`), so both
				// invocations surface the same typed error.
				throw challengeResponse(err);
			}
			throw err;
		}

		if (defaultRequiredScopes.length > 0) {
			const hasAll = defaultRequiredScopes.every((scope) =>
				session.scopes.includes(scope),
			);
			if (!hasAll) {
				throw challengeResponse(new InsufficientScope("Insufficient scope"));
			}
		}

		return session;
	};

	const oauth: NonNullable<ServerOptions<AuthplaneFastMcpSession>["oauth"]> = {
		enabled: true,
		protectedResource: {
			resource: protectedResourceMetadata.resource,
			authorizationServers: [
				...protectedResourceMetadata.authorization_servers,
			],
			scopesSupported: [...protectedResourceMetadata.scopes_supported],
			bearerMethodsSupported: [
				...protectedResourceMetadata.bearer_methods_supported,
			],
		},
	};

	return {
		client: wrapClientForElicitation(client),
		verifier,
		tokenVerifier,
		authenticate,
		oauth,
		protectedResourceMetadata,
		protectedResourceMetadataUrl,
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

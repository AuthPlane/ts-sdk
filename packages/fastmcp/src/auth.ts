import type { IncomingMessage } from "node:http";
import {
	AuthplaneClient,
	type AuthplaneResource,
	type AuthplaneResourceOptions,
	type DPoPProvider,
	type DPoPRequestContext,
	type FetchSettings,
	type ProtectedResourceMetadata,
} from "@authplane/sdk/core";
import type { ServerOptions } from "fastmcp";
import { toUrlElicitationRequiredError } from "./urlElicitation.js";
import {
	type AuthplaneFastMcpSession,
	AuthplaneTokenVerifier,
} from "./verifier.js";

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
	 * Defaults are derived from `devMode`. Java/Python parity.
	 */
	fetchSettings?: FetchSettings;
	jwksRefreshSeconds?: number;
	metadataRefreshSeconds?: number;
	/**
	 * Outbound DPoP provider for AS-facing calls (introspection, token
	 * exchange, revocation). When set, requests to the AS are accompanied by
	 * a DPoP proof and `cnf.jkt`-bound tokens are minted. Python parity with
	 * `authplane_auth(dpop=...)`.
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
	// (AP-412). Only the path varies per-request.
	const pathAndQuery = request.url ?? resourceDefaultPath;
	const url = `${resourceOrigin}${pathAndQuery}`;

	return {
		method: (request.method ?? "POST").toUpperCase(),
		url,
		proof,
	};
}

function unauthorizedResponse(
	description: string,
	resourceMetadataUrl: string,
): Response {
	return new Response(null, {
		status: 401,
		headers: {
			"WWW-Authenticate": `Bearer error="invalid_token", error_description="${description}", resource_metadata="${resourceMetadataUrl}"`,
		},
	});
}

function forbiddenInsufficientScopeResponse(
	requiredScopes: string[],
	resourceMetadataUrl: string,
): Response {
	const scopeValue = requiredScopes.join(" ");
	return new Response(null, {
		status: 403,
		headers: {
			"WWW-Authenticate": `Bearer error="insufficient_scope", error_description="Insufficient scope", scope="${scopeValue}", resource_metadata="${resourceMetadataUrl}"`,
		},
	});
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

	const authenticate: NonNullable<
		ServerOptions<AuthplaneFastMcpSession>["authenticate"]
	> = async (request) => {
		const token = getBearerToken(request);
		if (!token) {
			throw unauthorizedResponse(
				"Missing or invalid Authorization header",
				protectedResourceMetadataUrl,
			);
		}

		const dpopContext = buildDpopRequestContext(
			request,
			resourceOrigin,
			resourceDefaultPath,
		);
		const session = await tokenVerifier.verifyAccessToken(token, dpopContext);
		if (!session) {
			throw unauthorizedResponse(
				"Invalid access token",
				protectedResourceMetadataUrl,
			);
		}

		if (defaultRequiredScopes.length > 0) {
			const hasAll = defaultRequiredScopes.every((scope) =>
				session.scopes.includes(scope),
			);
			if (!hasAll) {
				throw forbiddenInsufficientScopeResponse(
					defaultRequiredScopes,
					protectedResourceMetadataUrl,
				);
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

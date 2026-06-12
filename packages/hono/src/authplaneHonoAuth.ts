import {
	AuthplaneClient,
	type AuthplaneResource,
	type AuthplaneResourceOptions,
	type DPoPProvider,
	type DPoPReplayStore,
	type FetchSettings,
	type ProtectedResourceMetadata,
} from "@authplane/sdk/core";
import type { Handler, MiddlewareHandler } from "hono";

import { bearerAuth } from "./bearerAuth.js";
import { protectedResourceMetadataHandler } from "./prmHandler.js";
import type { HonoAuthVariables } from "./types.js";

/**
 * Input options for {@link authplaneHonoAuth}. A faithful port of
 * `AuthplaneMcpAuthOptions` from `@authplane/mcp` so the two adapters have
 * interchangeable configuration.
 */
export interface AuthplaneHonoAuthOptions
	extends Omit<AuthplaneResourceOptions, "scopes" | "resource"> {
	/** Authorization server issuer URL (used for discovery + JWKS). */
	issuer: string;
	/** Canonical resource identifier this server protects. */
	resource: string;
	/** All scopes this resource server supports. */
	scopes?: string[];
	/**
	 * Scopes the middleware must enforce. Defaults to `scopes` when not
	 * provided, matching the behaviour of the Python + MCP adapters.
	 */
	requiredScopes?: string[];
	/**
	 * Outbound fetch hardening (SSRF, timeouts, allowlists) applied to both
	 * AS metadata and JWKS document fetches. When omitted, defaults are
	 * derived from `devMode`.
	 */
	fetchSettings?: FetchSettings;
	/** Seconds between JWKS refreshes. */
	jwksRefreshSeconds?: number;
	/** Seconds between AS metadata refreshes. */
	metadataRefreshSeconds?: number;
	/**
	 * Outbound DPoP provider for AS-facing calls (introspection, token
	 * exchange, revocation). When set, requests to the AS carry a DPoP proof
	 * and `cnf.jkt`-bound tokens are minted. Parity with the mcp/fastmcp
	 * adapters.
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
	/**
	 * Inbound DPoP proof replay store. Convenience shortcut that is folded
	 * into `inboundDPoP.replayStore` for the resource verifier; setting it
	 * also implicitly opts the resource into DPoP (Mode 2 — Supported) if
	 * `inboundDPoP` is not already provided.
	 *
	 * Setting both `replayStore` and `inboundDPoP.replayStore` throws at
	 * construction — pick one channel to avoid ambiguous precedence.
	 */
	replayStore?: DPoPReplayStore;
}

/**
 * Wiring returned by {@link authplaneHonoAuth}. Everything an application
 * needs to enable Authplane-issued bearer auth on a Hono server in a single
 * call.
 */
export interface AuthplaneHonoAuth {
	/** Shared Authplane client. Exposed so callers can reuse it for AS traffic. */
	client: AuthplaneClient;
	/** Core resource verifier. Useful for custom flows outside the middleware. */
	verifier: AuthplaneResource;
	/** Fully-configured bearer middleware (scope, DPoP, PRM URL all wired). */
	bearerAuth: MiddlewareHandler<{ Variables: HonoAuthVariables }>;
	/** Path (pathname portion) where the PRM handler should be mounted. */
	protectedResourceMetadataPath: string;
	/** The RFC 9728 PRM payload served by the handler. */
	protectedResourceMetadata: ProtectedResourceMetadata;
	/** Hono route handler that serves {@link protectedResourceMetadata} as JSON. */
	protectedResourceMetadataHandler: Handler;
}

/**
 * Build the wiring needed to enable Authplane auth on a Hono server.
 *
 * Mirrors the Express `authplaneMcpAuth()` variant in `@authplane/mcp`.
 * Returns the shared `AuthplaneClient`, the core
 * `AuthplaneResource`, the configured `bearerAuth` middleware, and the RFC
 * 9728 PRM handler + path.
 *
 * When `requiredScopes` is not provided it defaults to `scopes` so the
 * middleware treats every supported scope as required.
 */
export async function authplaneHonoAuth(
	options: AuthplaneHonoAuthOptions,
): Promise<AuthplaneHonoAuth> {
	const { requiredScopes, scopes, issuer, resource } = options;

	if (
		options.replayStore !== undefined &&
		options.inboundDPoP?.replayStore !== undefined
	) {
		throw new Error(
			"authplaneHonoAuth: pass `replayStore` OR `inboundDPoP.replayStore`, not both",
		);
	}

	const resolvedScopes = scopes ?? [];
	const resolvedRequiredScopes = requiredScopes ?? resolvedScopes;
	const resourceOrigin = new URL(resource).origin;

	const client = await buildAuthplaneClient({ issuer, options });
	const verifier = client.resource(
		buildResourceOptions(resource, resolvedScopes, options),
	);
	const resourceMetadataUrl = verifier.prmDocumentUrl();
	const protectedResourceMetadataPath = new URL(resourceMetadataUrl).pathname;
	const protectedResourceMetadata = verifier.prmResponse();

	return {
		client,
		verifier,
		bearerAuth: bearerAuth({
			verifier,
			requiredScopes: resolvedRequiredScopes,
			resourceMetadataUrl,
			resourceOrigin,
		}),
		protectedResourceMetadataPath,
		protectedResourceMetadata,
		protectedResourceMetadataHandler: protectedResourceMetadataHandler(
			protectedResourceMetadata,
		),
	};
}

interface BuildClientParams {
	readonly issuer: string;
	readonly options: AuthplaneHonoAuthOptions;
}

async function buildAuthplaneClient(
	params: BuildClientParams,
): Promise<AuthplaneClient> {
	const { issuer, options } = params;
	const clientOptions: Parameters<typeof AuthplaneClient.create>[0] = {
		issuer,
	};
	if (options.asCredentials !== undefined) {
		clientOptions.auth = options.asCredentials;
	}
	if (options.devMode !== undefined) {
		clientOptions.devMode = options.devMode;
	}
	if (options.fetchSettings !== undefined) {
		clientOptions.fetchSettings = options.fetchSettings;
	}
	if (options.jwksRefreshSeconds !== undefined) {
		clientOptions.jwksRefreshSeconds = options.jwksRefreshSeconds;
	}
	if (options.metadataRefreshSeconds !== undefined) {
		clientOptions.metadataRefreshSeconds = options.metadataRefreshSeconds;
	}
	if (options.dpopProvider !== undefined) {
		clientOptions.dpopProvider = options.dpopProvider;
	}
	if (options.cacheTtlBufferSeconds !== undefined) {
		clientOptions.cacheTtlBufferSeconds = options.cacheTtlBufferSeconds;
	}
	if (options.defaultTtlSeconds !== undefined) {
		clientOptions.defaultTtlSeconds = options.defaultTtlSeconds;
	}
	if (options.cacheMaxEntries !== undefined) {
		clientOptions.cacheMaxEntries = options.cacheMaxEntries;
	}
	if (options.circuitBreakerThreshold !== undefined) {
		clientOptions.circuitBreakerThreshold = options.circuitBreakerThreshold;
	}
	if (options.circuitBreakerCooldownSeconds !== undefined) {
		clientOptions.circuitBreakerCooldownSeconds =
			options.circuitBreakerCooldownSeconds;
	}
	return AuthplaneClient.create(clientOptions);
}

function buildResourceOptions(
	resource: string,
	scopes: string[],
	options: AuthplaneHonoAuthOptions,
): AuthplaneResourceOptions {
	const resourceOptions: AuthplaneResourceOptions = {
		resource,
		scopes,
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
	if (options.devMode !== undefined) {
		resourceOptions.devMode = options.devMode;
	}
	if (options.asCredentials !== undefined) {
		resourceOptions.asCredentials = options.asCredentials;
	}
	if (options.failClosed !== undefined) {
		resourceOptions.failClosed = options.failClosed;
	}
	if (options.inboundDPoP !== undefined || options.replayStore !== undefined) {
		resourceOptions.inboundDPoP = {
			...(options.inboundDPoP ?? {}),
			...(options.replayStore !== undefined
				? { replayStore: options.replayStore }
				: {}),
		};
	}
	return resourceOptions;
}

import type { ModuleMetadata, Type } from "@nestjs/common";

import type {
	ASCredentials,
	AuthProvider,
	AuthplaneResourceOptions,
	DPoPProvider,
	FetchSettings,
} from "@authplane/sdk/core";

import type { RequestAdapter } from "../infrastructure/request-adapter.js";

/**
 * Module-level options for {@link AuthplaneModule.forRootAsync}.
 *
 * Designed as a faithful port of `AuthplaneHonoAuthOptions` from
 * `@authplane/hono` (and `AuthplaneMcpAuthOptions` from `@authplane/mcp`)
 * so the three adapters stay interchangeable at the configuration surface.
 * The NestJS-only additions are explicitly called out below.
 */
export interface AuthplaneModuleOptions
	extends Omit<AuthplaneResourceOptions, "scopes" | "resource"> {
	/** Authorization server issuer URL (used for discovery + JWKS). */
	issuer: string;
	/** Canonical resource identifier this server protects. */
	resource: string;
	/** All scopes this resource server supports. */
	scopes?: string[];
	/**
	 * Scopes the guard must enforce at the module level — every request is
	 * checked against this set. Per-route `@RequireScopes(...)` metadata is
	 * merged on top. Defaults to `scopes` when not provided, matching the
	 * Python + Hono + MCP adapters.
	 */
	requiredScopes?: string[];
	/**
	 * Outbound fetch hardening (SSRF, timeouts, allowlists) applied to both
	 * AS metadata and JWKS document fetches. When omitted, defaults are
	 * derived from `devMode`. RFC 8414 / RFC 7517 — both endpoints share the
	 * same threat profile, so a single setting governs both.
	 */
	fetchSettings?: FetchSettings;
	/** Seconds between JWKS refreshes. */
	jwksRefreshSeconds?: number;
	/** Seconds between AS metadata refreshes. */
	metadataRefreshSeconds?: number;
	/**
	 * AS-facing credentials for outbound calls (token exchange, revocation,
	 * introspection). Accepts a full {@link AuthProvider} (e.g. for
	 * `private_key_jwt`, mTLS, or a custom provider) or an
	 * {@link ASCredentials} shortcut — bare credentials are wrapped in a
	 * `ClientCredentialsProvider` by the core client. Matches the
	 * `auth` knob on {@link AuthplaneClient.create}; mirrors mcp / fastmcp.
	 *
	 * If both `auth` and the legacy `asCredentials` shortcut are set, `auth`
	 * wins.
	 */
	auth?: AuthProvider | ASCredentials;
	/**
	 * Seconds subtracted from the upstream `expires_in` when caching AS
	 * responses, so cache entries expire ahead of the real token. Forwarded
	 * to {@link AuthplaneClient.create}; defaults to 30s.
	 */
	cacheTtlBufferSeconds?: number;
	/**
	 * Fallback TTL (seconds) used when an AS response omits `expires_in`.
	 * Forwarded to {@link AuthplaneClient.create}; defaults to 3600.
	 */
	defaultTtlSeconds?: number;
	/**
	 * Maximum number of entries kept in the outbound token cache before
	 * least-recently-used eviction kicks in. Forwarded to {@link
	 * AuthplaneClient.create}; defaults to `10_000`. Override on hosts with
	 * very high subject-token cardinality.
	 */
	cacheMaxEntries?: number;
	/**
	 * Consecutive AS failures before the outbound circuit breaker opens.
	 * Forwarded to {@link AuthplaneClient.create}; defaults to 5.
	 */
	circuitBreakerThreshold?: number;
	/**
	 * Seconds the outbound circuit breaker stays open before half-open
	 * retries. Forwarded to {@link AuthplaneClient.create}; defaults to 30.
	 */
	circuitBreakerCooldownSeconds?: number;
	/**
	 * DPoP provider used for **outbound** AS-facing calls (token exchange,
	 * client-credentials grants). Inbound DPoP verification is configured
	 * separately via `inboundDPoP.replayStore`. Forwarded as-is to
	 * {@link AuthplaneClient.create}.
	 */
	dpopProvider?: DPoPProvider;
	/**
	 * Optional override for the {@link RequestAdapter} used by the guard +
	 * exception filter. NestJS-specific escape hatch — swap this in to add a
	 * new transport (e.g. `@nestjs/platform-ws`) or to stub request reads in
	 * integration tests.
	 *
	 * Defaults to `defaultRequestAdapter`, which already covers
	 * `@nestjs/platform-express` and `@nestjs/platform-fastify`.
	 */
	requestAdapter?: RequestAdapter;
}

/**
 * Async options surface for {@link AuthplaneModule.forRootAsync} additions.
 *
 * NestJS requires the PRM controller's `@Get` path to be a string literal at
 * module-registration time, but async option factories (e.g. those that read
 * `ConfigService`) only resolve after the module is being constructed. Pass
 * `prmPath` to tell `AuthplaneModule.forRootAsync` which path to mount the
 * PRM controller at without inspecting the (still-unresolved) `resource` URL.
 *
 * When omitted, `forRootAsync` falls back to inspecting a synchronous
 * `useFactory` (no `inject`, no `Promise`). Async setups without `prmPath`
 * silently skip the PRM controller and applications are expected to mount
 * the document from their own handler.
 */
export interface AuthplaneAsyncRegistrationHints {
	/**
	 * Pre-derived PRM path (RFC 9728 §3.1), e.g.
	 * `/.well-known/oauth-protected-resource/mcp`. Use
	 * `oauthProtectedResourceMetadataPath(resource)` (from `@authplane/sdk/core`) to compute it.
	 */
	prmPath?: string;
}

/**
 * Factory interface for async options. Implement this in a provider class
 * when you need DI'd values (e.g. a `ConfigService`) to build
 * {@link AuthplaneModuleOptions}.
 */
export interface AuthplaneOptionsFactory {
	createAuthplaneOptions():
		| Promise<AuthplaneModuleOptions>
		| AuthplaneModuleOptions;
}

/**
 * Async options surface for {@link AuthplaneModule.forRootAsync}. Mirrors
 * the standard NestJS async-module shape so it composes naturally with
 * other modules (`ConfigModule`, `TypeOrmModule`, ...).
 */
export interface AuthplaneModuleAsyncOptions
	extends Pick<ModuleMetadata, "imports"> {
	/** Reuse a factory already registered elsewhere in the DI container. */
	useExisting?: Type<AuthplaneOptionsFactory>;
	/** Instantiate a factory class and call `createAuthplaneOptions()`. */
	useClass?: Type<AuthplaneOptionsFactory>;
	/** Inline factory function; `inject` lists the providers passed in. */
	useFactory?: (
		...args: readonly unknown[]
	) => Promise<AuthplaneModuleOptions> | AuthplaneModuleOptions;
	/** Providers passed positionally to `useFactory`. */
	inject?: readonly (Type<unknown> | string | symbol)[];
}

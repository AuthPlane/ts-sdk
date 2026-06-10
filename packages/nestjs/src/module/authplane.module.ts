import {
	type DynamicModule,
	Logger,
	Module,
	type Provider,
} from "@nestjs/common";

import {
	AuthplaneClient,
	type AuthplaneResource,
	type AuthplaneResourceOptions,
	oauthProtectedResourceMetadataPath,
} from "@authplane/sdk/core";

import { AuthplaneAuthGuard } from "../application/authplane.guard.js";
import { AuthplaneExceptionFilter } from "../application/authplane.exception-filter.js";
import {
	defaultRequestAdapter,
	type RequestAdapter,
} from "../infrastructure/request-adapter.js";
import { buildPrmController } from "../presentation/prm.controller.js";
import type {
	AuthplaneAsyncRegistrationHints,
	AuthplaneModuleAsyncOptions,
	AuthplaneModuleOptions,
	AuthplaneOptionsFactory,
} from "./authplane.options.js";
import { AuthplaneShutdownHook } from "./authplane.shutdown-hook.js";
import {
	AUTHPLANE_CLIENT,
	AUTHPLANE_MODULE_OPTIONS,
	AUTHPLANE_REQUEST_ADAPTER,
	AUTHPLANE_RESOURCE,
	AUTHPLANE_TOKEN_VERIFIER,
} from "./authplane.tokens.js";

/**
 * Top-level dynamic module for `@authplane/nestjs`.
 *
 * Provisions, in order:
 *
 *   1. {@link AuthplaneModuleOptions} — the user-supplied configuration.
 *   2. {@link AuthplaneClient} — created async via `AuthplaneClient.create`.
 *   3. {@link AuthplaneResource} — the per-resource verifier. Also exposed
 *      via the `AUTHPLANE_TOKEN_VERIFIER` DI token (same instance, separate
 *      symbol) so tests can substitute the verifier without rebinding the
 *      resource provider.
 *   4. {@link RequestAdapter} — Express+Fastify ACL (overridable).
 *   5. {@link AuthplaneShutdownHook} — calls `client.close()` on shutdown.
 *   6. {@link AuthplaneAuthGuard} + {@link AuthplaneExceptionFilter} — the
 *      guard and filter that applications wire up with `@UseGuards` /
 *      `@UseFilters` (or `APP_GUARD` / `APP_FILTER` globally).
 *
 * The PRM controller is minted at registration time from the resource URL
 * using core `oauthProtectedResourceMetadataPath()` so NestJS sees a
 * literal path string on `@Get`.
 *
 * @example
 * ```ts
 * import { AuthplaneModule } from "@authplane/nestjs";
 *
 * @Module({
 *   imports: [
 *     AuthplaneModule.forRoot({
 *       issuer: "https://auth.example.com",
 *       resource: "https://api.example.com/mcp",
 *       scopes: ["tools/add", "tools/multiply"],
 *     }),
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
@Module({})
export class AuthplaneModule {
	/**
	 * Register the module with a known, eagerly-available options object.
	 * Thin wrapper over {@link AuthplaneModule.forRootAsync} that makes the
	 * simple case (no DI dependencies) a one-liner.
	 */
	public static forRoot(options: AuthplaneModuleOptions): DynamicModule {
		// Synchronous factory means `derivePrmPath` can introspect the
		// resource URL eagerly; no need to pass an explicit `prmPath` hint.
		return AuthplaneModule.forRootAsync({
			useFactory: () => options,
		});
	}

	/**
	 * Register the module with async options. Mirrors the standard NestJS
	 * async-module shape (`useFactory` / `useClass` / `useExisting`) so it
	 * composes naturally with `ConfigModule` and friends.
	 *
	 * `hints.prmPath` lets async-configured callers (e.g.
	 * `useFactory: (cfg: ConfigService) => …`) pre-declare where the PRM
	 * controller should be mounted. Without it, the module can only
	 * register the controller when `useFactory` is fully synchronous —
	 * any `Promise` return or non-empty `inject` array forces the user to
	 * mount the PRM document from their own handler.
	 */
	public static forRootAsync(
		asyncOptions: AuthplaneModuleAsyncOptions,
		hints: AuthplaneAsyncRegistrationHints = {},
	): DynamicModule {
		// Inspect synchronously-resolvable factories once at registration so
		// we can derive the PRM path AND reuse the captured options as a
		// `useValue` provider — invoking the caller's factory twice (once
		// here, once inside the DI container) would double-fire any side
		// effects in their config code.
		const syncCapture = inspectSyncFactory(asyncOptions);
		const optionsProvider = syncCapture
			? ({
					provide: AUTHPLANE_MODULE_OPTIONS,
					useValue: syncCapture.options,
				} satisfies Provider)
			: buildOptionsProvider(asyncOptions);

		const clientProvider: Provider = {
			provide: AUTHPLANE_CLIENT,
			inject: [AUTHPLANE_MODULE_OPTIONS],
			useFactory: (options: AuthplaneModuleOptions) =>
				buildAuthplaneClient(options),
		};

		const resourceProvider: Provider = {
			provide: AUTHPLANE_RESOURCE,
			inject: [AUTHPLANE_CLIENT, AUTHPLANE_MODULE_OPTIONS],
			useFactory: (
				client: AuthplaneClient,
				options: AuthplaneModuleOptions,
			): AuthplaneResource => client.resource(buildResourceOptions(options)),
		};

		// Keep the dedicated `AUTHPLANE_TOKEN_VERIFIER` token so tests can
		// override the verifier seam (`{ provide: AUTHPLANE_TOKEN_VERIFIER,
		// useValue: mockVerifier }`) without touching the resource provider.
		// The token resolves to the same `AuthplaneResource` instance — there
		// is no adapter-level wrapper any more; the guard calls
		// `verifier.verify()` directly on core.
		const tokenVerifierProvider: Provider = {
			provide: AUTHPLANE_TOKEN_VERIFIER,
			inject: [AUTHPLANE_RESOURCE],
			useFactory: (resource: AuthplaneResource): AuthplaneResource => resource,
		};

		const requestAdapterProvider: Provider = {
			provide: AUTHPLANE_REQUEST_ADAPTER,
			inject: [AUTHPLANE_MODULE_OPTIONS],
			useFactory: (options: AuthplaneModuleOptions): RequestAdapter =>
				options.requestAdapter ?? defaultRequestAdapter,
		};

		// Stage the PRM controller so NestJS sees a literal path string on
		// @Get. Caller-supplied `hints.prmPath` wins for async setups where
		// the resource URL is not knowable synchronously.
		const prmPath = hints.prmPath ?? syncCapture?.prmPath;
		const controllers = prmPath ? [buildPrmController(prmPath)] : [];
		if (controllers.length === 0) {
			// RFC 9728 discovery is required for many OAuth client flows; if
			// we drop the controller silently the operator only finds out
			// when a client fails to bootstrap. Route through Nest's Logger
			// so the message lands in the application's configured log sink
			// — `console.warn` would be suppressed by some PaaS log
			// pipelines.
			new Logger("AuthplaneModule").warn(
				"PRM controller not registered — RFC 9728 discovery is disabled. " +
					"Pass `hints.prmPath` to `forRootAsync` (or use `forRoot` with a synchronous factory) to expose the metadata document.",
			);
		}

		return {
			module: AuthplaneModule,
			imports: [...(asyncOptions.imports ?? [])],
			providers: [
				optionsProvider,
				clientProvider,
				resourceProvider,
				tokenVerifierProvider,
				requestAdapterProvider,
				AuthplaneShutdownHook,
				AuthplaneAuthGuard,
				AuthplaneExceptionFilter,
			],
			controllers,
			exports: [
				AUTHPLANE_CLIENT,
				AUTHPLANE_RESOURCE,
				AUTHPLANE_TOKEN_VERIFIER,
				AUTHPLANE_REQUEST_ADAPTER,
				AUTHPLANE_MODULE_OPTIONS,
				AuthplaneAuthGuard,
				AuthplaneExceptionFilter,
			],
		};
	}
}

// --- Internals ----------------------------------------------------------

function buildOptionsProvider(
	asyncOptions: AuthplaneModuleAsyncOptions,
): Provider {
	if (asyncOptions.useFactory) {
		return {
			provide: AUTHPLANE_MODULE_OPTIONS,
			inject: [...(asyncOptions.inject ?? [])],
			useFactory: asyncOptions.useFactory,
		};
	}
	if (asyncOptions.useClass) {
		return {
			provide: AUTHPLANE_MODULE_OPTIONS,
			inject: [asyncOptions.useClass],
			useFactory: (factory: AuthplaneOptionsFactory) =>
				factory.createAuthplaneOptions(),
		};
	}
	if (asyncOptions.useExisting) {
		return {
			provide: AUTHPLANE_MODULE_OPTIONS,
			inject: [asyncOptions.useExisting],
			useFactory: (factory: AuthplaneOptionsFactory) =>
				factory.createAuthplaneOptions(),
		};
	}
	throw new Error(
		"AuthplaneModule.forRootAsync requires useFactory, useClass, or useExisting.",
	);
}

interface SyncFactoryCapture {
	readonly options: AuthplaneModuleOptions;
	readonly prmPath: string | undefined;
}

/**
 * Invoke a synchronous `useFactory` once at module-registration time, both
 * to derive the PRM controller path AND to reuse the result as a
 * `useValue` provider so the DI container does not invoke the user's
 * factory a second time. Returns `undefined` for any factory that is not
 * trivially sync-resolvable here (no factory, injected dependencies,
 * Promise return, or factory threw) — those cases fall through to the
 * normal `buildOptionsProvider` path and the PRM controller is registered
 * only when `hints.prmPath` is supplied.
 *
 * Swallowing a thrown factory is deliberate: this registration-time call
 * is purely an optimisation, and the DI container will re-invoke the
 * factory itself, surfacing the same error through Nest's standard
 * bootstrap path with full provider context. A test pins this behaviour.
 */
function inspectSyncFactory(
	asyncOptions: AuthplaneModuleAsyncOptions,
): SyncFactoryCapture | undefined {
	if (!asyncOptions.useFactory || asyncOptions.inject?.length) {
		return undefined;
	}
	let result: ReturnType<typeof asyncOptions.useFactory>;
	try {
		result = asyncOptions.useFactory();
	} catch {
		return undefined;
	}
	if (result instanceof Promise) return undefined;
	const options = result as AuthplaneModuleOptions;
	let prmPath: string | undefined;
	const resource = options.resource;
	if (typeof resource === "string" && resource.length > 0) {
		try {
			prmPath = oauthProtectedResourceMetadataPath(resource);
		} catch {
			prmPath = undefined;
		}
	}
	return { options, prmPath };
}

async function buildAuthplaneClient(
	options: AuthplaneModuleOptions,
): Promise<AuthplaneClient> {
	const clientOptions: Parameters<typeof AuthplaneClient.create>[0] = {
		issuer: options.issuer,
	};
	// `auth` accepts a full AuthProvider (private_key_jwt, mTLS, custom) or
	// raw ASCredentials (which core wraps in ClientCredentialsProvider).
	// `auth` is the canonical knob; `asCredentials` is kept as a legacy
	// shortcut for the client-secret path. When both are set, `auth` wins.
	const auth = options.auth ?? options.asCredentials;
	if (auth !== undefined) {
		clientOptions.auth = auth;
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
	if (options.dpopProvider !== undefined) {
		clientOptions.dpopProvider = options.dpopProvider;
	}
	return AuthplaneClient.create(clientOptions);
}

function buildResourceOptions(
	options: AuthplaneModuleOptions,
): AuthplaneResourceOptions {
	const scopes = options.scopes ?? [];
	const resourceOptions: AuthplaneResourceOptions = {
		resource: options.resource,
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
	if (options.inboundDPoP !== undefined) {
		resourceOptions.inboundDPoP = options.inboundDPoP;
	}
	return resourceOptions;
}

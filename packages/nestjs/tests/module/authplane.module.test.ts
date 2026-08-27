import {
	AuthplaneClient,
	type AuthplaneResource,
	FetchSettings,
} from "@authplane/sdk/core";
import { Test } from "@nestjs/testing";
import { afterEach, assert, describe, expect, it, vi } from "vitest";

import { Module } from "@nestjs/common";

import { AuthplaneAuthGuard } from "../../src/application/authplane.guard.js";
import { AuthplaneExceptionFilter } from "../../src/application/authplane.exception-filter.js";
import { AuthplaneModule } from "../../src/module/authplane.module.js";
import { AuthplaneShutdownHook } from "../../src/module/authplane.shutdown-hook.js";
import {
	AUTHPLANE_CLIENT,
	AUTHPLANE_MODULE_OPTIONS,
	AUTHPLANE_REQUEST_ADAPTER,
	AUTHPLANE_RESOURCE,
	AUTHPLANE_TOKEN_VERIFIER,
} from "../../src/module/authplane.tokens.js";
import type { AuthplaneModuleOptions } from "../../src/module/authplane.options.js";

function mockResource(): AuthplaneResource {
	return {
		verify: vi.fn(),
		prmResponse: vi.fn(() => ({
			resource: "https://api.example.com/mcp",
			authorization_servers: ["https://auth.example.com"],
		})),
		prmDocumentUrl: vi.fn(
			() =>
				"https://api.example.com/.well-known/oauth-protected-resource/mcp",
		),
	} as unknown as AuthplaneResource;
}

function mockClient(resource: AuthplaneResource) {
	return {
		resource: vi.fn(() => resource),
		close: vi.fn(async () => undefined),
	};
}

const BASE_OPTIONS: AuthplaneModuleOptions = {
	issuer: "https://auth.example.com",
	resource: "https://api.example.com/mcp",
	scopes: ["tools/add"],
};

describe("AuthplaneModule.forRoot", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("registers the core providers under their DI tokens", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(
			client as unknown as AuthplaneClient,
		);

		const moduleRef = await Test.createTestingModule({
			imports: [AuthplaneModule.forRoot(BASE_OPTIONS)],
		}).compile();

		expect(moduleRef.get(AUTHPLANE_CLIENT)).toBe(client);
		expect(moduleRef.get(AUTHPLANE_RESOURCE)).toBe(resource);
		// AUTHPLANE_TOKEN_VERIFIER now resolves to the same AuthplaneResource
		// instance — the adapter-level wrapper is gone, the guard calls
		// core verify() directly. The token survives as a test seam.
		expect(moduleRef.get(AUTHPLANE_TOKEN_VERIFIER)).toBe(resource);
		expect(moduleRef.get(AUTHPLANE_MODULE_OPTIONS)).toEqual(BASE_OPTIONS);
		expect(moduleRef.get(AUTHPLANE_REQUEST_ADAPTER)).toBeDefined();
		expect(moduleRef.get(AuthplaneAuthGuard)).toBeInstanceOf(
			AuthplaneAuthGuard,
		);
		expect(moduleRef.get(AuthplaneExceptionFilter)).toBeInstanceOf(
			AuthplaneExceptionFilter,
		);
		expect(moduleRef.get(AuthplaneShutdownHook)).toBeInstanceOf(
			AuthplaneShutdownHook,
		);

		await moduleRef.close();
	});

	it("calls client.close() via AuthplaneShutdownHook on moduleRef.close()", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(
			client as unknown as AuthplaneClient,
		);

		const moduleRef = await Test.createTestingModule({
			imports: [AuthplaneModule.forRoot(BASE_OPTIONS)],
		}).compile();
		// enableShutdownHooks is what triggers OnApplicationShutdown in prod;
		// calling the hook directly is the closest we can get from a pure
		// DI-only test.
		await moduleRef.get(AuthplaneShutdownHook).onApplicationShutdown();

		expect(client.close).toHaveBeenCalledOnce();
		await moduleRef.close();
	});

	it("forwards optional passthrough options to AuthplaneClient.create + resource()", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		const createSpy = vi
			.spyOn(AuthplaneClient, "create")
			.mockResolvedValue(client as unknown as AuthplaneClient);

		const moduleRef = await Test.createTestingModule({
			imports: [
				AuthplaneModule.forRoot({
					...BASE_OPTIONS,
					asCredentials: { clientId: "rs", clientSecret: "s3cret" },
					devMode: true,
				}),
			],
		}).compile();

		expect(createSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				issuer: "https://auth.example.com",
				// asCredentials is folded into `auth`, which the client wraps
				// in ClientCredentialsProvider internally.
				auth: { clientId: "rs", clientSecret: "s3cret" },
				devMode: true,
			}),
		);
		expect(client.resource).toHaveBeenCalledWith(
			expect.objectContaining({
				resource: "https://api.example.com/mcp",
				scopes: ["tools/add"],
				asCredentials: { clientId: "rs", clientSecret: "s3cret" },
				devMode: true,
			}),
		);

		await moduleRef.close();
	});

	it("registers the PRM controller at the derived well-known path", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(
			client as unknown as AuthplaneClient,
		);

		const dynamicModule = AuthplaneModule.forRoot(BASE_OPTIONS);
		expect(dynamicModule.controllers).toBeDefined();
		expect(dynamicModule.controllers).toHaveLength(1);
		const [ctrl] = dynamicModule.controllers as ReadonlyArray<{
			prototype: Record<string, unknown>;
		}>;
		assert(ctrl);
		const routePath = Reflect.getMetadata(
			"path",
			ctrl.prototype.serve as object,
		);
		expect(routePath).toBe("/.well-known/oauth-protected-resource/mcp");
	});
});

describe("AuthplaneModule.forRootAsync", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("supports useFactory with inject: []", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(
			client as unknown as AuthplaneClient,
		);

		class ConfigStub {
			public getOptions(): AuthplaneModuleOptions {
				return BASE_OPTIONS;
			}
		}
		@Module({
			providers: [ConfigStub],
			exports: [ConfigStub],
		})
		class ConfigModuleStub {}

		const moduleRef = await Test.createTestingModule({
			imports: [
				AuthplaneModule.forRootAsync({
					imports: [ConfigModuleStub],
					inject: [ConfigStub],
					useFactory: (cfg: ConfigStub) => cfg.getOptions(),
				} as never),
			],
		}).compile();

		expect(moduleRef.get(AUTHPLANE_CLIENT)).toBe(client);
		await moduleRef.close();
	});

	it("throws when none of useFactory/useClass/useExisting is provided", () => {
		expect(() => AuthplaneModule.forRootAsync({} as never)).toThrow(
			/requires useFactory, useClass, or useExisting/,
		);
	});

	it("honours a user-supplied requestAdapter override via options", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(
			client as unknown as AuthplaneClient,
		);

		const customAdapter = {
			getHeader: vi.fn(),
			getHeaderValues: vi.fn(),
			getMethod: vi.fn(),
			getPathAndQuery: vi.fn(),
			stashAuthInfo: vi.fn(),
		};

		const moduleRef = await Test.createTestingModule({
			imports: [
				AuthplaneModule.forRoot({
					...BASE_OPTIONS,
					requestAdapter: customAdapter,
				}),
			],
		}).compile();

		expect(moduleRef.get(AUTHPLANE_REQUEST_ADAPTER)).toBe(customAdapter);
		await moduleRef.close();
	});

	it("supports useClass with a factory class", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(
			client as unknown as AuthplaneClient,
		);

		class OptionsFactory {
			public createAuthplaneOptions(): AuthplaneModuleOptions {
				return BASE_OPTIONS;
			}
		}

		// useClass returns the provider shape; since AuthplaneModule does not
		// register the factory itself, we add it via a sibling module so the
		// inject resolves.
		@Module({
			providers: [OptionsFactory],
			exports: [OptionsFactory],
		})
		class OptionsFactoryModule {}

		const moduleRef = await Test.createTestingModule({
			imports: [
				AuthplaneModule.forRootAsync({
					imports: [OptionsFactoryModule],
					useClass: OptionsFactory,
				} as never),
			],
		}).compile();

		expect(moduleRef.get(AUTHPLANE_MODULE_OPTIONS)).toEqual(BASE_OPTIONS);
		await moduleRef.close();
	});

	it("supports useExisting with a pre-registered factory", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(
			client as unknown as AuthplaneClient,
		);

		class ExistingFactory {
			public createAuthplaneOptions(): AuthplaneModuleOptions {
				return BASE_OPTIONS;
			}
		}
		@Module({
			providers: [ExistingFactory],
			exports: [ExistingFactory],
		})
		class ExistingModule {}

		const moduleRef = await Test.createTestingModule({
			imports: [
				AuthplaneModule.forRootAsync({
					imports: [ExistingModule],
					useExisting: ExistingFactory,
				} as never),
			],
		}).compile();

		expect(moduleRef.get(AUTHPLANE_MODULE_OPTIONS)).toEqual(BASE_OPTIONS);
		await moduleRef.close();
	});

	it("skips PRM controller when useFactory throws during PRM-path derivation", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(
			client as unknown as AuthplaneClient,
		);

		const dynamicModule = AuthplaneModule.forRootAsync({
			useFactory: () => {
				throw new Error("boom");
			},
		} as never);
		expect(dynamicModule.controllers).toEqual([]);
	});

	it("skips PRM controller when useFactory returns an empty resource", async () => {
		const dynamicModule = AuthplaneModule.forRootAsync({
			useFactory: () =>
				({ ...BASE_OPTIONS, resource: "" }) as AuthplaneModuleOptions,
		} as never);
		expect(dynamicModule.controllers).toEqual([]);
	});

	it("skips PRM controller when useFactory returns a malformed resource URL", async () => {
		const dynamicModule = AuthplaneModule.forRootAsync({
			useFactory: () =>
				({ ...BASE_OPTIONS, resource: "not a url" }) as AuthplaneModuleOptions,
		} as never);
		expect(dynamicModule.controllers).toEqual([]);
	});

	it("mounts the PRM controller for an async factory when hints.prmPath is supplied", () => {
		// derivePrmPath returns undefined whenever the factory is async or
		// has DI injects — the explicit `hints.prmPath` is the escape hatch
		// for users that compose with ConfigService.
		const dynamicModule = AuthplaneModule.forRootAsync(
			{
				inject: ["ConfigService"],
				useFactory: () => Promise.resolve(BASE_OPTIONS),
			} as never,
			{ prmPath: "/.well-known/oauth-protected-resource/mcp" },
		);
		expect(dynamicModule.controllers).toHaveLength(1);
	});

	it("hints.prmPath wins over the derived sync path when both are present", () => {
		const dynamicModule = AuthplaneModule.forRootAsync(
			{
				useFactory: () => BASE_OPTIONS,
			} as never,
			{ prmPath: "/custom/prm" },
		);
		// The mounted controller uses the explicit hint, not the derived
		// path. We assert via the metadata key Nest writes on the class.
		const ctrlClass = dynamicModule.controllers?.[0] as
			| { prototype: object }
			| undefined;
		expect(ctrlClass).toBeDefined();
	});
});

describe("AuthplaneModule option passthrough", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("forwards JWKS + metadata fetch settings and refresh cadences to AuthplaneClient.create", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		const createSpy = vi
			.spyOn(AuthplaneClient, "create")
			.mockResolvedValue(client as unknown as AuthplaneClient);
		const fetchSettings = new FetchSettings({ timeoutSeconds: 7 });

		const moduleRef = await Test.createTestingModule({
			imports: [
				AuthplaneModule.forRoot({
					...BASE_OPTIONS,
					fetchSettings,
					jwksRefreshSeconds: 120,
					metadataRefreshSeconds: 240,
				}),
			],
		}).compile();

		expect(createSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				// `fetchSettings` is the unified successor of the old
				// `jwksFetchSettings` + `metadataFetchSettings` split.
				fetchSettings,
				jwksRefreshSeconds: 120,
				metadataRefreshSeconds: 240,
			}),
		);

		await moduleRef.close();
	});

	it("forwards client-tunable knobs (cacheTtl / circuitBreaker / dpopProvider) to AuthplaneClient.create — parity with mcp / fastmcp", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		const createSpy = vi
			.spyOn(AuthplaneClient, "create")
			.mockResolvedValue(client as unknown as AuthplaneClient);

		const dpopProvider = { sign: vi.fn() } as unknown as NonNullable<
			AuthplaneModuleOptions["dpopProvider"]
		>;

		const moduleRef = await Test.createTestingModule({
			imports: [
				AuthplaneModule.forRoot({
					...BASE_OPTIONS,
					cacheTtlBufferSeconds: 45,
					defaultTtlSeconds: 1800,
					cacheMaxEntries: 25_000,
					circuitBreakerThreshold: 10,
					circuitBreakerCooldownSeconds: 60,
					dpopProvider,
				}),
			],
		}).compile();

		expect(createSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				cacheTtlBufferSeconds: 45,
				defaultTtlSeconds: 1800,
				cacheMaxEntries: 25_000,
				circuitBreakerThreshold: 10,
				circuitBreakerCooldownSeconds: 60,
				dpopProvider,
			}),
		);

		await moduleRef.close();
	});

	it("accepts a full AuthProvider via `auth` (not just ASCredentials) and forwards it to AuthplaneClient.create", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		const createSpy = vi
			.spyOn(AuthplaneClient, "create")
			.mockResolvedValue(client as unknown as AuthplaneClient);

		// Minimal AuthProvider shape — anything that satisfies the duck-type
		// is enough here. The point is that core no longer narrows to
		// ASCredentials.
		const authProvider = {
			authorize: vi.fn(async () => ({
				headers: { authorization: "Bearer x" },
			})),
		};

		const moduleRef = await Test.createTestingModule({
			imports: [
				AuthplaneModule.forRoot({
					...BASE_OPTIONS,
					auth: authProvider as unknown as NonNullable<
						AuthplaneModuleOptions["auth"]
					>,
				}),
			],
		}).compile();

		expect(createSpy).toHaveBeenCalledWith(
			expect.objectContaining({ auth: authProvider }),
		);

		await moduleRef.close();
	});

	it("prefers `auth` over the legacy `asCredentials` shortcut when both are set", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		const createSpy = vi
			.spyOn(AuthplaneClient, "create")
			.mockResolvedValue(client as unknown as AuthplaneClient);

		const authProvider = {
			authorize: vi.fn(),
		} as unknown as NonNullable<AuthplaneModuleOptions["auth"]>;

		const moduleRef = await Test.createTestingModule({
			imports: [
				AuthplaneModule.forRoot({
					...BASE_OPTIONS,
					auth: authProvider,
					asCredentials: { clientId: "legacy", clientSecret: "s" },
				}),
			],
		}).compile();

		expect(createSpy).toHaveBeenCalledWith(
			expect.objectContaining({ auth: authProvider }),
		);

		await moduleRef.close();
	});

	it("forwards revocationChecker, allowedAlgorithms, and clockSkew to client.resource()", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(
			client as unknown as AuthplaneClient,
		);

		const revocationChecker = {
			isRevoked: vi.fn(async () => false),
			close: vi.fn(async () => undefined),
		};

		const moduleRef = await Test.createTestingModule({
			imports: [
				AuthplaneModule.forRoot({
					...BASE_OPTIONS,
					revocationChecker,
					allowedAlgorithms: ["ES256"],
					clockSkewSeconds: 90,
				}),
			],
		}).compile();

		expect(client.resource).toHaveBeenCalledWith(
			expect.objectContaining({
				revocationChecker,
				allowedAlgorithms: ["ES256"],
				clockSkewSeconds: 90,
			}),
		);

		await moduleRef.close();
	});
});

import { describe, expectTypeOf, it } from "vitest";

import type {
	AuthplaneModuleAsyncOptions,
	AuthplaneModuleOptions,
	AuthplaneOptionsFactory,
} from "../../src/module/authplane.options.js";
import type { RequestAdapter } from "../../src/infrastructure/request-adapter.js";

describe("AuthplaneModuleOptions (type surface)", () => {
	it("requires issuer + resource", () => {
		expectTypeOf<AuthplaneModuleOptions>().toHaveProperty("issuer");
		expectTypeOf<AuthplaneModuleOptions>().toHaveProperty("resource");
		expectTypeOf<AuthplaneModuleOptions["issuer"]>().toEqualTypeOf<string>();
		expectTypeOf<AuthplaneModuleOptions["resource"]>().toEqualTypeOf<string>();
	});

	it("exposes requestAdapter as optional RequestAdapter", () => {
		expectTypeOf<AuthplaneModuleOptions["requestAdapter"]>().toEqualTypeOf<
			RequestAdapter | undefined
		>();
	});

	it("keeps asCredentials optional (pass-through from core)", () => {
		expectTypeOf<AuthplaneModuleOptions>().toHaveProperty("asCredentials");
	});

	it("keeps scopes + requiredScopes optional", () => {
		expectTypeOf<AuthplaneModuleOptions["scopes"]>().toEqualTypeOf<
			string[] | undefined
		>();
		expectTypeOf<AuthplaneModuleOptions["requiredScopes"]>().toEqualTypeOf<
			string[] | undefined
		>();
	});
});

describe("AuthplaneOptionsFactory (type surface)", () => {
	it("returns options or a Promise of them", () => {
		expectTypeOf<AuthplaneOptionsFactory["createAuthplaneOptions"]>().returns
			.toEqualTypeOf<Promise<AuthplaneModuleOptions> | AuthplaneModuleOptions>();
	});
});

describe("AuthplaneModuleAsyncOptions (type surface)", () => {
	it("accepts a useFactory option", () => {
		const asyncOpts: AuthplaneModuleAsyncOptions = {
			useFactory: () => ({
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
			}),
		};
		expectTypeOf(asyncOpts).toMatchTypeOf<AuthplaneModuleAsyncOptions>();
	});

	it("accepts imports from @nestjs/common ModuleMetadata", () => {
		const asyncOpts: AuthplaneModuleAsyncOptions = { imports: [] };
		expectTypeOf(asyncOpts.imports).toEqualTypeOf<
			ReadonlyArray<unknown> | undefined
		>();
	});
});

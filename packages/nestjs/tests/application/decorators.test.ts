import type { ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { VerifiedClaims } from "@authplane/sdk/core";
import { describe, expect, it } from "vitest";

import {
	AuthInfo,
	RequireScopes,
	SkipAuth,
} from "../../src/application/decorators.js";
import {
	METADATA_KEY_REQUIRED_SCOPES,
	METADATA_KEY_SKIP_AUTH,
} from "../../src/application/metadata-keys.js";
import { AUTH_INFO_REQUEST_KEY } from "../../src/infrastructure/request-adapter.js";

function buildClaims(): VerifiedClaims {
	return new VerifiedClaims({
		sub: "s",
		clientId: "c",
		scopes: [],
		issuer: "https://auth.example.com",
		audience: ["https://api.example.com/mcp"],
		expiresAt: 0,
		issuedAt: 0,
		jti: "j",
		kid: "k",
		agentId: "",
		agentChain: [],
		notBefore: 0,
		raw: {},
	});
}

describe("@RequireScopes", () => {
	it("stores the supplied scopes under METADATA_KEY_REQUIRED_SCOPES on a method", () => {
		class MathController {
			@RequireScopes("tools/add", "tools/multiply")
			public add(): void {}
		}

		const meta = Reflect.getMetadata(
			METADATA_KEY_REQUIRED_SCOPES,
			MathController.prototype.add,
		);
		expect(meta).toEqual(["tools/add", "tools/multiply"]);
	});

	it("stacks class-level and method-level metadata via Reflector.getAllAndMerge", () => {
		@RequireScopes("tools/base")
		class MathController {
			@RequireScopes("tools/add")
			public add(): void {}
		}

		const reflector = new Reflector();
		const merged = reflector.getAllAndMerge<string[]>(
			METADATA_KEY_REQUIRED_SCOPES,
			[MathController.prototype.add, MathController],
		);
		expect(merged).toEqual(
			expect.arrayContaining(["tools/base", "tools/add"]),
		);
	});

	it("accepts zero scopes without throwing", () => {
		class MathController {
			@RequireScopes()
			public noop(): void {}
		}
		const meta = Reflect.getMetadata(
			METADATA_KEY_REQUIRED_SCOPES,
			MathController.prototype.noop,
		);
		expect(meta).toEqual([]);
	});
});

describe("@AuthInfo", () => {
	it("is exported as a param decorator (factory returning a ParameterDecorator)", () => {
		const decoratorFactory = AuthInfo;
		expect(typeof decoratorFactory).toBe("function");
		const decorator = decoratorFactory();
		expect(typeof decorator).toBe("function");
	});

	it("exposes an internal extractor that reads the stashed claims from the request", () => {
		const claims = buildClaims();
		const req: Record<symbol, unknown> = {};
		req[AUTH_INFO_REQUEST_KEY] = claims;
		const ctx = {
			switchToHttp: () => ({ getRequest: () => req }),
		} as unknown as ExecutionContext;

		const extractor = (
			AuthInfo as unknown as {
				__authplaneExtractor: (
					data: unknown,
					ctx: ExecutionContext,
				) => unknown;
			}
		).__authplaneExtractor;
		expect(extractor(undefined, ctx)).toBe(claims);
	});

	it("returns undefined when no auth info has been stashed", () => {
		const req: Record<symbol, unknown> = {};
		const ctx = {
			switchToHttp: () => ({ getRequest: () => req }),
		} as unknown as ExecutionContext;
		const extractor = (
			AuthInfo as unknown as {
				__authplaneExtractor: (
					data: unknown,
					ctx: ExecutionContext,
				) => unknown;
			}
		).__authplaneExtractor;
		expect(extractor(undefined, ctx)).toBeUndefined();
	});

	it("returns undefined when getRequest() returns null (defensive)", () => {
		const ctx = {
			switchToHttp: () => ({ getRequest: () => null }),
		} as unknown as ExecutionContext;
		const extractor = (
			AuthInfo as unknown as {
				__authplaneExtractor: (
					data: unknown,
					ctx: ExecutionContext,
				) => unknown;
			}
		).__authplaneExtractor;
		expect(extractor(undefined, ctx)).toBeUndefined();
	});
});

describe("@SkipAuth", () => {
	it("marks the handler as public under METADATA_KEY_SKIP_AUTH", () => {
		class HealthController {
			@SkipAuth()
			public ping(): void {}
		}

		const meta = Reflect.getMetadata(
			METADATA_KEY_SKIP_AUTH,
			HealthController.prototype.ping,
		);
		expect(meta).toBe(true);
	});

	it("also works at the class level and is visible via Reflector.getAllAndOverride", () => {
		@SkipAuth()
		class PublicController {
			public one(): void {}
		}

		const reflector = new Reflector();
		const flag = reflector.getAllAndOverride<boolean>(METADATA_KEY_SKIP_AUTH, [
			PublicController.prototype.one,
			PublicController,
		]);
		expect(flag).toBe(true);
	});
});

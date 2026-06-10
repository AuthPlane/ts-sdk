import type { ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import {
	type AuthplaneResource,
	InsufficientScope,
	MultipleDPoPProofs,
	TokenMissing,
	VerifiedClaims,
} from "@authplane/sdk/core";
import { describe, expect, it, vi } from "vitest";

import { AuthplaneAuthGuard } from "../../src/application/authplane.guard.js";
import { METADATA_KEY_REQUIRED_SCOPES } from "../../src/application/metadata-keys.js";
import {
	AUTH_INFO_REQUEST_KEY,
	defaultRequestAdapter,
} from "../../src/infrastructure/request-adapter.js";
import type { AuthplaneModuleOptions } from "../../src/module/authplane.options.js";

function buildClaims(
	overrides: Partial<ConstructorParameters<typeof VerifiedClaims>[0]> = {},
): VerifiedClaims {
	return new VerifiedClaims({
		sub: "user_1",
		clientId: "client_1",
		scopes: ["tools/add"],
		issuer: "https://auth.example.com",
		audience: ["https://api.example.com/mcp"],
		expiresAt: Math.floor(Date.now() / 1000) + 60,
		issuedAt: Math.floor(Date.now() / 1000) - 60,
		jti: "jti-1",
		kid: "kid-1",
		agentId: "",
		agentChain: [],
		notBefore: 0,
		raw: {},
		...overrides,
	});
}

function expressReq(overrides: Record<string, unknown> = {}) {
	return {
		method: "POST",
		originalUrl: "/mcp",
		headers: {
			host: "api.example.com",
			authorization: "Bearer abc",
		},
		...overrides,
	};
}

function makeContext(
	req: unknown,
	handler: (...args: readonly unknown[]) => unknown = () => undefined,
	cls: object = class {},
): ExecutionContext {
	return {
		switchToHttp: () => ({
			getRequest: () => req,
			getResponse: () => ({}),
			getNext: () => undefined,
		}),
		getHandler: () => handler,
		getClass: () => cls,
	} as unknown as ExecutionContext;
}

function buildGuard(params: {
	readonly verifier: AuthplaneResource;
	readonly options: AuthplaneModuleOptions;
	readonly reflector?: Reflector;
}): AuthplaneAuthGuard {
	const reflector = params.reflector ?? new Reflector();
	return new AuthplaneAuthGuard(
		params.verifier,
		params.options,
		defaultRequestAdapter,
		reflector,
	);
}

describe("AuthplaneAuthGuard", () => {
	it("throws core TokenMissing when the Authorization header is missing", async () => {
		const verifier = { verify: vi.fn() } as unknown as AuthplaneResource;
		const guard = buildGuard({
			verifier,
			options: {
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
			},
		});
		const ctx = makeContext(expressReq({ headers: {} }));

		await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(TokenMissing);
		expect(verifier.verify).not.toHaveBeenCalled();
	});

	it("stashes verified claims on the request and returns true", async () => {
		const claims = buildClaims();
		const verifier = {
			verify: vi.fn(async () => claims),
		} as unknown as AuthplaneResource;
		const guard = buildGuard({
			verifier,
			options: {
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
			},
		});
		const req = expressReq();
		const ctx = makeContext(req);

		await expect(guard.canActivate(ctx)).resolves.toBe(true);
		expect(verifier.verify).toHaveBeenCalledWith("abc", {
			dpopRequest: undefined,
		});
		expect((req as Record<symbol, unknown>)[AUTH_INFO_REQUEST_KEY]).toBe(
			claims,
		);
	});

	it("enforces module-level requiredScopes (core InsufficientScope)", async () => {
		const claims = buildClaims({ scopes: ["tools/read"] });
		const verifier = {
			verify: vi.fn(async () => claims),
		} as unknown as AuthplaneResource;
		const guard = buildGuard({
			verifier,
			options: {
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
				requiredScopes: ["tools/write"],
			},
		});

		await expect(
			guard.canActivate(makeContext(expressReq())),
		).rejects.toBeInstanceOf(InsufficientScope);
	});

	it("defaults requiredScopes to options.scopes when not provided", async () => {
		const claims = buildClaims({ scopes: ["tools/read"] });
		const verifier = {
			verify: vi.fn(async () => claims),
		} as unknown as AuthplaneResource;
		const guard = buildGuard({
			verifier,
			options: {
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
				scopes: ["tools/write"],
			},
		});

		await expect(
			guard.canActivate(makeContext(expressReq())),
		).rejects.toBeInstanceOf(InsufficientScope);
	});

	it("treats requiredScopes: [] as 'enforce nothing' even when scopes is non-empty", async () => {
		const claims = buildClaims({ scopes: ["tools/read"] });
		const verifier = {
			verify: vi.fn(async () => claims),
		} as unknown as AuthplaneResource;
		const guard = buildGuard({
			verifier,
			options: {
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
				scopes: ["tools/write"],
				requiredScopes: [],
			},
		});

		await expect(
			guard.canActivate(makeContext(expressReq())),
		).resolves.toBe(true);
	});

	it("enforces route-level @RequireScopes via Reflector", async () => {
		const claims = buildClaims({ scopes: ["tools/add"] });
		const verifier = {
			verify: vi.fn(async () => claims),
		} as unknown as AuthplaneResource;
		const reflector = {
			getAllAndOverride: vi.fn(() => undefined),
			getAllAndMerge: vi.fn(() => ["tools/add", "tools/admin"]),
		} as unknown as Reflector;
		const guard = buildGuard({
			verifier,
			options: {
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
			},
			reflector,
		});

		await expect(
			guard.canActivate(makeContext(expressReq())),
		).rejects.toBeInstanceOf(InsufficientScope);
		expect(reflector.getAllAndMerge).toHaveBeenCalledWith(
			METADATA_KEY_REQUIRED_SCOPES,
			expect.any(Array),
		);
	});

	it("threads the DPoP proof through to verify() on every request that carries one", async () => {
		const claims = buildClaims();
		const verifier = {
			verify: vi.fn(async () => claims),
		} as unknown as AuthplaneResource;
		const guard = buildGuard({
			verifier,
			options: {
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
			},
		});
		const req = expressReq({
			headers: {
				host: "api.example.com",
				authorization: "Bearer abc",
				dpop: "proof-value",
			},
		});

		await guard.canActivate(makeContext(req));

		expect(verifier.verify).toHaveBeenCalledWith("abc", {
			dpopRequest: expect.objectContaining({
				method: "POST",
				url: "https://api.example.com/mcp",
				proofs: ["proof-value"],
			}),
		});
	});

	it("pins the DPoP htu to the configured resource — ignores Host / X-Forwarded-* spoofing", async () => {
		const claims = buildClaims();
		const verifier = {
			verify: vi.fn(async () => claims),
		} as unknown as AuthplaneResource;
		const guard = buildGuard({
			verifier,
			options: {
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
			},
		});
		const req = expressReq({
			headers: {
				host: "evil.example.com",
				"x-forwarded-host": "spoofed.example.com",
				"x-forwarded-proto": "http",
				authorization: "Bearer abc",
				dpop: "proof-value",
			},
			originalUrl: "/mcp/tools/call?id=42",
		});

		await guard.canActivate(makeContext(req));

		expect(verifier.verify).toHaveBeenCalledWith("abc", {
			dpopRequest: expect.objectContaining({
				method: "POST",
				url: "https://api.example.com/mcp/tools/call?id=42",
				proofs: ["proof-value"],
			}),
		});
	});

	it("rejects requests carrying two DPoP headers without invoking the verifier (RFC 9449 §4.3)", async () => {
		// `http.IncomingMessage.headers` (the bag Express surfaces as
		// `req.headers`) comma-folds duplicate same-name values for
		// everything outside Node's fixed allow-list — so two `DPoP`
		// headers on the wire arrive as the single string
		// `"proofA, proofB"`. The `buildDPoPRequestContext` factory
		// splits on `,` (JWS compact serialisation never contains a
		// literal `,`, so any comma is a merged duplicate) and raises
		// `MultipleDPoPProofs`. The exception filter routes that
		// `AuthplaneError` through `wwwAuthenticate()`; the verifier
		// MUST NOT run for a request the spec already requires us to
		// reject. The string[] shape — landing in `req.headers` only
		// when callers reach for `req.rawHeaders` or hand-build the
		// bag — is covered separately in the request-adapter tests.
		const verifier = { verify: vi.fn() } as unknown as AuthplaneResource;
		const guard = buildGuard({
			verifier,
			options: {
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
			},
		});
		const req = expressReq({
			headers: {
				host: "api.example.com",
				authorization: "Bearer abc",
				dpop: "eyJ.first, eyJ.second",
			},
		});

		await expect(guard.canActivate(makeContext(req))).rejects.toBeInstanceOf(
			MultipleDPoPProofs,
		);
		expect(verifier.verify).not.toHaveBeenCalled();
	});

	it("short-circuits with true when @SkipAuth is set on the handler", async () => {
		const verifier = { verify: vi.fn() } as unknown as AuthplaneResource;
		const reflector = {
			getAllAndOverride: vi.fn((key: string) =>
				key === "authplane:skipAuth" ? true : undefined,
			),
			getAllAndMerge: vi.fn(() => []),
		} as unknown as Reflector;
		const guard = buildGuard({
			verifier,
			options: {
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
			},
			reflector,
		});

		await expect(
			guard.canActivate(makeContext(expressReq({ headers: {} }))),
		).resolves.toBe(true);
		expect(verifier.verify).not.toHaveBeenCalled();
	});
});

describe("AuthplaneAuthGuard — constructor validation", () => {
	it("throws TypeError with the inner URL failure on .cause when 'resource' is not an absolute URL", () => {
		const verifier = { verify: vi.fn() } as unknown as AuthplaneResource;
		let thrown: unknown;
		try {
			buildGuard({
				verifier,
				options: {
					issuer: "https://auth.example.com",
					resource: "not-a-url",
				},
			});
		} catch (err) {
			thrown = err;
		}
		expect(thrown).toBeInstanceOf(TypeError);
		expect((thrown as Error).message).toContain(
			"AuthplaneModule: 'resource' must be an absolute URL",
		);
		expect((thrown as Error).message).toContain('"not-a-url"');
		// `cause` carries the raw `new URL()` failure so a debugger can chain
		// to the underlying parse error.
		expect((thrown as Error & { cause?: unknown }).cause).toBeInstanceOf(
			Error,
		);
	});
});

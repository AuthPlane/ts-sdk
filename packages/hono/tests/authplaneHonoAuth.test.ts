import {
	AuthplaneClient,
	type AuthplaneResource,
	type DPoPReplayStore,
	VerifiedClaims,
} from "@authplane/sdk/core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { authplaneHonoAuth } from "../src/authplaneHonoAuth.js";

function buildClaims(
	overrides: Partial<ConstructorParameters<typeof VerifiedClaims>[0]> = {},
): VerifiedClaims {
	return new VerifiedClaims({
		sub: "u",
		clientId: "c",
		scopes: [],
		issuer: "https://auth.example.com",
		audience: ["https://api.example.com/mcp"],
		expiresAt: Math.floor(Date.now() / 1000) + 3_600,
		issuedAt: Math.floor(Date.now() / 1000),
		jti: "j",
		kid: "k",
		agentId: "",
		agentChain: [],
		notBefore: 0,
		raw: {},
		...overrides,
	});
}

function mockResource(
	overrides: Partial<{
		prmDocumentUrl: string;
		prmResponse: Record<string, unknown>;
		verify: ReturnType<typeof vi.fn>;
	}> = {},
): AuthplaneResource {
	const url =
		overrides.prmDocumentUrl ??
		"https://api.example.com/.well-known/oauth-protected-resource/mcp";
	const prm = overrides.prmResponse ?? {
		resource: "https://api.example.com/mcp",
		authorization_servers: ["https://auth.example.com"],
		scopes_supported: ["tools/add"],
		bearer_methods_supported: ["header"],
	};
	return {
		verify: overrides.verify ?? vi.fn(async () => buildClaims()),
		prmResponse: vi.fn(() => prm),
		prmDocumentUrl: vi.fn(() => url),
	} as unknown as AuthplaneResource;
}

function mockClient(resource: AuthplaneResource): AuthplaneClient {
	return {
		resource: vi.fn(() => resource),
	} as unknown as AuthplaneClient;
}

describe("authplaneHonoAuth", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("returns the core verifier, bearerAuth, PRM wiring, and the underlying client", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);

		const result = await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: ["tools/add"],
			requiredScopes: ["tools/add"],
		});

		expect(result.client).toBe(client);
		expect(result.verifier).toBe(resource);
		expect(typeof result.bearerAuth).toBe("function");
		expect(result.protectedResourceMetadataPath).toBe(
			"/.well-known/oauth-protected-resource/mcp",
		);
		expect(result.protectedResourceMetadata).toEqual({
			resource: "https://api.example.com/mcp",
			authorization_servers: ["https://auth.example.com"],
			scopes_supported: ["tools/add"],
			bearer_methods_supported: ["header"],
		});
		expect(typeof result.protectedResourceMetadataHandler).toBe("function");
	});

	it("forwards issuer + asCredentials (via `auth`) to AuthplaneClient.create", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		const createSpy = vi
			.spyOn(AuthplaneClient, "create")
			.mockResolvedValue(client);

		await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			asCredentials: { clientId: "id", clientSecret: "s3cret" },
		});

		expect(createSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				issuer: "https://auth.example.com",
				auth: { clientId: "id", clientSecret: "s3cret" },
			}),
		);
	});

	it("forwards resource config (scopes, revocationChecker) to client.resource()", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);

		await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: ["tools/add"],
			revocationChecker: { clientId: "my-rs", clientSecret: "s" },
		});

		expect(client.resource).toHaveBeenCalledWith(
			expect.objectContaining({
				resource: "https://api.example.com/mcp",
				scopes: ["tools/add"],
				revocationChecker: { clientId: "my-rs", clientSecret: "s" },
			}),
		);
	});

	it("defaults requiredScopes to scopes when not provided", async () => {
		const resource = mockResource({
			verify: vi.fn(async () => buildClaims({ scopes: ["tools/other"] })),
		});
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);

		const { bearerAuth } = await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: ["tools/add"],
		});

		const { Hono } = await import("hono");
		const app = new Hono();
		app.use("/mcp", bearerAuth);
		app.post("/mcp", (c) => c.json({ ok: true }));

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(403);
		expect(response.headers.get("WWW-Authenticate")).toContain(
			'scope="tools/add"',
		);
	});

	it("folds the convenience `replayStore` into `inboundDPoP` and threads DPoP through verify", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);
		const verifyMock = resource.verify as ReturnType<typeof vi.fn>;

		const replayStore = {
			checkAndStore: vi.fn(async () => true),
		} as unknown as DPoPReplayStore;

		const { bearerAuth } = await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			replayStore,
		});

		expect(client.resource).toHaveBeenCalledWith(
			expect.objectContaining({
				inboundDPoP: { replayStore },
			}),
		);

		const { Hono } = await import("hono");
		const app = new Hono();
		app.use("/mcp", bearerAuth);
		app.post("/mcp", (c) => c.json({ ok: true }));

		await app.request("http://api.example.com/mcp", {
			method: "POST",
			headers: {
				Authorization: "Bearer valid_jwt",
				DPoP: "eyJ.proof.value",
			},
		});

		expect(verifyMock).toHaveBeenCalledWith("valid_jwt", {
			dpopRequest: expect.objectContaining({
				method: "POST",
				url: "https://api.example.com/mcp",
				proofs: ["eyJ.proof.value"],
			}),
		});
	});

	it("forwards every optional passthrough field to client + resource factories", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		const createSpy = vi
			.spyOn(AuthplaneClient, "create")
			.mockResolvedValue(client);

		const fetchSettings = {} as never;
		const revocationChecker = vi.fn(async () => false);
		const asCredentials = { clientId: "id", clientSecret: "s" };
		const dpopProvider = { sign: vi.fn() } as never;

		await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: ["tools/add"],
			asCredentials,
			devMode: true,
			fetchSettings,
			jwksRefreshSeconds: 60,
			metadataRefreshSeconds: 120,
			revocationChecker,
			allowedAlgorithms: ["ES256"],
			clockSkewSeconds: 10,
			dpopProvider,
			cacheTtlBufferSeconds: 45,
			defaultTtlSeconds: 1800,
			cacheMaxEntries: 25_000,
			circuitBreakerThreshold: 7,
			circuitBreakerCooldownSeconds: 60,
		});

		expect(createSpy).toHaveBeenCalledWith({
			issuer: "https://auth.example.com",
			auth: asCredentials,
			devMode: true,
			fetchSettings,
			jwksRefreshSeconds: 60,
			metadataRefreshSeconds: 120,
			dpopProvider,
			cacheTtlBufferSeconds: 45,
			defaultTtlSeconds: 1800,
			cacheMaxEntries: 25_000,
			circuitBreakerThreshold: 7,
			circuitBreakerCooldownSeconds: 60,
		});

		expect(client.resource).toHaveBeenCalledWith({
			resource: "https://api.example.com/mcp",
			scopes: ["tools/add"],
			revocationChecker,
			allowedAlgorithms: ["ES256"],
			clockSkewSeconds: 10,
			devMode: true,
			asCredentials,
		});
	});

	it("forwards failClosed to client.resource()", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);

		await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			failClosed: true,
		});

		expect(client.resource).toHaveBeenCalledWith(
			expect.objectContaining({ failClosed: true }),
		);
	});

	it("rejects setting both `replayStore` and `inboundDPoP.replayStore`", async () => {
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);

		const replayStore = {
			checkAndStore: vi.fn(async () => true),
		} as unknown as DPoPReplayStore;

		await expect(
			authplaneHonoAuth({
				issuer: "https://auth.example.com",
				resource: "https://api.example.com/mcp",
				replayStore,
				inboundDPoP: { replayStore },
			}),
		).rejects.toThrow(/replayStore.*not both/u);
	});

	it("emits the PRM URL as resource_metadata on WWW-Authenticate challenges", async () => {
		const resource = mockResource({
			prmDocumentUrl:
				"https://api.example.com/.well-known/oauth-protected-resource/mcp",
		});
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);

		const { bearerAuth } = await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
		});

		const { Hono } = await import("hono");
		const app = new Hono();
		app.use("/mcp", bearerAuth);
		app.post("/mcp", (c) => c.json({ ok: true }));

		const response = await app.request("/mcp", { method: "POST" });
		expect(response.status).toBe(401);
		expect(response.headers.get("WWW-Authenticate")).toContain(
			'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"',
		);
	});
});

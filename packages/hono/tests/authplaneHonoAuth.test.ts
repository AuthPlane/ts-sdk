import {
	AuthplaneClient,
	type AuthplaneResource,
	type DPoPReplayStore,
	TokenExpired,
	VerifiedClaims,
} from "@authplane/sdk/core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { authplaneHonoAuth } from "../src/authplaneHonoAuth.js";
import { requireScope } from "../src/requireScope.js";
import type { HonoAuthVariables } from "../src/types.js";

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

	it("wires the SAME realm + resource_metadata into bearerAuth (401) and auth.onError (403) so the two challenges cannot drift", async () => {
		const realm = "https://api.example.com/mcp";
		const prmUrl =
			"https://api.example.com/.well-known/oauth-protected-resource/mcp";
		const resource = mockResource({
			prmDocumentUrl: prmUrl,
			// Token clears the global scope gate (tools/read) but lacks the
			// per-route scope the handler demands (tools/add).
			verify: vi.fn(async () => buildClaims({ scopes: ["tools/read"] })),
		});
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);

		const auth = await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: ["tools/read"],
			realm,
		});

		const { Hono } = await import("hono");
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use("/mcp", auth.bearerAuth);
		app.post("/mcp", (c) => {
			requireScope(c, "tools/add");
			return c.json({ ok: true });
		});
		app.onError(auth.onError);

		// 401 comes from the bearerAuth verification path.
		const unauthenticated = await app.request("/mcp", { method: "POST" });
		expect(unauthenticated.status).toBe(401);
		const challenge401 = unauthenticated.headers.get("WWW-Authenticate");

		// 403 comes from auth.onError catching the handler-raised InsufficientScope.
		const forbidden = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});
		expect(forbidden.status).toBe(403);
		const challenge403 = forbidden.headers.get("WWW-Authenticate");

		for (const challenge of [challenge401, challenge403]) {
			expect(challenge).toContain(`realm="${realm}"`);
			expect(challenge).toContain(`resource_metadata="${prmUrl}"`);
		}
	});

	it("honors emitDownstreamChallenge: false forwarded through the factory (app keeps control of the downstream response)", async () => {
		const resource = mockResource({
			verify: vi.fn(async () => buildClaims({ scopes: ["tools/read"] })),
		});
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);

		const auth = await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: ["tools/read"],
			emitDownstreamChallenge: false,
		});

		const { Hono } = await import("hono");
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use("/mcp", auth.bearerAuth);
		app.post("/mcp", (c) => {
			requireScope(c, "tools/add");
			return c.json({ ok: true });
		});
		// The app's own handler shapes the downstream response. With the middleware
		// guard opted out, bearerAuth must NOT overwrite it with a challenge.
		app.onError((_err, c) => c.json({ handled: true }, 418));

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(418);
		expect(response.headers.get("WWW-Authenticate")).toBeNull();
		await expect(response.json()).resolves.toEqual({ handled: true });
	});

	it("exercises auth.onError directly: a handler-thrown AuthplaneError maps to its RFC 6750 challenge", async () => {
		const prmUrl =
			"https://api.example.com/.well-known/oauth-protected-resource/mcp";
		const resource = mockResource({ prmDocumentUrl: prmUrl });
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);

		const auth = await authplaneHonoAuth({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			realm: "https://api.example.com/mcp",
		});

		const { Hono } = await import("hono");
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.get("/", () => {
			throw new TokenExpired("Token has expired");
		});
		app.onError(auth.onError);

		const response = await app.request("/");
		expect(response.status).toBe(401);
		expect(response.headers.get("WWW-Authenticate")).toBe(
			'Bearer realm="https://api.example.com/mcp", error="invalid_token", error_description="Token has expired", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"',
		);
	});

	it("auth.onError typechecks and runs on a Bindings-typed (Workers) app via the generic factory", async () => {
		type Env = { API_KEY: string };
		const resource = mockResource();
		const client = mockClient(resource);
		vi.spyOn(AuthplaneClient, "create").mockResolvedValue(client);

		// Instantiate the factory at the Workers Env so auth.onError is
		// ErrorHandler<{ Bindings; Variables }> and attaches without a cast.
		const auth = await authplaneHonoAuth<{
			Bindings: Env;
			Variables: HonoAuthVariables;
		}>({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
		});

		const { Hono } = await import("hono");
		const app = new Hono<{ Bindings: Env; Variables: HonoAuthVariables }>();
		app.get("/", () => {
			throw new TokenExpired("Token has expired");
		});
		app.onError(auth.onError);

		const response = await app.request("/");
		expect(response.status).toBe(401);
		expect(response.headers.get("WWW-Authenticate")).toContain(
			'error="invalid_token"',
		);
	});
});

import {
	type AuthplaneResource,
	InvalidClaims,
	InvalidSignature,
	JWKSFetchError,
	MetadataFetchError,
	TokenExpired,
	VerifiedClaims,
} from "@authplane/sdk/core";
import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { bearerAuth } from "../src/bearerAuth.js";
import type { HonoAuthVariables } from "../src/types.js";

function futureSeconds(offset = 3_600): number {
	return Math.floor(Date.now() / 1000) + offset;
}

function buildClaims(
	overrides: Partial<ConstructorParameters<typeof VerifiedClaims>[0]> = {},
) {
	return new VerifiedClaims({
		sub: "user_123",
		clientId: "client_456",
		scopes: ["tools/add", "tools/echo"],
		issuer: "https://auth.example.com",
		audience: ["https://api.example.com/mcp"],
		expiresAt: futureSeconds(),
		issuedAt: Math.floor(Date.now() / 1000),
		jti: "token_123",
		kid: "key_1",
		agentId: "",
		agentChain: [],
		notBefore: 0,
		raw: { sub: "user_123" },
		...overrides,
	});
}

describe("bearerAuth — happy path", () => {
	let verifyMock: ReturnType<typeof vi.fn>;
	let verifier: AuthplaneResource;

	beforeEach(() => {
		verifyMock = vi.fn(async () => buildClaims());
		verifier = { verify: verifyMock } as unknown as AuthplaneResource;
	});

	it("calls verifier.verify with the extracted Bearer token and continues", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => c.json({ ok: true }));

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toEqual({ ok: true });
		// No DPoP header → bearerAuth calls verify(token) without the second arg.
		expect(verifyMock).toHaveBeenCalledWith("valid_jwt", { dpopRequest: undefined });
	});

	it("stores the verified claims in the Hono context under 'auth'", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => {
			const auth = c.get("auth");
			return c.json({
				sub: auth.sub,
				clientId: auth.clientId,
				scopes: auth.scopes,
			});
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toEqual({
			sub: "user_123",
			clientId: "client_456",
			scopes: ["tools/add", "tools/echo"],
		});
	});

	it("accepts lowercase `bearer` scheme (RFC 6750 §2.1)", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => c.json({ ok: true }));

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "bearer valid_jwt" },
		});

		expect(response.status).toBe(200);
		expect(verifyMock).toHaveBeenCalledWith("valid_jwt", { dpopRequest: undefined });
	});
});

describe("bearerAuth — error paths", () => {
	function buildApp(
		overrides: {
			verify?: ReturnType<typeof vi.fn>;
			requiredScopes?: readonly string[];
			resourceMetadataUrl?: string;
		} = {},
	) {
		const verifyMock = overrides.verify ?? vi.fn(async () => buildClaims());
		const verifier = { verify: verifyMock } as unknown as AuthplaneResource;

		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({
				verifier,
				resourceOrigin: "http://api.example.com",
				...(overrides.requiredScopes !== undefined
					? { requiredScopes: overrides.requiredScopes }
					: {}),
				...(overrides.resourceMetadataUrl !== undefined
					? { resourceMetadataUrl: overrides.resourceMetadataUrl }
					: {}),
			}),
		);
		app.post("/mcp", (c) => c.json({ ok: true }));
		return { app, verifyMock };
	}

	it("returns 401 when the Authorization header is missing (core TokenMissing)", async () => {
		const { app } = buildApp();

		const response = await app.request("/mcp", { method: "POST" });

		expect(response.status).toBe(401);
		expect(response.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="invalid_token", error_description="Missing Authorization header"',
		);
		await expect(response.json()).resolves.toEqual({
			error: "invalid_token",
			error_description: "Missing Authorization header",
		});
	});

	it("returns 401 when the scheme is not Bearer/DPoP (core TokenMissing)", async () => {
		const { app } = buildApp();

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Basic dXNlcjpwYXNz" },
		});

		expect(response.status).toBe(401);
		expect(response.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="invalid_token", error_description="Invalid Authorization header format, expected \'Bearer TOKEN\' or \'DPoP TOKEN\'"',
		);
	});

	it("returns 401 when verifier rejects the token (core InvalidSignature)", async () => {
		const { app } = buildApp({
			verify: vi.fn(async () => {
				throw new InvalidSignature("bad signature");
			}),
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer bad_jwt" },
		});

		expect(response.status).toBe(401);
		expect(response.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="invalid_token", error_description="bad signature"',
		);
	});

	it("returns 401 when core rejects the token as expired", async () => {
		const { app } = buildApp({
			verify: vi.fn(async () => {
				throw new TokenExpired("Token has expired");
			}),
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(401);
		await expect(response.json()).resolves.toEqual({
			error: "invalid_token",
			error_description: "Token has expired",
		});
	});

	it("returns 401 when core rejects the token for malformed claims", async () => {
		const { app } = buildApp({
			verify: vi.fn(async () => {
				throw new InvalidClaims("Token has no expiration time");
			}),
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(401);
		await expect(response.json()).resolves.toEqual({
			error: "invalid_token",
			error_description: "Token has no expiration time",
		});
	});

	it("returns 503 when core fails to fetch JWKS (upstream AS unreachable)", async () => {
		const { app } = buildApp({
			verify: vi.fn(async () => {
				throw new JWKSFetchError("JWKS endpoint unreachable");
			}),
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(503);
		await expect(response.json()).resolves.toEqual({
			error: "invalid_token",
			error_description: "JWKS endpoint unreachable",
		});
	});

	it("returns 503 when core fails to fetch AS metadata", async () => {
		const { app } = buildApp({
			verify: vi.fn(async () => {
				throw new MetadataFetchError("AS metadata endpoint unreachable");
			}),
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(503);
		await expect(response.json()).resolves.toEqual({
			error: "invalid_token",
			error_description: "AS metadata endpoint unreachable",
		});
	});

	it("returns 403 with scope challenge when a required scope is missing", async () => {
		const { app } = buildApp({
			requiredScopes: ["tools/add", "tools/delete"],
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(403);
		// bearerAuth delegates to core claims.requireScopes, whose message names
		// the missing scope (`tools/delete`) and the scopes the token does
		// carry — verbatim into both the JSON body and the WWW-Authenticate
		// challenge's `error_description=`.
		expect(response.headers.get("WWW-Authenticate")).toBe(
			`Bearer error="insufficient_scope", error_description="Token missing required scope 'tools/delete'. Token has scopes: tools/add, tools/echo", scope="tools/add tools/delete"`,
		);
		await expect(response.json()).resolves.toEqual({
			error: "insufficient_scope",
			error_description:
				"Token missing required scope 'tools/delete'. Token has scopes: tools/add, tools/echo",
		});
	});

	it("lets the request through when all required scopes are present", async () => {
		const { app } = buildApp({
			requiredScopes: ["tools/add"],
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(200);
	});

	it("appends resource_metadata to the challenge when configured", async () => {
		const { app } = buildApp({
			resourceMetadataUrl:
				"https://api.example.com/.well-known/oauth-protected-resource",
		});

		const response = await app.request("/mcp", { method: "POST" });

		expect(response.status).toBe(401);
		expect(response.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"',
		);
	});

	it("returns 500 without a challenge when a non-Authplane error escapes", async () => {
		const { app } = buildApp({
			verify: vi.fn(async () => {
				throw new TypeError("boom");
			}),
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(500);
		expect(response.headers.get("WWW-Authenticate")).toBeNull();
		await expect(response.json()).resolves.toEqual({
			error: "server_error",
			error_description: "boom",
		});
	});
});

describe("bearerAuth — DPoP binding", () => {
	let verifyMock: ReturnType<typeof vi.fn>;
	let verifier: AuthplaneResource;

	beforeEach(() => {
		verifyMock = vi.fn(async () => buildClaims());
		verifier = { verify: verifyMock } as unknown as AuthplaneResource;
	});

	it("threads the DPoP proof, method, and URL into the verifier call", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => c.json({ ok: true }));

		const response = await app.request("http://api.example.com/mcp", {
			method: "POST",
			headers: {
				Authorization: "Bearer valid_jwt",
				DPoP: "eyJ.proof.value",
			},
		});

		expect(response.status).toBe(200);
		expect(verifyMock).toHaveBeenCalledWith("valid_jwt", {
			dpopRequest: expect.objectContaining({
				method: "POST",
				url: "http://api.example.com/mcp",
				proofs: ["eyJ.proof.value"],
			}),
		});
	});

	it("pins the DPoP htu to the configured resourceOrigin — ignores X-Forwarded-*", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({
				verifier,
				resourceOrigin: "https://api.example.com",
			}),
		);
		app.post("/mcp", (c) => c.json({ ok: true }));

		await app.request("http://internal.local/mcp?id=42", {
			method: "POST",
			headers: {
				Authorization: "Bearer valid_jwt",
				DPoP: "eyJ.proof.value",
				"X-Forwarded-Proto": "http",
				"X-Forwarded-Host": "evil.example.com",
			},
		});

		expect(verifyMock).toHaveBeenCalledWith("valid_jwt", {
			dpopRequest: expect.objectContaining({
				method: "POST",
				url: "https://api.example.com/mcp?id=42",
				proofs: ["eyJ.proof.value"],
			}),
		});
	});

	it("calls verify without DPoP context when no DPoP header is present", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => c.json({ ok: true }));

		await app.request("http://api.example.com/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(verifyMock).toHaveBeenCalledWith("valid_jwt", { dpopRequest: undefined });
	});

	it("calls verify without DPoP context when the DPoP header is empty", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => c.json({ ok: true }));

		await app.request("http://api.example.com/mcp", {
			method: "POST",
			headers: {
				Authorization: "Bearer valid_jwt",
				DPoP: "",
			},
		});

		expect(verifyMock).toHaveBeenCalledWith("valid_jwt", { dpopRequest: undefined });
	});

	it("rejects requests carrying two DPoP headers with a DPoP-scheme challenge (RFC 9449 §4.3)", async () => {
		// `Headers.append` collapses duplicate same-name entries into one
		// comma-separated value when accessed via `get()` / iteration. The
		// SDK's `buildDPoPRequestContext` re-splits on `,` so the §4.3 #1
		// violation surfaces as `MultipleDPoPProofs`, which the
		// middleware must translate into a 401 with a `DPoP`-scheme
		// challenge — never `Bearer`. The verifier must not even be
		// invoked: we shouldn't waste a JWKS lookup on a request the
		// boundary already rejected.
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => c.json({ ok: true }));

		const multiHeader = new Headers({ Authorization: "Bearer valid_jwt" });
		multiHeader.append("DPoP", "eyJ.first");
		multiHeader.append("DPoP", "eyJ.second");

		const response = await app.request("http://api.example.com/mcp", {
			method: "POST",
			headers: multiHeader,
		});

		expect(response.status).toBe(401);
		const challenge = response.headers.get("WWW-Authenticate");
		expect(challenge).toMatch(/^DPoP /);
		// RFC 9449 §7.1: §4.3 rejections carry invalid_dpop_proof, not the
		// SDK's historical invalid_token used by the other DPoPError shapes.
		expect(challenge).toContain('error="invalid_dpop_proof"');
		expect(verifyMock).not.toHaveBeenCalled();
	});
});

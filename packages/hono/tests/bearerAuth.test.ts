import {
	type AuthplaneResource,
	InsufficientScope,
	InvalidClaims,
	InvalidSignature,
	JWKSFetchError,
	MetadataFetchError,
	TokenExpired,
	VerifiedClaims,
} from "@authplane/sdk/core";
import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { authplaneOnError } from "../src/authplaneOnError.js";
import { bearerAuth } from "../src/bearerAuth.js";
import { requireScope } from "../src/requireScope.js";
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

	it("returns 500 without a challenge and never echoes the raw message when a non-Authplane error escapes", async () => {
		// `verify()` drives app-supplied collaborators (revocationChecker, the
		// inbound DPoP replayStore), so a raw failure here can carry an
		// infrastructure detail. The client must get a FIXED description while the
		// original error is logged server-side.
		const leakySecret = "boom: connect ECONNREFUSED 10.0.0.5:6379";
		const { app } = buildApp({
			verify: vi.fn(async () => {
				throw new TypeError(leakySecret);
			}),
		});
		const consoleError = vi
			.spyOn(console, "error")
			.mockImplementation(() => {});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(500);
		expect(response.headers.get("WWW-Authenticate")).toBeNull();
		await expect(response.json()).resolves.toEqual({
			error: "server_error",
			error_description: "Internal Server Error",
		});
		expect(consoleError).toHaveBeenCalledTimes(1);
		expect((consoleError.mock.calls[0]?.[0] as Error).message).toBe(
			leakySecret,
		);
		consoleError.mockRestore();
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

describe("bearerAuth — downstream requireScope challenge (zero app wiring)", () => {
	function buildClaimsWith(scopes: readonly string[]) {
		return buildClaims({ scopes: [...scopes] });
	}

	it("emits a 403 insufficient_scope challenge with the per-route scope, no onError installed", async () => {
		const verifier = {
			verify: vi.fn(async () => buildClaimsWith(["tools/add"])),
		} as unknown as AuthplaneResource;

		// A route guarded ONLY by bearerAuth. No app.onError, no custom error
		// handling of any kind — the adapter must guarantee the challenge itself.
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => {
			requireScope(c, "tools/delete_thing");
			return c.json({ ok: true });
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(403);
		expect(response.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="insufficient_scope", error_description="Token missing required scope \'tools/delete_thing\'. Token has scopes: tools/add", scope="tools/delete_thing"',
		);
		// The zero-config rewrite must still emit a JSON body, not inherit the
		// content-type of whatever the guarded handler was about to return.
		expect(response.headers.get("content-type")).toContain("application/json");
		await expect(response.json()).resolves.toEqual({
			error: "insufficient_scope",
			error_description:
				"Token missing required scope 'tools/delete_thing'. Token has scopes: tools/add",
		});
	});

	it("challenge carries the per-route scope, NOT the middleware-level required-scope union", async () => {
		const verifier = {
			verify: vi.fn(async () => buildClaimsWith(["tools/add"])),
		} as unknown as AuthplaneResource;

		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			// The global gate requires (and the token has) tools/add, so the
			// middleware scope check passes; the per-route requireScope is what
			// fails. The challenge must report the per-route scope only.
			bearerAuth({
				verifier,
				resourceOrigin: "http://api.example.com",
				requiredScopes: ["tools/add"],
			}),
		);
		app.post("/mcp", (c) => {
			requireScope(c, "tools/delete_thing");
			return c.json({ ok: true });
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(403);
		const challenge = response.headers.get("WWW-Authenticate");
		expect(challenge).toContain('scope="tools/delete_thing"');
		expect(challenge).not.toContain('scope="tools/add"');
	});

	it("re-throws a non-Authplane error from the guarded route instead of masking it as an auth response", async () => {
		const verifier = {
			verify: vi.fn(async () => buildClaimsWith(["tools/add"])),
		} as unknown as AuthplaneResource;

		const boom = new TypeError("handler exploded");
		let seen: unknown;
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", () => {
			throw boom;
		});
		app.onError((err, c) => {
			seen = err;
			return c.json({ handled: true }, 500);
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		// The middleware did not swallow the app error into a synthetic auth
		// response — it reached the app's own onError untouched, with no
		// WWW-Authenticate challenge attached.
		expect(seen).toBe(boom);
		expect(response.status).toBe(500);
		expect(response.headers.get("WWW-Authenticate")).toBeNull();
	});
});

describe("bearerAuth — emitDownstreamChallenge", () => {
	function buildClaimsWith(scopes: readonly string[]) {
		return buildClaims({ scopes: [...scopes] });
	}

	it("overrides a plain app handler's non-challenge AuthplaneError response by default", async () => {
		const verifier = {
			verify: vi.fn(async () => buildClaimsWith(["tools/add"])),
		} as unknown as AuthplaneResource;

		// A plain app.onError maps the downstream InsufficientScope to a 403 but
		// deliberately omits the WWW-Authenticate header. With the default
		// (emitDownstreamChallenge unset → true) the middleware's post-next()
		// guard fires — the `instanceof AuthplaneError && !has(WWW-Authenticate)`
		// branch — and rewrites the response WITH the RFC 6750 §3 challenge.
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => {
			requireScope(c, "tools/delete_thing");
			return c.json({ ok: true });
		});
		app.onError((_err, c) => c.json({ handled: "by app" }, 403));

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(403);
		expect(response.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="insufficient_scope", error_description="Token missing required scope \'tools/delete_thing\'. Token has scopes: tools/add", scope="tools/delete_thing"',
		);
		await expect(response.json()).resolves.toEqual({
			error: "insufficient_scope",
			error_description:
				"Token missing required scope 'tools/delete_thing'. Token has scopes: tools/add",
		});
	});

	it("leaves the app's own non-challenge response intact when emitDownstreamChallenge is false", async () => {
		const verifier = {
			verify: vi.fn(async () => buildClaimsWith(["tools/add"])),
		} as unknown as AuthplaneResource;

		// Same setup, but the app opts out: the middleware must NOT override the
		// downstream AuthplaneError response even though it carries no challenge.
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({
				verifier,
				resourceOrigin: "http://api.example.com",
				emitDownstreamChallenge: false,
			}),
		);
		app.post("/mcp", (c) => {
			requireScope(c, "tools/delete_thing");
			return c.json({ ok: true });
		});
		app.onError((_err, c) => c.json({ handled: "by app" }, 403));

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(403);
		expect(response.headers.get("WWW-Authenticate")).toBeNull();
		await expect(response.json()).resolves.toEqual({ handled: "by app" });
	});
});

describe("bearerAuth — downstream error that rejects next() (app onError re-throws)", () => {
	function buildClaimsWith(scopes: readonly string[]) {
		return buildClaims({ scopes: [...scopes] });
	}

	it("re-throws a non-Authplane error unchanged when the app onError re-throws it", async () => {
		const verifier = {
			verify: vi.fn(async () => buildClaimsWith(["tools/add"])),
		} as unknown as AuthplaneResource;

		// `authplaneOnError({ fallback: "rethrow" })` re-throws a
		// non-`AuthplaneError`, which is the ONLY way `await next()` REJECTS in
		// the middleware (normally Hono resolves next() and leaves the error on
		// `c.error`). The middleware must leave a non-`AuthplaneError` alone —
		// re-throw it untouched — so it is never masked as an auth response.
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", () => {
			throw new TypeError("handler exploded");
		});
		app.onError(authplaneOnError({ fallback: "rethrow" }));

		await expect(
			app.request("/mcp", {
				method: "POST",
				headers: { Authorization: "Bearer valid_jwt" },
			}),
		).rejects.toThrow("handler exploded");
	});

	it("emits the RFC 6750 §3 challenge for an AuthplaneError that rejects next() (default flag)", async () => {
		const verifier = {
			verify: vi.fn(async () => buildClaimsWith(["tools/add"])),
		} as unknown as AuthplaneResource;

		// A custom onError re-throws the `AuthplaneError` it is handed — unlike
		// `authplaneOnError`, which always answers an `AuthplaneError` itself and
		// never re-throws it. That rejects `await next()` WITH the
		// `InsufficientScope`, exercising the `catch` branch. With
		// `emitDownstreamChallenge` defaulting to true the middleware writes the
		// challenge.
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => {
			requireScope(c, "tools/delete_thing");
			return c.json({ ok: true });
		});
		app.onError((err) => {
			throw err;
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(403);
		expect(response.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="insufficient_scope", error_description="Token missing required scope \'tools/delete_thing\'. Token has scopes: tools/add", scope="tools/delete_thing"',
		);
	});

	it("honors emitDownstreamChallenge: false on the reject path — the AuthplaneError propagates", async () => {
		const verifier = {
			verify: vi.fn(async () => buildClaimsWith(["tools/add"])),
		} as unknown as AuthplaneResource;

		// Same reject-next() setup, but the app opted out. The middleware must
		// NOT synthesize a challenge — it re-throws the `AuthplaneError`, which
		// then propagates out of the request untouched.
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({
				verifier,
				resourceOrigin: "http://api.example.com",
				emitDownstreamChallenge: false,
			}),
		);
		app.post("/mcp", (c) => {
			requireScope(c, "tools/delete_thing");
			return c.json({ ok: true });
		});
		app.onError((err) => {
			throw err;
		});

		await expect(
			app.request("/mcp", {
				method: "POST",
				headers: { Authorization: "Bearer valid_jwt" },
			}),
		).rejects.toBeInstanceOf(InsufficientScope);
	});
});

describe("bearerAuth — WWW-Authenticate guard against double-emit", () => {
	function buildClaimsWith(scopes: readonly string[]) {
		return buildClaims({ scopes: [...scopes] });
	}

	it("emits exactly ONE 403 challenge when both bearerAuth and app.onError(authplaneOnError()) are installed", async () => {
		const verifier = {
			verify: vi.fn(async () => buildClaimsWith(["tools/add"])),
		} as unknown as AuthplaneResource;

		// Both the middleware guard AND the app-level authplaneOnError() can map
		// the same InsufficientScope. authplaneOnError() runs first (inside the
		// middleware's next()); the middleware's
		// `!c.res.headers.has("WWW-Authenticate")` guard must then suppress its
		// own emit so the challenge is written once and the JSON body from
		// authplaneOnError() is not clobbered.
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => {
			requireScope(c, "tools/delete_thing");
			return c.json({ ok: true });
		});
		app.onError(authplaneOnError());

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(403);
		// A doubled emit via Headers.append would surface here as a
		// comma-joined value; exact equality to the single expected challenge
		// proves the guard suppressed the middleware's second write.
		expect(response.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="insufficient_scope", error_description="Token missing required scope \'tools/delete_thing\'. Token has scopes: tools/add", scope="tools/delete_thing"',
		);
		await expect(response.json()).resolves.toEqual({
			error: "insufficient_scope",
			error_description:
				"Token missing required scope 'tools/delete_thing'. Token has scopes: tools/add",
		});
	});

	it("suppresses its own emit when a WWW-Authenticate header is already present on the response", async () => {
		const verifier = {
			verify: vi.fn(async () => buildClaimsWith(["tools/add"])),
		} as unknown as AuthplaneResource;

		// A custom app.onError pre-sets a WWW-Authenticate header before control
		// returns to the middleware's post-next() guard. The downstream error is
		// an AuthplaneError, so the guard's `instanceof` arm is live — the only
		// thing stopping a rewrite is the `!c.res.headers.has(...)` check. Assert
		// the pre-set challenge survives untouched (suppression branch).
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use(
			"/mcp",
			bearerAuth({ verifier, resourceOrigin: "http://api.example.com" }),
		);
		app.post("/mcp", (c) => {
			requireScope(c, "tools/delete_thing");
			return c.json({ ok: true });
		});
		app.onError((_err, c) => {
			c.header("WWW-Authenticate", 'Bearer error="preset_by_app"');
			return c.json({ handled: "by app" }, 403);
		});

		const response = await app.request("/mcp", {
			method: "POST",
			headers: { Authorization: "Bearer valid_jwt" },
		});

		expect(response.status).toBe(403);
		expect(response.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="preset_by_app"',
		);
		await expect(response.json()).resolves.toEqual({ handled: "by app" });
	});
});

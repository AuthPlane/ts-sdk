import {
	InsufficientScope,
	TokenExpired,
	VerifiedClaims,
} from "@authplane/sdk/core";
import { Hono } from "hono";
import { basicAuth } from "hono/basic-auth";
import { HTTPException } from "hono/http-exception";
import { describe, expect, it, vi } from "vitest";

import { authplaneOnError } from "../src/authplaneOnError.js";
import { requireScope } from "../src/requireScope.js";
import {
	type HonoAuthVariables,
	REQUIRED_SCOPE_CONTEXT_KEY,
} from "../src/types.js";

function claimsWith(scopes: readonly string[]): VerifiedClaims {
	return new VerifiedClaims({
		sub: "user_123",
		clientId: "client_456",
		scopes: [...scopes],
		issuer: "https://auth.example.com",
		audience: ["https://api.example.com/mcp"],
		expiresAt: Math.floor(Date.now() / 1000) + 3_600,
		issuedAt: Math.floor(Date.now() / 1000),
		jti: "token_123",
		kid: "key_1",
		agentId: "",
		agentChain: [],
		notBefore: 0,
		raw: {},
	});
}

describe("authplaneOnError", () => {
	it("maps a per-route InsufficientScope to 403 with the stashed scope in the challenge", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use("*", async (c, next) => {
			c.set("auth", claimsWith(["tools/echo"]));
			await next();
		});
		app.get("/", (c) => {
			// requireScope stashes REQUIRED_SCOPE_CONTEXT_KEY then throws.
			requireScope(c, "tools/add");
			return c.json({ ok: true });
		});
		app.onError(authplaneOnError());

		const res = await app.request("/");

		expect(res.status).toBe(403);
		expect(res.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="insufficient_scope", error_description="Token missing required scope \'tools/add\'. Token has scopes: tools/echo", scope="tools/add"',
		);
		await expect(res.json()).resolves.toEqual({
			error: "insufficient_scope",
			error_description:
				"Token missing required scope 'tools/add'. Token has scopes: tools/echo",
		});
	});

	it("falls back to the requiredScopes union when no per-route scope was stashed", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.get("/", () => {
			throw new InsufficientScope("Insufficient scope");
		});
		app.onError(authplaneOnError({ requiredScopes: ["tools/read"] }));

		const res = await app.request("/");

		expect(res.status).toBe(403);
		expect(res.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="insufficient_scope", error_description="Insufficient scope", scope="tools/read"',
		);
	});

	it("prefers the per-route scope over the requiredScopes union", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.get("/", (c) => {
			c.set(REQUIRED_SCOPE_CONTEXT_KEY, "tools/delete");
			throw new InsufficientScope("Insufficient scope");
		});
		app.onError(authplaneOnError({ requiredScopes: ["tools/read"] }));

		const res = await app.request("/");

		const challenge = res.headers.get("WWW-Authenticate");
		expect(challenge).toContain('scope="tools/delete"');
		expect(challenge).not.toContain('scope="tools/read"');
	});

	it("maps a non-scope AuthplaneError to 401 invalid_token and includes resource_metadata", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.get("/", () => {
			throw new TokenExpired("Token has expired");
		});
		app.onError(
			authplaneOnError({
				resourceMetadataUrl:
					"https://api.example.com/.well-known/oauth-protected-resource",
			}),
		);

		const res = await app.request("/");

		expect(res.status).toBe(401);
		expect(res.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="invalid_token", error_description="Token has expired", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"',
		);
	});

	it("maps a non-Authplane error to a clean server_error 500 without leaking the message", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		const leakySecret = "boom: connect ECONNREFUSED 10.0.0.5:5432";
		app.get("/", () => {
			throw new TypeError(leakySecret);
		});
		// authplaneOnError is the sole error handler. Because it REPLACES Hono's
		// built-in handler, the default `fallback: "server_error"` keeps a
		// copy-pasted one-liner safe: a route TypeError becomes a clean 500
		// instead of an unhandled rejection. The response must carry a FIXED
		// description (never the raw error message, which could name internal
		// hosts / columns / URLs) while the original error is logged server-side.
		const consoleError = vi
			.spyOn(console, "error")
			.mockImplementation(() => {});
		app.onError(authplaneOnError());

		const res = await app.request("/");

		expect(res.status).toBe(500);
		expect(res.headers.get("WWW-Authenticate")).toBeNull();
		await expect(res.json()).resolves.toEqual({
			error: "server_error",
			error_description: "Internal Server Error",
		});
		// The stack is preserved for the operator via console.error, and the raw
		// message never reaches the client body.
		expect(consoleError).toHaveBeenCalledTimes(1);
		expect(consoleError.mock.calls[0]?.[0]).toBeInstanceOf(TypeError);
		expect((consoleError.mock.calls[0]?.[0] as Error).message).toBe(
			leakySecret,
		);
		consoleError.mockRestore();
	});

	it("preserves an HTTPException's status and body instead of collapsing it to a 500", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.get("/", () => {
			throw new HTTPException(404, { message: "widget not found" });
		});
		// `app.onError(handler)` REPLACES Hono's built-in handler, which would have
		// returned the HTTPException's own response. The handler must reproduce
		// that instead of masking a 404 as a generic `server_error` 500.
		const consoleError = vi
			.spyOn(console, "error")
			.mockImplementation(() => {});
		app.onError(authplaneOnError());

		const res = await app.request("/");

		expect(res.status).toBe(404);
		await expect(res.text()).resolves.toBe("widget not found");
		// It is not routed through the `server_error` fallback, so nothing is
		// logged as an internal fault.
		expect(consoleError).not.toHaveBeenCalled();
		consoleError.mockRestore();
	});

	it("preserves a Hono basicAuth 401 challenge (status + WWW-Authenticate) through the handler", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.use("/", basicAuth({ username: "user", password: "pass" }));
		app.get("/", (c) => c.json({ ok: true }));
		app.onError(authplaneOnError());

		// No credentials → basicAuth throws HTTPException(401) whose response
		// carries the `WWW-Authenticate: Basic realm="…"` challenge. That header
		// must survive the handler.
		const res = await app.request("/");

		expect(res.status).toBe(401);
		expect(res.headers.get("WWW-Authenticate")).toContain("Basic");
		expect(res.headers.get("WWW-Authenticate")).toContain("realm=");
	});

	it("routes the server_error fallback through a custom onServerError sink", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.get("/", () => {
			throw new TypeError("boom");
		});
		const sink = vi.fn();
		const consoleError = vi
			.spyOn(console, "error")
			.mockImplementation(() => {});
		app.onError(authplaneOnError({ onServerError: sink }));

		const res = await app.request("/");

		expect(res.status).toBe(500);
		await expect(res.json()).resolves.toEqual({
			error: "server_error",
			error_description: "Internal Server Error",
		});
		// The structured sink receives the original error; console.error does not.
		expect(sink).toHaveBeenCalledTimes(1);
		expect((sink.mock.calls[0]?.[0] as Error).message).toBe("boom");
		expect(consoleError).not.toHaveBeenCalled();
		consoleError.mockRestore();
	});

	it("re-throws non-Authplane errors unchanged with fallback: 'rethrow'", async () => {
		const app = new Hono<{ Variables: HonoAuthVariables }>();
		app.get("/", () => {
			throw new TypeError("boom");
		});
		// Opt back into the pre-fallback behaviour: re-throw a non-AuthplaneError
		// for an outer handler to catch. With no outer handler the error
		// propagates out of the app untouched.
		app.onError(authplaneOnError({ fallback: "rethrow" }));

		await expect(async () => {
			await app.request("/");
		}).rejects.toThrow("boom");
	});

	it("typechecks and runs on a Bindings-typed (Cloudflare Workers) app", async () => {
		type Env = { API_KEY: string };
		// The standard Workers shape carries both Bindings and Variables; the
		// handler must be generic enough to attach here without a cast.
		const app = new Hono<{ Bindings: Env; Variables: HonoAuthVariables }>();
		app.get("/", () => {
			throw new TokenExpired("Token has expired");
		});
		app.onError(authplaneOnError());

		const res = await app.request("/");

		expect(res.status).toBe(401);
		expect(res.headers.get("WWW-Authenticate")).toBe(
			'Bearer error="invalid_token", error_description="Token has expired"',
		);
	});
});

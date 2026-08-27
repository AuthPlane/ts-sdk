/**
 * Calculator Service — Hono demo.
 *
 * A minimal Hono server demonstrating `@authplane/hono`'s full stack:
 *
 * - RFC 9728 Protected Resource Metadata served at the discovered path
 * - Bearer token validation (signature, issuer, audience, expiry)
 * - RFC 7662 token introspection for revocation checks
 * - Per-route scope enforcement via `requireScope()`
 * - RFC 6750 error responses (`WWW-Authenticate`, 401 / 403) via `app.onError`
 *
 * Routes:
 *
 * | Route                | Required scope      |
 * | -------------------- | ------------------- |
 * | `POST /math/add`     | `tools/add`         |
 * | `POST /math/multiply`| `tools/multiply`    |
 * | `GET  /me`           | (any valid token)   |
 *
 * Run from the package root:
 *
 *   cp demo/.env.example demo/.env
 *   ./demo/run.sh
 */

import { dirname, resolve } from "node:path";
import { fileURLToPath, URL } from "node:url";

import { serve } from "@hono/node-server";
import {
	type ASCredentials,
	IntrospectionRevocation,
} from "@authplane/sdk/core";
import { config } from "dotenv";
import { Hono } from "hono";

import {
	authplaneHonoAuth,
	type HonoAuthVariables,
	requireScope,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, ".env") });

function env(name: string, legacyName: string, fallback: string): string {
	return process.env[name] ?? process.env[legacyName] ?? fallback;
}

const resource = env(
	"AUTHPLANE_RESOURCE",
	"RESOURCE_URL",
	"http://localhost:8080/mcp",
);
const parsedResourceUrl = new URL(resource);
const port = parsedResourceUrl.port
	? Number(parsedResourceUrl.port)
	: parsedResourceUrl.protocol === "https:"
		? 443
		: 80;

const clientSecret =
	process.env.AUTHPLANE_CLIENT_SECRET ?? process.env.CLIENT_SECRET ?? "";

const auth = await authplaneHonoAuth({
	issuer: env("AUTHPLANE_ISSUER", "ISSUER_URL", "http://localhost:9000"),
	resource,
	realm: resource,
	scopes: ["tools/add", "tools/multiply"],
	devMode: true,
	asCredentials: {
		clientId:
			process.env.AUTHPLANE_CLIENT_ID ?? process.env.CLIENT_ID ?? resource,
		clientSecret,
	} satisfies ASCredentials,
	revocationChecker: IntrospectionRevocation.get(),
});

const app = new Hono<{ Variables: HonoAuthVariables }>();

// RFC 9728 Protected Resource Metadata. The path is derived from `resource` by
// the SDK, so mounting it under the exact path the PRM document URL points to
// means MCP / OAuth clients can discover it through the `WWW-Authenticate:
// resource_metadata=...` pointer on 401 responses.
app.get(
	auth.protectedResourceMetadataPath,
	auth.protectedResourceMetadataHandler,
);

// Everything under `/math/*` and `/me` is authenticated. The middleware
// validates the bearer token, checks revocation, verifies any DPoP proof, and
// populates `c.get("auth")` with the core `VerifiedClaims`.
app.use("/math/*", auth.bearerAuth);
app.use("/me", auth.bearerAuth);

app.post("/math/add", async (c) => {
	requireScope(c, "tools/add");
	const { a, b } = (await c.req.json()) as { a: number; b: number };
	return c.json({ result: a + b });
});

app.post("/math/multiply", async (c) => {
	requireScope(c, "tools/multiply");
	const { a, b } = (await c.req.json()) as { a: number; b: number };
	return c.json({ result: a * b });
});

app.get("/me", (c) => {
	const info = c.get("auth");
	return c.json({
		sub: info.sub,
		clientId: info.clientId,
		scopes: info.scopes,
		expiresAt: info.expiresAt,
	});
});

// Bridge scope / token errors thrown from handlers into RFC 6750 responses.
// The bearerAuth middleware handles errors thrown from its own *token*
// validation path, but an `InsufficientScope` from `requireScope()` inside a
// handler surfaces through the framework's `onError` hook. `auth.onError` is a
// ready `authplaneOnError` bound with the SAME `realm` + `resource_metadata`
// URL the factory wired into `bearerAuth`, so the 401 from verification and the
// 403 from `requireScope()` carry an identical challenge and cannot drift. It
// maps any other error to a clean `server_error` 500 — no hand-written bridge.
app.onError(auth.onError);

serve({ fetch: app.fetch, port }, () => {
	console.log(`Hono Calculator Service running on ${resource}`);
	console.log(`  PRM path: ${auth.protectedResourceMetadataPath}`);
	console.log("  routes:");
	console.log("    POST /math/add        (requires tools/add)");
	console.log("    POST /math/multiply   (requires tools/multiply)");
	console.log("    GET  /me              (requires valid token)");
});

const shutdown = async () => {
	await auth.client.close();
	process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

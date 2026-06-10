/**
 * Calculator Service — NestJS demo.
 *
 * A minimal NestJS server demonstrating `@authplane/nestjs`'s full stack:
 *
 * - RFC 9728 Protected Resource Metadata served at the discovered path
 * - Bearer token validation (signature, issuer, audience, expiry)
 * - RFC 7662 token introspection for revocation checks
 * - Per-route scope enforcement via `@RequireScopes(...)`
 * - RFC 6750 error responses (`WWW-Authenticate`, 401 / 403) via the bundled
 *   `AuthplaneExceptionFilter`
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

import "reflect-metadata";

import { dirname, resolve } from "node:path";
import { fileURLToPath, URL } from "node:url";

import {
	Body,
	Controller,
	Get,
	Module,
	Post,
	UseGuards,
} from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import {
	type ASCredentials,
	IntrospectionRevocation,
} from "@authplane/sdk/core";
import { config } from "dotenv";

import {
	AuthInfo,
	AuthplaneAuthGuard,
	AuthplaneExceptionFilter,
	AuthplaneModule,
	type VerifiedClaims,
	RequireScopes,
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
const clientId =
	process.env.AUTHPLANE_CLIENT_ID ?? process.env.CLIENT_ID ?? resource;

// Guarded controller. `@UseGuards(AuthplaneAuthGuard)` validates the bearer
// token, checks revocation, verifies any DPoP proof, and stashes the core
// `VerifiedClaims` on the request; `@RequireScopes(...)` layers per-route
// scope enforcement on top.
@Controller()
@UseGuards(AuthplaneAuthGuard)
class MathController {
	@Post("math/add")
	@RequireScopes("tools/add")
	public add(@Body() body: { a: number; b: number }): { result: number } {
		return { result: body.a + body.b };
	}

	@Post("math/multiply")
	@RequireScopes("tools/multiply")
	public multiply(@Body() body: { a: number; b: number }): { result: number } {
		return { result: body.a * body.b };
	}

	@Get("me")
	public me(@AuthInfo() info: VerifiedClaims): {
		sub: string;
		clientId: string;
		scopes: readonly string[];
		expiresAt: number;
	} {
		return {
			sub: info.sub,
			clientId: info.clientId,
			scopes: info.scopes,
			expiresAt: info.expiresAt,
		};
	}
}

@Module({
	imports: [
		AuthplaneModule.forRoot({
			issuer: env("AUTHPLANE_ISSUER", "ISSUER_URL", "http://localhost:9000"),
			resource,
			scopes: ["tools/add", "tools/multiply"],
			devMode: true,
			asCredentials: { clientId, clientSecret } satisfies ASCredentials,
			// IntrospectionRevocation is a singleton — always obtain it via
			// `IntrospectionRevocation.get()` (lesson #1 in the plan).
			revocationChecker: IntrospectionRevocation.get(),
		}),
	],
	controllers: [MathController],
})
class AppModule {}

const app = await NestFactory.create(AppModule);
// Mount the RFC 6750 §3 filter globally — `AuthplaneModule` provides it but
// does not auto-register it as APP_FILTER, so the demo opts in explicitly.
// Without this, the auth failures the docstring above advertises come back
// as Nest's generic 500 instead of `WWW-Authenticate: Bearer error="…"`.
app.useGlobalFilters(app.get(AuthplaneExceptionFilter));
// `enableShutdownHooks()` is what wakes up `AuthplaneShutdownHook` so
// `await client.close()` runs on SIGINT / SIGTERM (lesson #3).
app.enableShutdownHooks();
await app.listen(port);

console.log(`NestJS Calculator Service running on ${resource}`);
console.log(`  PRM path: /.well-known/oauth-protected-resource${parsedResourceUrl.pathname.replace(/\/+$/u, "")}`);
console.log("  routes:");
console.log("    POST /math/add        (requires tools/add)");
console.log("    POST /math/multiply   (requires tools/multiply)");
console.log("    GET  /me              (requires valid token)");

import {
	Body,
	Controller,
	Get,
	type INestApplication,
	Module,
	Post,
	UseGuards,
} from "@nestjs/common";
import {
	FastifyAdapter,
	type NestFastifyApplication,
} from "@nestjs/platform-fastify";
import { Test } from "@nestjs/testing";
import {
	AuthplaneClient,
	type AuthplaneResource,
	InvalidSignature,
	TokenExpired,
	VerifiedClaims,
} from "@authplane/sdk/core";
import supertest from "supertest";
import {
	afterAll,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	vi,
} from "vitest";

import {
	AuthInfo,
	AuthplaneAuthGuard,
	AuthplaneExceptionFilter,
	AuthplaneModule,
	RequireScopes,
} from "../../src/index.js";

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

@Controller("math")
@UseGuards(AuthplaneAuthGuard)
class MathController {
	@Post("add")
	@RequireScopes("tools/add")
	public add(
		@AuthInfo() info: VerifiedClaims,
		@Body() body: { a: number; b: number },
	): { readonly result: number; readonly caller: string } {
		return { result: body.a + body.b, caller: info.clientId };
	}

	@Get("whoami")
	public whoami(
		@AuthInfo() info: VerifiedClaims,
	): { readonly sub: string } {
		return { sub: info.sub };
	}
}

@Module({
	imports: [
		AuthplaneModule.forRoot({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: ["tools/add"],
		}),
	],
	controllers: [MathController],
})
class TestAppModule {}

function mockResource(): AuthplaneResource {
	return {
		verify: vi.fn(),
		prmResponse: vi.fn(() => ({
			resource: "https://api.example.com/mcp",
			authorization_servers: ["https://auth.example.com"],
			scopes_supported: ["tools/add"],
			bearer_methods_supported: ["header"],
		})),
		prmDocumentUrl: vi.fn(
			() =>
				"https://api.example.com/.well-known/oauth-protected-resource/mcp",
		),
	} as unknown as AuthplaneResource;
}

function mockClient(resource: AuthplaneResource) {
	return {
		resource: vi.fn(() => resource),
		close: vi.fn(async () => undefined),
	};
}

function buildClaims(
	overrides: Partial<ConstructorParameters<typeof VerifiedClaims>[0]> = {},
): VerifiedClaims {
	const now = Math.floor(Date.now() / 1000);
	return new VerifiedClaims({
		sub: "user_1",
		clientId: "client_1",
		scopes: ["tools/add"],
		issuer: "https://auth.example.com",
		audience: ["https://api.example.com/mcp"],
		expiresAt: now + 600,
		issuedAt: now - 60,
		jti: "jti",
		kid: "kid",
		agentId: "",
		agentChain: [],
		notBefore: 0,
		raw: {},
		...overrides,
	});
}

// ---------------------------------------------------------------------------
// The platforms we support share the same module + guard + filter — hammer
// both with the same battery of behavioural tests.
// ---------------------------------------------------------------------------

type AppFactory = () => Promise<INestApplication>;

const platforms: ReadonlyArray<{
	readonly name: string;
	readonly build: AppFactory;
}> = [
	{
		name: "platform-express",
		build: async () => {
			const moduleRef = await Test.createTestingModule({
				imports: [TestAppModule],
			}).compile();
			return moduleRef.createNestApplication();
		},
	},
	{
		name: "platform-fastify",
		build: async () => {
			const moduleRef = await Test.createTestingModule({
				imports: [TestAppModule],
			}).compile();
			return moduleRef.createNestApplication<NestFastifyApplication>(
				new FastifyAdapter(),
			);
		},
	},
];

describe.each(platforms)(
	"AuthplaneModule — end-to-end ($name)",
	({ name, build }) => {
		let app: INestApplication;
		let resource: AuthplaneResource;
		let client: ReturnType<typeof mockClient>;

		beforeAll(async () => {
			resource = mockResource();
			client = mockClient(resource);
			vi.spyOn(AuthplaneClient, "create").mockResolvedValue(
				client as unknown as AuthplaneClient,
			);
			app = await build();

			// Register the exception filter globally so it catches errors
			// thrown from the guard regardless of which controller they hit.
			app.useGlobalFilters(app.get(AuthplaneExceptionFilter));

			await app.init();
			if (name === "platform-fastify") {
				await (
					app as unknown as { getHttpAdapter: () => { getInstance: () => { ready: () => Promise<unknown> } } }
				)
					.getHttpAdapter()
					.getInstance()
					.ready();
			}
		});

		afterAll(async () => {
			await app.close();
			vi.restoreAllMocks();
		});

		beforeEach(() => {
			// Default: verify succeeds for "valid_jwt", rejects everything else.
			const verifyMock = resource.verify as ReturnType<typeof vi.fn>;
			verifyMock.mockReset();
			verifyMock.mockImplementation(async (token: string) => {
				if (token === "valid_jwt") {
					return buildClaims();
				}
				if (token === "expired_jwt") {
					throw new TokenExpired("Token expired");
				}
				if (token === "wrong_scope_jwt") {
					return buildClaims({ scopes: ["tools/read"] });
				}
				throw new InvalidSignature("Unknown token");
			});
		});

		afterEach(() => {
			vi.restoreAllMocks();
		});

		it("401s when the Authorization header is absent", async () => {
			const response = await supertest(app.getHttpServer())
				.post("/math/add")
				.send({ a: 1, b: 2 });
			expect(response.status).toBe(401);
			expect(response.headers["www-authenticate"]).toContain(
				'error="invalid_token"',
			);
		});

		it("401s + PRM URL in challenge for an expired token", async () => {
			const response = await supertest(app.getHttpServer())
				.post("/math/add")
				.set("Authorization", "Bearer expired_jwt")
				.send({ a: 1, b: 2 });
			expect(response.status).toBe(401);
			expect(response.headers["www-authenticate"]).toContain(
				'error="invalid_token"',
			);
			expect(response.headers["www-authenticate"]).toContain(
				'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"',
			);
		});

		it("403s with scope hint when the token lacks the required scope", async () => {
			const response = await supertest(app.getHttpServer())
				.post("/math/add")
				.set("Authorization", "Bearer wrong_scope_jwt")
				.send({ a: 1, b: 2 });
			expect(response.status).toBe(403);
			expect(response.headers["www-authenticate"]).toContain(
				'error="insufficient_scope"',
			);
			expect(response.headers["www-authenticate"]).toContain(
				'scope="tools/add"',
			);
		});

		it("200s on the happy path and injects VerifiedClaims via @AuthInfo", async () => {
			const response = await supertest(app.getHttpServer())
				.post("/math/add")
				.set("Authorization", "Bearer valid_jwt")
				.send({ a: 40, b: 2 });
			expect(response.status).toBe(201); // NestJS default for POST without explicit @HttpCode is 201
			expect(response.body).toEqual({ result: 42, caller: "client_1" });
		});

		it("serves the PRM document at the derived well-known path without auth", async () => {
			const response = await supertest(app.getHttpServer()).get(
				"/.well-known/oauth-protected-resource/mcp",
			);
			expect(response.status).toBe(200);
			expect(response.body).toEqual({
				resource: "https://api.example.com/mcp",
				authorization_servers: ["https://auth.example.com"],
				scopes_supported: ["tools/add"],
				bearer_methods_supported: ["header"],
			});
		});
	},
);

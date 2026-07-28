import { type AddressInfo } from "node:net";
import {
	createServer,
	type IncomingMessage,
	type Server,
	type ServerResponse,
} from "node:http";
import { Buffer } from "node:buffer";

import { randomBytes, randomUUID } from "node:crypto";

import {
	SignJWT,
	calculateJwkThumbprint,
	exportJWK,
	generateKeyPair,
	type JWK,
	type KeyLike,
} from "jose";

export interface Es256Keypair {
	privateKey: KeyLike;
	publicJwk: Record<string, unknown>;
	jwks: { keys: Array<Record<string, unknown>> };
	kid: string;
}

export async function generateEs256Keypair(
	kid = "test-key-1",
): Promise<Es256Keypair> {
	const { privateKey, publicKey } = await generateKeyPair("ES256");
	const publicJwk = (await exportJWK(publicKey)) as Record<string, unknown>;
	publicJwk.kid = kid;
	publicJwk.alg = "ES256";
	publicJwk.use = "sig";
	return {
		privateKey: privateKey as KeyLike,
		publicJwk,
		jwks: { keys: [publicJwk] },
		kid,
	};
}

export interface TokenClaimsInput {
	iss?: string;
	aud?: string | string[];
	sub?: string;
	client_id?: string;
	scope?: string;
	exp?: number;
	nbf?: number;
	iat?: number;
	jti?: string;
	typ?: string;
	excludeClaims?: string[];
	extra?: Record<string, unknown>;
}

export type TokenFactory = (claims?: TokenClaimsInput) => Promise<string>;

export function createTokenFactory(keypair: Es256Keypair): TokenFactory {
	return async (input: TokenClaimsInput = {}): Promise<string> => {
		const now = Math.floor(Date.now() / 1000);
		const payload: Record<string, unknown> = {
			iss: input.iss ?? "https://auth.example.com",
			aud: input.aud ?? "https://api.example.com",
			sub: input.sub ?? "user123",
			client_id: input.client_id ?? "client456",
			scope: input.scope ?? "read:data write:data",
			exp: input.exp ?? now + 3600,
			nbf: input.nbf ?? now,
			iat: input.iat ?? now,
			jti: input.jti ?? "token-id-123",
			...(input.extra ?? {}),
		};
		for (const claim of input.excludeClaims ?? []) {
			delete payload[claim];
		}
		return await new SignJWT(payload)
			.setProtectedHeader({
				alg: "ES256",
				typ: input.typ ?? "at+jwt",
				kid: keypair.kid,
			})
			.sign(keypair.privateKey);
	};
}

export interface MockAsServerHandle {
	origin: string;
	metadataUrl: string;
	jwksUrl: string;
	close(): Promise<void>;
	readonly tokenRequests: Array<{
		body: URLSearchParams;
		headers: Record<string, string>;
	}>;
	readonly introspectionRequests: Array<{
		body: URLSearchParams;
		headers: Record<string, string>;
	}>;
	readonly revocationRequests: Array<{
		body: URLSearchParams;
		headers: Record<string, string>;
	}>;
}

export interface MockAsServerOptions {
	keypair: Es256Keypair;
	metadataOverrides?: Record<string, unknown>;
	/**
	 * Suffix appended to the server origin to form the advertised issuer
	 * (e.g. "/" to simulate an AS whose issuer identifier ends in a slash).
	 */
	issuerSuffix?: string;
	/**
	 * Path the metadata document is served at. Defaults to the RFC 8414
	 * well-known path for an issuer with no path component.
	 */
	metadataPath?: string;
	includeTokenEndpoint?: boolean;
	includeIntrospectionEndpoint?: boolean;
	includeRevocationEndpoint?: boolean;
	tokenResponse?: {
		status?: number;
		body?: unknown;
		headers?: Record<string, string>;
	};
	introspectionResponse?: {
		status?: number;
		body?: unknown;
	};
	revocationResponse?: {
		status?: number;
		body?: unknown;
	};
}

async function readBody(req: IncomingMessage): Promise<string> {
	return await new Promise<string>((resolve, reject) => {
		let data = "";
		req.on("data", (chunk: Buffer) => {
			data += chunk.toString("utf-8");
		});
		req.on("end", () => resolve(data));
		req.on("error", reject);
	});
}

function collectHeaders(req: IncomingMessage): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [k, v] of Object.entries(req.headers)) {
		if (typeof v === "string") {
			out[k.toLowerCase()] = v;
		} else if (Array.isArray(v)) {
			out[k.toLowerCase()] = v.join(",");
		}
	}
	return out;
}

export async function createMockAsServer(
	options: MockAsServerOptions,
): Promise<MockAsServerHandle> {
	const server: Server = createServer();
	const tokenRequests: MockAsServerHandle["tokenRequests"] = [];
	const introspectionRequests: MockAsServerHandle["introspectionRequests"] = [];
	const revocationRequests: MockAsServerHandle["revocationRequests"] = [];

	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const addr = server.address() as AddressInfo;
	const origin = `http://127.0.0.1:${addr.port}`;

	const baseMetadata: Record<string, unknown> = {
		issuer: `${origin}${options.issuerSuffix ?? ""}`,
		jwks_uri: `${origin}/.well-known/jwks.json`,
	};
	if (options.includeTokenEndpoint !== false) {
		baseMetadata.token_endpoint = `${origin}/oauth/token`;
	}
	if (options.includeIntrospectionEndpoint) {
		baseMetadata.introspection_endpoint = `${origin}/oauth/introspect`;
	}
	if (options.includeRevocationEndpoint) {
		baseMetadata.revocation_endpoint = `${origin}/oauth/revoke`;
	}
	const metadata: Record<string, unknown> = {
		...baseMetadata,
		...(options.metadataOverrides ?? {}),
	};

	const metadataPath =
		options.metadataPath ?? "/.well-known/oauth-authorization-server";
	const metadataUrl = `${origin}${metadataPath}`;
	const jwksUrl =
		typeof metadata.jwks_uri === "string"
			? metadata.jwks_uri
			: `${origin}/.well-known/jwks.json`;

	const sendJson = (
		res: ServerResponse,
		status: number,
		body: unknown,
		extraHeaders: Record<string, string> = {},
	) => {
		res.statusCode = status;
		res.setHeader("content-type", "application/json");
		for (const [k, v] of Object.entries(extraHeaders)) {
			res.setHeader(k, v);
		}
		res.end(typeof body === "string" ? body : JSON.stringify(body));
	};

	server.on("request", async (req, res) => {
		try {
			const url = req.url ?? "";
			if (req.method === "GET" && url === metadataPath) {
				sendJson(res, 200, metadata);
				return;
			}
			if (req.method === "GET" && url === "/.well-known/jwks.json") {
				sendJson(res, 200, options.keypair.jwks);
				return;
			}
			if (req.method === "POST" && url === "/oauth/token") {
				const raw = await readBody(req);
				tokenRequests.push({
					body: new URLSearchParams(raw),
					headers: collectHeaders(req),
				});
				const resp = options.tokenResponse ?? {};
				sendJson(
					res,
					resp.status ?? 200,
					resp.body ?? {
						access_token: "at_test",
						token_type: "Bearer",
						expires_in: 3600,
						scope: "",
					},
					resp.headers ?? {},
				);
				return;
			}
			if (req.method === "POST" && url === "/oauth/introspect") {
				const raw = await readBody(req);
				introspectionRequests.push({
					body: new URLSearchParams(raw),
					headers: collectHeaders(req),
				});
				const resp = options.introspectionResponse ?? {};
				sendJson(res, resp.status ?? 200, resp.body ?? { active: true });
				return;
			}
			if (req.method === "POST" && url === "/oauth/revoke") {
				const raw = await readBody(req);
				revocationRequests.push({
					body: new URLSearchParams(raw),
					headers: collectHeaders(req),
				});
				const resp = options.revocationResponse ?? {};
				sendJson(res, resp.status ?? 200, resp.body ?? {});
				return;
			}
			res.statusCode = 404;
			res.end();
		} catch (e) {
			res.statusCode = 500;
			res.end(String(e));
		}
	});

	return {
		origin,
		metadataUrl,
		jwksUrl,
		tokenRequests,
		introspectionRequests,
		revocationRequests,
		close: () =>
			new Promise<void>((resolve) => {
				server.close(() => resolve());
			}),
	};
}

/**
 * Fail the current test with an `Unimplemented` error to signal a catalog
 * case that the SDK does not yet expose sufficient surface to exercise.
 */
export function unimplemented(detail: string): never {
	throw new Error(`Unimplemented: ${detail}`);
}

import type { AuthplaneClient as AuthplaneClientType } from "../src/core/client.js";
import type { AuthplaneResource as AuthplaneResourceType } from "../src/core/resource.js";

export interface TestFixture {
	server: MockAsServerHandle;
	client: AuthplaneClientType;
	resource: AuthplaneResourceType;
	keypair: Es256Keypair;
	tokenFactory: TokenFactory;
	close(): Promise<void>;
}

/**
 * Stand up a mock AS, create an AuthplaneClient against it, and mint a
 * bound AuthplaneResource for verification tests. Callers must invoke
 * `close()` to clean up the HTTP server and client caches.
 */
export async function createTestFixture(
	options: Omit<MockAsServerOptions, "keypair"> & {
		keypair?: Es256Keypair;
		resourceScopes?: string[];
		resourcePath?: string;
		inboundDPoP?: import("../src/core/dpop.js").InboundDPoPOptions;
	} = {},
): Promise<TestFixture> {
	const { AuthplaneClient } = await import("../src/core/client.js");
	const { FetchSettings } = await import("../src/auth/fetchSettings.js");

	const keypair = options.keypair ?? (await generateEs256Keypair());
	const { keypair: _, inboundDPoP, ...rest } = options as MockAsServerOptions & {
		inboundDPoP?: import("../src/core/dpop.js").InboundDPoPOptions;
	};
	const server = await createMockAsServer({ keypair, ...rest });
	const noSsrf = new FetchSettings({
		ssrfProtection: false,
		allowHttp: true,
		allowLocalhost: true,
		allowPrivateNetworks: true,
	});
	const client = await AuthplaneClient.create({
		issuer: server.origin,
		fetchSettings: noSsrf,
	});
	const resourceUri = `${server.origin}${options.resourcePath ?? "/api"}`;
	const resource = client.resource({
		resource: resourceUri,
		scopes: options.resourceScopes ?? ["read:data"],
		...(inboundDPoP !== undefined ? { inboundDPoP } : {}),
	});
	const tokenFactory = createTokenFactory(keypair);
	return {
		server,
		client,
		resource,
		keypair,
		tokenFactory,
		async close(): Promise<void> {
			await client.close();
			await server.close();
		},
	};
}

export interface DpopKeypair {
	privateKey: KeyLike;
	publicJwk: JWK;
	jkt: string;
}

export async function generateDpopKeypair(): Promise<DpopKeypair> {
	const { privateKey, publicKey } = await generateKeyPair("ES256");
	const publicJwk = await exportJWK(publicKey);
	const jkt = await calculateJwkThumbprint(publicJwk, "sha256");
	return { privateKey: privateKey as KeyLike, publicJwk, jkt };
}

export interface SignDpopProofInput {
	keypair: DpopKeypair;
	method?: string;
	url?: string;
	iat?: number;
	jti?: string;
	ath?: string;
	nonce?: string;
	exp?: number;
	headerOverrides?: Record<string, unknown>;
	payloadOverrides?: Record<string, unknown>;
}

export async function signDpopProof(
	input: SignDpopProofInput,
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	const header: Record<string, unknown> = {
		alg: "ES256",
		typ: "dpop+jwt",
		jwk: input.keypair.publicJwk,
		...(input.headerOverrides ?? {}),
	};
	const payload: Record<string, unknown> = {
		htm: input.method ?? "GET",
		htu: input.url ?? "https://api.example.com/resource",
		jti: input.jti ?? randomUUID(),
		iat: input.iat ?? now,
		...(input.exp !== undefined ? { exp: input.exp } : {}),
		...(input.ath !== undefined ? { ath: input.ath } : {}),
		...(input.nonce !== undefined ? { nonce: input.nonce } : {}),
		...(input.payloadOverrides ?? {}),
	};
	// Symmetric algs require a raw secret; asymmetric ones use the ES256
	// keypair generated by `generateDpopKeypair`. This lets negative tests
	// declare a header `alg` that mismatches the key type (e.g. HS256) so
	// the verifier's alg allowlist can be exercised end-to-end.
	const alg = typeof header.alg === "string" ? header.alg : "ES256";
	const signingKey =
		alg === "HS256" || alg === "HS384" || alg === "HS512"
			? randomBytes(32)
			: input.keypair.privateKey;
	return await new SignJWT(payload)
		.setProtectedHeader(
			header as Parameters<typeof SignJWT.prototype.setProtectedHeader>[0],
		)
		.sign(signingKey);
}

export function staticMetadataFetcher(
	document: Record<string, unknown>,
): () => Promise<{
	document: Record<string, unknown>;
	expiresAt: number | undefined;
}> {
	return async () => ({ document, expiresAt: undefined });
}

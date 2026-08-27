import type { ArgumentsHost } from "@nestjs/common";
import { Logger } from "@nestjs/common";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
	AuthplaneError,
	DPoPNotSupported,
	DPoPReplayDetected,
	InsufficientScope,
	JWKSFetchError,
	TokenExpired,
	TokenMissing,
} from "@authplane/sdk/core";

import { AuthplaneExceptionFilter } from "../../src/application/authplane.exception-filter.js";
import { REQUIRED_SCOPES_REQUEST_KEY } from "../../src/infrastructure/request-adapter.js";
import type { AuthplaneModuleOptions } from "../../src/module/authplane.options.js";

function expressReply() {
	const chain: Record<string, unknown> = {};
	const reply = {
		setHeader: vi.fn((name: string, value: string) => {
			chain[`header:${name}`] = value;
		}),
		status: vi.fn((code: number) => {
			chain.status = code;
			return reply;
		}),
		json: vi.fn((body: unknown) => {
			chain.body = body;
			return reply;
		}),
	};
	return { reply, chain };
}

function fastifyReply() {
	const chain: Record<string, unknown> = {};
	const reply = {
		header: vi.fn((name: string, value: string) => {
			chain[`header:${name}`] = value;
			return reply;
		}),
		code: vi.fn((code: number) => {
			chain.status = code;
			return reply;
		}),
		send: vi.fn((body: unknown) => {
			chain.body = body;
			return reply;
		}),
	};
	return { reply, chain };
}

function makeHost(reply: unknown, req: unknown = {}): ArgumentsHost {
	return {
		switchToHttp: () => ({
			getRequest: () => req,
			getResponse: () => reply,
			getNext: () => undefined,
		}),
	} as unknown as ArgumentsHost;
}

const OPTIONS: AuthplaneModuleOptions = {
	issuer: "https://auth.example.com",
	resource: "https://api.example.com/mcp",
	requiredScopes: ["tools/add"],
};

const RESOURCE = {
	prmDocumentUrl: () =>
		"https://api.example.com/.well-known/oauth-protected-resource/mcp",
} as const;

function newFilter(options: AuthplaneModuleOptions = OPTIONS) {
	return new AuthplaneExceptionFilter(
		options,
		RESOURCE as unknown as ConstructorParameters<
			typeof AuthplaneExceptionFilter
		>[1],
	);
}

describe("AuthplaneExceptionFilter — TokenMissing (401)", () => {
	it("sends 401 JSON + Bearer challenge on Express-style responses", () => {
		const { reply, chain } = expressReply();
		newFilter().catch(new TokenMissing("nope"), makeHost(reply));

		expect(chain.status).toBe(401);
		expect(chain.body).toEqual({
			error: "invalid_token",
			error_description: "nope",
		});
		expect(reply.setHeader).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringContaining('Bearer realm="https://api.example.com/mcp"'),
		);
		expect(reply.setHeader).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringContaining('error="invalid_token"'),
		);
		expect(reply.setHeader).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringContaining(
				'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"',
			),
		);
	});

	it("sends 401 JSON + Bearer challenge on Fastify-style responses", () => {
		const { reply, chain } = fastifyReply();
		newFilter().catch(new TokenMissing("nope"), makeHost(reply));

		expect(chain.status).toBe(401);
		expect(chain.body).toEqual({
			error: "invalid_token",
			error_description: "nope",
		});
		expect(reply.header).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringContaining('error="invalid_token"'),
		);
		expect(reply.code).toHaveBeenCalledWith(401);
		expect(reply.send).toHaveBeenCalled();
	});

	it("maps TokenExpired to 401 too", () => {
		const { reply, chain } = expressReply();
		newFilter().catch(new TokenExpired("expired"), makeHost(reply));
		expect(chain.status).toBe(401);
	});
});

describe("AuthplaneExceptionFilter — InsufficientScope (403)", () => {
	it("sends 403 + scope=\"…\" from the request stash (route-level wins)", () => {
		const { reply, chain } = expressReply();
		const req = {
			[REQUIRED_SCOPES_REQUEST_KEY]: ["tools/multiply"],
		};
		newFilter().catch(
			new InsufficientScope("need more"),
			makeHost(reply, req),
		);

		expect(chain.status).toBe(403);
		expect(chain.body).toEqual({
			error: "insufficient_scope",
			error_description: "need more",
		});
		expect(reply.setHeader).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringContaining('scope="tools/multiply"'),
		);
		expect(reply.setHeader).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringContaining('error="insufficient_scope"'),
		);
	});

	it("falls back to options.requiredScopes when the stash is empty", () => {
		const { reply } = expressReply();
		newFilter().catch(new InsufficientScope("need more"), makeHost(reply));
		expect(reply.setHeader).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringContaining('scope="tools/add"'),
		);
	});

	it("falls back to options.scopes when both stash and requiredScopes are absent", () => {
		const { reply } = expressReply();
		newFilter({
			issuer: "https://auth.example.com",
			resource: "https://api.example.com/mcp",
			scopes: ["tools/add"],
		}).catch(new InsufficientScope("need more"), makeHost(reply));
		expect(reply.setHeader).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringContaining('scope="tools/add"'),
		);
	});
});

describe("AuthplaneExceptionFilter — DPoP scheme handling (RFC 9449 §7.1)", () => {
	it("emits the DPoP scheme when the error is a DPoPError subclass", () => {
		const { reply } = expressReply();
		newFilter().catch(
			new DPoPReplayDetected("proof seen"),
			makeHost(reply),
		);
		expect(reply.setHeader).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringMatching(/^DPoP /u),
		);
	});

	it("emits the Bearer scheme for DPoPNotSupported (the carve-out)", () => {
		const { reply } = expressReply();
		newFilter().catch(
			new DPoPNotSupported("resource not DPoP-aware"),
			makeHost(reply),
		);
		expect(reply.setHeader).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringMatching(/^Bearer /u),
		);
	});

	it("emits the Bearer scheme for non-DPoP errors", () => {
		const { reply } = expressReply();
		newFilter().catch(new TokenMissing("plain"), makeHost(reply));
		expect(reply.setHeader).toHaveBeenCalledWith(
			"WWW-Authenticate",
			expect.stringMatching(/^Bearer /u),
		);
	});
});

describe("AuthplaneExceptionFilter — upstream-failure mapping", () => {
	it("maps JWKSFetchError to 503 via core httpStatus()", () => {
		const { reply, chain } = expressReply();
		newFilter().catch(
			new JWKSFetchError("AS unreachable"),
			makeHost(reply),
		);
		expect(chain.status).toBe(503);
	});
});

describe("AuthplaneExceptionFilter — header sanitisation", () => {
	it("strips quote / CR / LF / backslash from interpolated values", () => {
		const { reply } = expressReply();
		newFilter().catch(
			new TokenMissing('bad "quotes"\r\nInjected: x\\path'),
			makeHost(reply),
		);
		const headerCall = reply.setHeader.mock.calls.find(
			(call) => call[0] === "WWW-Authenticate",
		);
		expect(headerCall).toBeDefined();
		const value = headerCall?.[1] as string;
		expect(value).not.toContain("\r");
		expect(value).not.toContain("\n");
		expect(value).not.toContain('"quotes"');
		expect(value).not.toContain("x\\path");
		const matched = value.match(/error_description="([^"]*)"/u);
		expect(matched?.[1]).toBeDefined();
	});

	it("also sanitises the realm value", () => {
		const { reply } = expressReply();
		newFilter({
			...OPTIONS,
			resource: 'https://api.example.com/x"; injected"',
		}).catch(new TokenMissing("oops"), makeHost(reply));
		const headerCall = reply.setHeader.mock.calls.find(
			(call) => call[0] === "WWW-Authenticate",
		);
		const value = headerCall?.[1] as string;
		expect(value).not.toContain('"; injected"');
	});
});

describe("AuthplaneExceptionFilter — PRM URL handling", () => {
	let warnSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		warnSpy = vi.spyOn(Logger.prototype, "warn").mockImplementation(() => {});
	});

	afterEach(() => {
		warnSpy.mockRestore();
	});

	function buildFailingFilter(): AuthplaneExceptionFilter {
		const failing = {
			prmDocumentUrl: () => {
				throw new Error("not configured");
			},
		} as const;
		return new AuthplaneExceptionFilter(
			OPTIONS,
			failing as unknown as ConstructorParameters<
				typeof AuthplaneExceptionFilter
			>[1],
		);
	}

	it("omits resource_metadata when prmDocumentUrl() throws", () => {
		const { reply } = expressReply();
		buildFailingFilter().catch(new TokenMissing("nope"), makeHost(reply));
		const headerCall = reply.setHeader.mock.calls.find(
			(call) => call[0] === "WWW-Authenticate",
		);
		expect(headerCall?.[1]).not.toContain("resource_metadata=");
	});

	it("warns exactly once even when the resource keeps failing", () => {
		const filter = buildFailingFilter();
		const { reply: reply1 } = expressReply();
		const { reply: reply2 } = expressReply();
		const { reply: reply3 } = expressReply();
		filter.catch(new TokenMissing("nope"), makeHost(reply1));
		filter.catch(new TokenMissing("nope"), makeHost(reply2));
		filter.catch(new TokenMissing("nope"), makeHost(reply3));
		expect(warnSpy).toHaveBeenCalledTimes(1);
		expect(warnSpy.mock.calls[0]?.[0]).toContain("prmDocumentUrl() threw");
		expect(warnSpy.mock.calls[0]?.[0]).toContain("not configured");
	});
});

describe("AuthplaneExceptionFilter — Fastify defensive fallback", () => {
	it("falls back to r.send(body) when r.code() returns void (older Fastify)", () => {
		const chain: Record<string, unknown> = {};
		const reply = {
			header: vi.fn(),
			code: vi.fn((code: number) => {
				chain.status = code;
				return undefined;
			}),
			send: vi.fn((body: unknown) => {
				chain.body = body;
				return reply;
			}),
		};
		newFilter().catch(new TokenMissing("nope"), makeHost(reply));
		expect(reply.send).toHaveBeenCalled();
		expect(chain.status).toBe(401);
	});

	it("does not throw when status() returns void without .json (degenerate reply)", () => {
		const reply = {
			setHeader: vi.fn(),
			status: vi.fn(() => undefined),
		};
		expect(() =>
			newFilter().catch(new TokenMissing("nope"), makeHost(reply)),
		).not.toThrow();
		expect(reply.status).toHaveBeenCalledWith(401);
	});

	it("does not throw when reply has neither setHeader nor header", () => {
		const reply = {
			status: vi.fn(() => ({ json: vi.fn() })),
		};
		expect(() =>
			newFilter().catch(new TokenMissing("nope"), makeHost(reply)),
		).not.toThrow();
	});

	it("does not throw when reply is null", () => {
		expect(() =>
			newFilter().catch(new TokenMissing("nope"), makeHost(null)),
		).not.toThrow();
	});
});

describe("AuthplaneExceptionFilter — @Catch contract", () => {
	it("claims AuthplaneError, not raw Error", () => {
		// `@Catch()` stores exception *classes*, so the element type is a
		// constructor, not `unknown`. It cannot be `Function` — biome's
		// noBannedTypes rejects that — so this is the top constructor type,
		// which keeps "these are classes" while staying lint-clean.
		const catchMetadata = Reflect.getMetadata?.(
			"__filterCatchExceptions__",
			AuthplaneExceptionFilter,
		) as readonly (abstract new (...args: never[]) => unknown)[] | undefined;
		expect(catchMetadata).toBeDefined();
		expect(catchMetadata).toContain(AuthplaneError);
		// Importantly, NOT raw Error — that would swallow every HttpException
		// when the filter is mounted globally.
		expect(catchMetadata).not.toContain(Error);
	});
});

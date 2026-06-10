import { describe, expect, it } from "vitest";

import { extractBearerToken } from "../../src/core/bearerToken.js";
import { TokenMissing } from "../../src/core/errors.js";

describe("extractBearerToken", () => {
	it("returns the token from a canonical `Bearer <token>` header", () => {
		expect(extractBearerToken("Bearer abc123")).toBe("abc123");
	});

	it("is case-insensitive on the scheme (RFC 6750 §2.1)", () => {
		expect(extractBearerToken("bearer abc123")).toBe("abc123");
		expect(extractBearerToken("BEARER abc123")).toBe("abc123");
		expect(extractBearerToken("BeArEr abc123")).toBe("abc123");
	});

	it("accepts the DPoP authentication scheme (RFC 9449 §7.1)", () => {
		expect(extractBearerToken("DPoP abc123")).toBe("abc123");
	});

	it("is case-insensitive on the DPoP scheme", () => {
		expect(extractBearerToken("dpop abc123")).toBe("abc123");
		expect(extractBearerToken("DPOP abc123")).toBe("abc123");
		expect(extractBearerToken("DpOp abc123")).toBe("abc123");
	});

	it("throws TokenMissing when the header is undefined", () => {
		expect(() => extractBearerToken(undefined)).toThrow(TokenMissing);
		expect(() => extractBearerToken(undefined)).toThrow(
			"Missing Authorization header",
		);
	});

	it("throws TokenMissing when the header is empty", () => {
		expect(() => extractBearerToken("")).toThrow(TokenMissing);
		expect(() => extractBearerToken("")).toThrow(
			"Missing Authorization header",
		);
	});

	it("throws TokenMissing when the scheme is not Bearer/DPoP", () => {
		expect(() => extractBearerToken("Basic dXNlcjpwYXNz")).toThrow(
			TokenMissing,
		);
		expect(() => extractBearerToken("Basic dXNlcjpwYXNz")).toThrow(
			"Invalid Authorization header format, expected 'Bearer TOKEN' or 'DPoP TOKEN'",
		);
	});

	it("throws TokenMissing when no scheme is present", () => {
		expect(() => extractBearerToken("abc")).toThrow(TokenMissing);
	});

	it("throws TokenMissing when the token part is missing", () => {
		expect(() => extractBearerToken("Bearer")).toThrow(TokenMissing);
	});

	it("throws TokenMissing when the token part is empty (trailing space)", () => {
		expect(() => extractBearerToken("Bearer ")).toThrow(TokenMissing);
	});

	it("rejects extra whitespace-separated fields after the token", () => {
		expect(() => extractBearerToken("Bearer abc extra")).toThrow(TokenMissing);
	});

	it("rejects tab separators between scheme and token", () => {
		expect(() => extractBearerToken("Bearer\tabc")).toThrow(TokenMissing);
	});

	it("rejects multiple spaces between scheme and token", () => {
		expect(() => extractBearerToken("Bearer  abc")).toThrow(TokenMissing);
	});
});

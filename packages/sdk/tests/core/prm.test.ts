import { describe, expect, it } from "vitest";

import { buildPrm, validateIssuerIdentifier } from "../../src/core/index.js";

describe("buildPrm", () => {
	it("rfc9728-prm-must-contain-required-fields — builds RFC9728-like metadata shape", () => {
		const prm = buildPrm(
			"https://auth.example.com",
			"https://api.example.com/mcp",
			["tools/query", "tools/write"],
		);

		expect(prm.resource).toBe("https://api.example.com/mcp");
		expect(prm.authorization_servers).toEqual(["https://auth.example.com"]);
		expect(prm.bearer_methods_supported).toEqual(["header"]);
		expect(prm.resource_signing_alg_values_supported).toEqual([
			"RS256",
			"ES256",
		]);
		expect(prm.scopes_supported).toEqual(["tools/query", "tools/write"]);
	});

	// `buildPrm` is exported and documented as the standalone way to serve the
	// PRM document, so it is a public boundary and not merely an internal helper
	// reached through a gated caller. An identifier it accepted but the document
	// URL derivation reshapes produces the RFC 9728 §3.3 mismatch a conformant
	// client responds to by discarding the document — which surfaces as an
	// unreachable resource server, not as a configuration error.
	it("rejects a resource identifier carrying a fragment", () => {
		expect(() =>
			buildPrm("https://auth.example.com", "https://api.example.com/mcp#frag", [
				"read",
			]),
		).toThrow(TypeError);
		expect(() =>
			buildPrm("https://auth.example.com", "https://api.example.com/mcp#frag", [
				"read",
			]),
		).toThrow(/must not contain a fragment component/);
	});

	it("rejects a resource identifier that is not an absolute URL", () => {
		for (const resource of [
			"/mcp",
			"//api.example.com/mcp",
			"https:api.example.com/mcp",
			"urn:example:api",
		]) {
			expect(() =>
				buildPrm("https://auth.example.com", resource, ["read"]),
			).toThrow(/must be an absolute URL with a scheme and a host/);
		}
	});

	it("rejects a resource identifier whose query is not a valid RFC 3986 query", () => {
		expect(() =>
			buildPrm(
				"https://auth.example.com",
				"https://api.example.com/mcp?a=%zz",
				["read"],
			),
		).toThrow(/query must be a valid RFC 3986/);
	});

	it("accepts the identifier shapes the derivation preserves byte-for-byte", () => {
		expect(
			buildPrm("https://auth.example.com", "https://api.example.com/mcp?v=2", [
				"read",
			]).resource,
		).toBe("https://api.example.com/mcp?v=2");
		// The profile deliberately admits http for local development, and any
		// scheme that carries a host.
		expect(
			buildPrm("https://auth.example.com", "http://localhost:8080/mcp", [
				"read",
			]).resource,
		).toBe("http://localhost:8080/mcp");
	});
	// The issuer is the other URL-shaped member of the document `buildPrm`
	// serves, so the builder runs the gate on it too. The axes themselves are
	// pinned against `validateIssuerIdentifier` directly, below; this is the
	// wiring.
	it("runs the issuer gate", () => {
		expect(() =>
			buildPrm(
				"https://svc:s3cr3t@auth.example.com",
				"https://api.example.com/mcp",
				["read"],
			),
		).toThrow(/must not include a userinfo component/u);
	});

	it("accepts the issuer shapes the derivation preserves", () => {
		expect(
			buildPrm(
				"https://auth.example.com/tenant-a",
				"https://api.example.com/mcp",
				["read"],
			).authorization_servers,
		).toEqual(["https://auth.example.com/tenant-a"]);
		// A trailing slash is an identity difference, not a defect — the gate
		// must not reject it, and must not normalise it away either.
		expect(
			buildPrm("https://auth.example.com/", "https://api.example.com/mcp", [
				"read",
			]).authorization_servers,
		).toEqual(["https://auth.example.com/"]);
	});
});

/**
 * All five axes of the issuer gate, pinned against `validateIssuerIdentifier`
 * itself rather than through `buildPrm`.
 *
 * The resource-side axes are pinned the same way in `resourceIndicator.test.ts`;
 * these used to sit under `describe("buildPrm")`, which gave equivalent coverage
 * but left the two halves of the same module tested at different levels. Wiring
 * — that `buildPrm`, `buildMetadataUrl` and `AuthplaneClient.create` all reach
 * this gate — stays pinned where each of those lives.
 */
describe("validateIssuerIdentifier query and fragment (RFC 8414 §2)", () => {
	it("rejects a query or a fragment, including the bare delimiters", () => {
		for (const issuer of [
			"https://auth.example.com?x=1",
			"https://auth.example.com#frag",
			"https://auth.example.com?",
			"https://auth.example.com#",
		]) {
			expect(() => validateIssuerIdentifier(issuer)).toThrow(TypeError);
			expect(() => validateIssuerIdentifier(issuer)).toThrow(
				/must not contain a query or fragment component \(RFC 8414 §2\)/u,
			);
		}
	});

	it("does not echo a credential-shaped query", () => {
		const issuer = "https://auth.example.com?token=s3cr3t";
		expect(() => validateIssuerIdentifier(issuer)).toThrow(
			"https://auth.example.com",
		);
		expect(() => validateIssuerIdentifier(issuer)).not.toThrow("s3cr3t");
	});
});

describe("validateIssuerIdentifier whitespace and control characters (RFC 3986 §2)", () => {
	it("rejects whitespace the WHATWG parser would trim or strip away", () => {
		// Every one of these parsed with a non-empty host before the gate: the
		// parser trims leading and trailing C0-or-space and removes tab, CR and
		// LF anywhere in the input. The issuer is published verbatim in
		// `authorization_servers` and stored byte-for-byte as the expected `iss`,
		// while the `.well-known` location is derived from the cleaned parse.
		for (const issuer of [
			"https://auth.example.com\n",
			"\nhttps://auth.example.com",
			"https://auth.example.com ",
			"https://auth.exa\tmple.com",
			"https://auth.example.com/ten ant",
		]) {
			expect(() => validateIssuerIdentifier(issuer)).toThrow(TypeError);
			expect(() => validateIssuerIdentifier(issuer)).toThrow(
				/must not contain whitespace or control characters/u,
			);
		}
	});

	it("rejects the boundary codepoints of the class", () => {
		// The three ranges the class is built from: C0 and space, DEL and the C1
		// controls, and what Unicode `\s` adds on top. The last two are the ones
		// `JSON.stringify` alone would emit raw.
		for (const char of [
			"\u0000",
			"\u001f",
			"\u007f",
			"\u009f",
			"\u00a0",
			"\u2028",
			"\u3000",
			"\ufeff",
		]) {
			expect(() =>
				validateIssuerIdentifier(`https://auth.example.com/${char}t`),
			).toThrow(/must not contain whitespace or control characters/u);
		}
	});

	it("names the offending codepoint and its offset", () => {
		// A tab keeps `JSON.stringify`'s own short escape; only the codepoints it
		// has no escape for are rewritten to `\uXXXX`.
		expect(() =>
			validateIssuerIdentifier("https://auth.exa\tmple.com"),
		).toThrow('invalid character "\\t" at offset 16');
		expect(() =>
			validateIssuerIdentifier("https://auth.example.com/\u00a0t"),
		).toThrow('invalid character "\\u00a0" at offset 25');
	});

	it("renders the offending codepoint as an escape, never as the raw byte", () => {
		// `JSON.stringify` is not enough on its own: it emits DEL, the C1
		// controls, U+00A0, U+2028, U+3000 and U+FEFF raw, so the message would
		// carry into a startup log exactly the invisible byte it is reporting.
		for (const char of ["\u007f", "\u009f", "\u00a0", "\u2028", "\u3000", "\ufeff"]) {
			const message = String(
				(() => {
					try {
						validateIssuerIdentifier(`https://auth.example.com/${char}`);
					} catch (error) {
						return (error as Error).message;
					}
					return "did not throw";
				})(),
			);
			expect(message).toContain("must not contain whitespace or control");
			expect(message).not.toContain(char);
		}
	});

	it("accepts an issuer with no whitespace at all", () => {
		expect(() =>
			validateIssuerIdentifier("https://auth.example.com/tenant-a"),
		).not.toThrow();
	});
});

describe("validateIssuerIdentifier absolute-URL requirement (RFC 8414 §2, §3.1)", () => {
	it("rejects a relative, empty, opaque or authority-less issuer", () => {
		for (const issuer of [
			"/auth",
			"",
			"//auth.example.com",
			"urn:example:as",
			"https:auth.example.com",
			"https:/auth.example.com",
		]) {
			expect(() => validateIssuerIdentifier(issuer)).toThrow(TypeError);
			expect(() => validateIssuerIdentifier(issuer)).toThrow(
				/must be an absolute URL with a scheme and a host \(RFC 8414 §2, §3\.1\)/u,
			);
		}
	});

	it("rejects an invalid port at the parse, with no port check of its own", () => {
		// The gate carries no port branch of its own: `new URL` throws for a
		// port that is not a decimal number in range, so `parsed` stays undefined
		// and the absoluteness branch reports it. Pinned rather than duplicated as
		// a redundant check — if the platform ever starts accepting these, this
		// test is what fails.
		for (const issuer of [
			"https://auth.example.com:80O",
			"https://auth.example.com:99999",
			"https://auth.example.com:-1",
		]) {
			expect(() => validateIssuerIdentifier(issuer)).toThrow(
				/must be an absolute URL with a scheme and a host/u,
			);
		}
	});

	it("accepts http and a non-special scheme with a host", () => {
		// The same deliberate profile relaxation the resource gate makes.
		expect(() =>
			validateIssuerIdentifier("http://localhost:8080"),
		).not.toThrow();
		expect(() =>
			validateIssuerIdentifier("https://auth.example.com:8443/tenant-a"),
		).not.toThrow();
	});
});

describe("validateIssuerIdentifier userinfo requirement (RFC 9110 §4.2.4)", () => {
	it("rejects a userinfo component and does not echo the credential", () => {
		const issuer = "https://svc:s3cr3t@auth.example.com";
		expect(() => validateIssuerIdentifier(issuer)).toThrow(
			/must not include a userinfo component in its authority \(RFC 9110 §4\.2\.4\)/u,
		);
		expect(() => validateIssuerIdentifier(issuer)).toThrow("auth.example.com");
		expect(() => validateIssuerIdentifier(issuer)).not.toThrow("s3cr3t");
	});

	it("rejects a username-only and an empty userinfo", () => {
		for (const issuer of [
			"https://svc@auth.example.com",
			"https://@auth.example.com",
		]) {
			expect(() => validateIssuerIdentifier(issuer)).toThrow(
				/must not include a userinfo component/u,
			);
		}
	});
});

describe("validateIssuerIdentifier message ordering and quoting", () => {
	it("reports the query or fragment ahead of the whitespace", () => {
		// Ordering pin. It is also what makes the quoting below load-bearing:
		// the first axis to fire is the one that has to render a raw control
		// character the whitespace axis has not reached yet.
		expect(() =>
			validateIssuerIdentifier("\nhttps://auth.example.com#frag"),
		).toThrow(/must not contain a query or fragment component/u);
	});

	it("never lets a raw control character reach the message, on any axis", () => {
		// The demonstrated leak: a leading LF fails the anchored
		// `SCHEME_AND_AUTHORITY` test the redaction needs to take its parsed
		// branch, so the fallback hands back the raw prefix — and each of these
		// four axes embedded that prefix unquoted.
		for (const issuer of [
			// Fragment, reported ahead of the whitespace axis.
			"\nhttps://auth.example.com#frag",
			// Absoluteness.
			"\u0000https:auth.example.com",
			// Userinfo, reached only once the string parses — the C1 control
			// survives the parse rather than being trimmed.
			"https://svc@auth.example.com/\u0085t",
		]) {
			let message = "did not throw";
			try {
				validateIssuerIdentifier(issuer);
			} catch (error) {
				message = (error as Error).message;
			}
			expect(message).not.toBe("did not throw");
			for (const char of ["\n", "\u0000", "\u0085"]) {
				expect(message).not.toContain(char);
			}
		}
	});
});

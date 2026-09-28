import { describe, expect, it } from "vitest";

import { AuthplaneResource } from "../../src/core/resource.js";
import { validateResourceMetadataUrl } from "../../src/core/prm.js";

function buildResource(
	resource: string,
	resourceMetadataUrl?: string,
): AuthplaneResource {
	return new AuthplaneResource({
		resource,
		scopes: ["read"],
		...(resourceMetadataUrl !== undefined ? { resourceMetadataUrl } : {}),
		issuer: "https://auth.example.com",
		metadataCache: {},
		fetchSettings: {},
		getJwksCache: () => ({}),
	} as unknown as ConstructorParameters<typeof AuthplaneResource>[0]);
}

describe("validateResourceMetadataUrl (RFC 9728 §3)", () => {
	it("accepts absolute URLs with a scheme and a host", () => {
		for (const url of [
			"https://auth.example.com/.well-known/oauth-protected-resource/mcp",
			"https://auth.example.com/.well-known/oauth-protected-resource",
			"https://auth.example.com:8443/.well-known/oauth-protected-resource/mcp",
			// `http` stays accepted, as it does on the issuer and resource
			// gates — local development, not a narrowing decision taken here.
			"http://localhost:9000/.well-known/oauth-protected-resource/mcp",
			// A query is legal: the derived URL carries the resource
			// identifier's query through, so an override must be able to name
			// the same document.
			"https://auth.example.com/.well-known/oauth-protected-resource/mcp?tenant=a",
		]) {
			expect(() => validateResourceMetadataUrl(url)).not.toThrow();
		}
	});

	it("rejects a fragment", () => {
		expect(() =>
			validateResourceMetadataUrl("https://auth.example.com/prm#frag"),
		).toThrow(/fragment component/u);
	});

	it("rejects anything that is not an absolute URL with a scheme and a host", () => {
		for (const url of [
			"/.well-known/oauth-protected-resource/mcp",
			"//auth.example.com/prm",
			"urn:example:prm",
			"https:auth.example.com/prm",
			"not a url",
			// Leading whitespace defeats the scheme/authority match before the
			// quoted-string scan ever runs; rejected either way.
			" https://auth.example.com/prm",
		]) {
			expect(() => validateResourceMetadataUrl(url)).toThrow(
				/absolute URL with a scheme and a host/u,
			);
		}
	});

	it("rejects a scheme the client cannot dereference", () => {
		for (const url of [
			"mcp://auth.example.com/prm",
			"ftp://auth.example.com/prm",
			"ws://auth.example.com/prm",
		]) {
			expect(() => validateResourceMetadataUrl(url)).toThrow(
				/http or https scheme/u,
			);
		}
	});

	it("rejects octets that cannot survive the quoted-string", () => {
		// WHATWG accepts all of these in a path and the override is advertised
		// verbatim — never re-derived — so without this gate the challenge
		// sanitiser would silently emit a well-formed challenge naming an
		// unfetchable URL.
		for (const url of [
			'https://auth.example.com/prm"x',
			"https://auth.example.com/prm\\x",
			"https://auth.example.com/prm doc",
			"https://auth.example.com/prm\tx",
			"https://auth.example.com/prm\nx",
			"https://auth.example.com/prm\n",
		]) {
			expect(() => validateResourceMetadataUrl(url)).toThrow(
				/literal double quote|literal backslash|non-URI octet/u,
			);
		}
	});

	it("rejects an out-of-grammar query", () => {
		expect(() =>
			validateResourceMetadataUrl("https://auth.example.com/prm?filter[a]=b"),
		).toThrow(/RFC 3986 §3.4 query/u);
	});

	it("rejects a userinfo component and keeps the credential out of the message", () => {
		expect(() =>
			validateResourceMetadataUrl("https://svc:pw@auth.example.com/prm"),
		).toThrow(/userinfo component/u);
		expect(() =>
			validateResourceMetadataUrl("https://svc:pw@auth.example.com/prm"),
		).not.toThrow(/pw/u);
	});

	it("throws TypeError, like the sibling identifier gates", () => {
		expect(() => validateResourceMetadataUrl("/prm")).toThrow(TypeError);
	});
});

describe("AuthplaneResource.resourceMetadataUrl()", () => {
	it("returns the derived document URL when no override is configured", () => {
		// The default is the behaviour every existing challenge assertion in
		// this repo pins; this is the statement of it in one place.
		const resource = buildResource("https://api.example.com/mcp");
		expect(resource.resourceMetadataUrl()).toBe(
			"https://api.example.com/.well-known/oauth-protected-resource/mcp",
		);
		expect(resource.resourceMetadataUrl()).toBe(resource.prmDocumentUrl());
	});

	it("returns the configured override verbatim", () => {
		// The AS-hosted topology: authserver >= 0.2.0 serves the document for
		// every registered Resource at `<issuer>/.well-known/
		// oauth-protected-resource/{ref}` and the resource server only points
		// at it.
		const resource = buildResource(
			"https://api.example.com/mcp",
			"https://auth.example.com/.well-known/oauth-protected-resource/mcp",
		);
		expect(resource.resourceMetadataUrl()).toBe(
			"https://auth.example.com/.well-known/oauth-protected-resource/mcp",
		);
	});

	it("leaves the derived URL and the served document alone", () => {
		// Only the advertisement moves. `prmDocumentUrl()` is what the
		// adapters mount their PRM route at, and the document's own `resource`
		// member is what RFC 9728 §3.3 binds to the identifier the client
		// used — neither may follow the override.
		const resource = buildResource(
			"https://api.example.com/mcp",
			"https://auth.example.com/.well-known/oauth-protected-resource/mcp",
		);
		expect(resource.prmDocumentUrl()).toBe(
			"https://api.example.com/.well-known/oauth-protected-resource/mcp",
		);
		expect(resource.prmResponse().resource).toBe(
			"https://api.example.com/mcp",
		);
	});

	it("rejects an invalid override at construction", () => {
		expect(() =>
			buildResource("https://api.example.com/mcp", "/.well-known/prm"),
		).toThrow(/absolute URL with a scheme and a host/u);
		expect(() =>
			buildResource("https://api.example.com/mcp", "https://auth.example.com#f"),
		).toThrow(TypeError);
	});

	// The value is stored and advertised exactly as typed, so nothing downstream
	// percent-encodes these the way WHATWG normalisation does for the resource
	// identifier's path. Held to the whole non-URI set (RFC 3986 §2), not just
	// the four octets the first cut covered — otherwise the same octet is
	// refused inside the query, which has its own grammar check, and accepted in
	// the path.
	it.each([
		[
			"a raw non-ASCII path segment",
			"https://auth.example.com/.well-known/oauth-protected-resource/münchen",
		],
		["an IDN host given as unicode", "https://café.example.com/prm"],
		["a pipe in the path", "https://auth.example.com/prm|x"],
		["a brace in the path", "https://auth.example.com/pr{m}"],
		["an angle bracket in the path", "https://auth.example.com/pr<m>"],
		["a backtick in the path", "https://auth.example.com/pr`m"],
		["a caret in the path", "https://auth.example.com/pr^m"],
	])("rejects %s", (_label, url) => {
		expect(() => buildResource("https://api.example.com/mcp", url)).toThrow(
			TypeError,
		);
	});

	it("accepts the punycode spelling of an IDN host", () => {
		const resource = buildResource(
			"https://api.example.com/mcp",
			"https://xn--caf-dma.example.com/prm",
		);
		expect(resource.resourceMetadataUrl()).toBe(
			"https://xn--caf-dma.example.com/prm",
		);
	});
});

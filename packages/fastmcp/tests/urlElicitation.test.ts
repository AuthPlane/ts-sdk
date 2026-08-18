import { assert, describe, expect, it } from "vitest";
import { UrlElicitationRequiredError } from "@modelcontextprotocol/sdk/types.js";
import { AuthError, ConsentRequiredError } from "@authplane/sdk/core";

import { toUrlElicitationRequiredError } from "../src/urlElicitation.js";

function makeConsentError(consentUrl: string | null): ConsentRequiredError {
	return new ConsentRequiredError("consent needed", {
		serviceId: "calendar",
		causeDetail: "missing_consent",
		consentUrl,
		statusCode: 400,
	});
}

describe("toUrlElicitationRequiredError", () => {
	it("maps ConsentRequiredError with consentUrl to -32042", () => {
		const result = toUrlElicitationRequiredError(
			makeConsentError("https://as.example.com/consent?service=calendar"),
			{ createElicitationId: () => "elicitation-123" },
		);
		expect(result).toBeInstanceOf(UrlElicitationRequiredError);
		assert(result);
		expect(result.code).toBe(-32042);
		expect(result.elicitations[0]?.elicitationId).toBe("elicitation-123");
		expect(result.elicitations[0]?.url).toBe(
			"https://as.example.com/consent?service=calendar",
		);
	});

	it("uses ConsentRequiredError.describe() for the elicitation message", () => {
		const err = makeConsentError("https://as.example.com/c");
		const result = toUrlElicitationRequiredError(err);
		expect(result).not.toBeNull();
		assert(result);
		expect(result.elicitations[0]?.message).toBe(err.describe());
	});

	it("returns null for ConsentRequiredError without consentUrl", () => {
		expect(toUrlElicitationRequiredError(makeConsentError(null))).toBeNull();
	});

	it("returns null for non-AuthError", () => {
		expect(toUrlElicitationRequiredError(new Error("boom"))).toBeNull();
	});

	it("returns null for AuthError with non-consent code", () => {
		const err = new AuthError("nope", { code: "invalid_grant", statusCode: 400 });
		expect(toUrlElicitationRequiredError(err)).toBeNull();
	});

	it("maps interaction_required code", () => {
		const err = new ConsentRequiredError("interaction needed", {
			serviceId: "drive",
			causeDetail: "needs_user",
			consentUrl: "https://as.example.com/interaction?service=drive",
			oauthCode: "interaction_required",
		});
		const result = toUrlElicitationRequiredError(err, {
			createElicitationId: () => "el-2",
		});
		expect(result).toBeInstanceOf(UrlElicitationRequiredError);
		assert(result);
		expect(result.elicitations[0]?.elicitationId).toBe("el-2");
	});

	it("generates a UUID elicitationId by default", () => {
		const result = toUrlElicitationRequiredError(
			makeConsentError("https://as.example.com/c"),
		);
		assert(result);
		expect(result.elicitations[0]?.elicitationId).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
		);
	});
});


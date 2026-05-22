import { describe, expect, it } from "vitest";

import {
	AuthError,
	ConsentRequiredError,
	DPoPBindingMismatch,
	DPoPNotSupported,
	DPoPProofMissing,
	DPoPReplayDetected,
	InsufficientScope,
	InvalidClaims,
	InvalidDPoPProof,
	InvalidGrant,
	InvalidSignature,
	JWKSFetchError,
	MetadataFetchError,
	MissingMetadataEndpoint,
	ProtocolError,
	TokenExpired,
	TokenMissing,
	TokenRevoked,
	VerifierRuntimeError,
	httpStatus,
	mapOAuthError,
	wwwAuthenticate,
} from "../../src/core/errors.js";

describe("mapOAuthError", () => {
	it("maps consent_required into ConsentRequiredError with metadata", () => {
		const err = mapOAuthError("token exchange", 400, {
			error: "consent_required",
			error_description: "user must grant access",
			consent_url: "https://as.example.com/consent?service=calendar",
			service_id: "calendar",
			cause: "missing_user_consent",
		});

		expect(err).toBeInstanceOf(ConsentRequiredError);
		const consent = err as ConsentRequiredError;
		expect(consent.serviceId).toBe("calendar");
		expect(consent.causeDetail).toBe("missing_user_consent");
		expect(consent.consentUrl).toBe(
			"https://as.example.com/consent?service=calendar",
		);
		expect(consent.code).toBe("consent_required");
	});

	it("maps interaction_required into ConsentRequiredError", () => {
		const err = mapOAuthError("token exchange", 400, {
			error: "interaction_required",
			error_description: "user interaction required",
			service: "profile",
		});

		expect(err).toBeInstanceOf(ConsentRequiredError);
		const consent = err as ConsentRequiredError;
		expect(consent.serviceId).toBe("profile");
		expect(consent.code).toBe("interaction_required");
	});

	it("falls back to AuthError for unknown 4xx oauth errors", () => {
		const err = mapOAuthError("token exchange", 400, {
			error: "unknown_error",
		});

		expect(err).toBeInstanceOf(AuthError);
		expect(err).not.toBeInstanceOf(ConsentRequiredError);
	});
});

describe("httpStatus", () => {
	it("returns 403 for InsufficientScope", () => {
		expect(httpStatus(new InsufficientScope())).toBe(403);
	});

	it("returns 503 for JWKSFetchError and MetadataFetchError (including subclasses)", () => {
		expect(httpStatus(new JWKSFetchError())).toBe(503);
		expect(httpStatus(new MetadataFetchError())).toBe(503);
		expect(httpStatus(new MissingMetadataEndpoint())).toBe(503);
	});

	it("returns 401 for authentication failures and DPoP errors", () => {
		expect(httpStatus(new TokenMissing())).toBe(401);
		expect(httpStatus(new TokenExpired())).toBe(401);
		expect(httpStatus(new InvalidSignature())).toBe(401);
		expect(httpStatus(new InvalidClaims())).toBe(401);
		expect(httpStatus(new TokenRevoked())).toBe(401);
		expect(httpStatus(new InvalidGrant())).toBe(401);
		expect(httpStatus(new DPoPProofMissing())).toBe(401);
		expect(httpStatus(new DPoPReplayDetected())).toBe(401);
	});

	it("returns 500 for protocol and runtime errors", () => {
		expect(httpStatus(new VerifierRuntimeError())).toBe(500);
		expect(httpStatus(new ProtocolError("boom"))).toBe(500);
	});

	it("returns 500 for unrelated errors (Error, undefined)", () => {
		expect(httpStatus(new Error("other"))).toBe(500);
		expect(httpStatus(undefined)).toBe(500);
	});
});

describe("wwwAuthenticate", () => {
	describe("error → scheme + error code mapping", () => {
		it.each([
			["TokenMissing", new TokenMissing("missing"), "Bearer", "invalid_token"],
			["TokenExpired", new TokenExpired("past exp"), "Bearer", "invalid_token"],
			[
				"InvalidSignature",
				new InvalidSignature("sig failed"),
				"Bearer",
				"invalid_token",
			],
			[
				"InvalidClaims",
				new InvalidClaims("bad aud"),
				"Bearer",
				"invalid_token",
			],
			[
				"TokenRevoked",
				new TokenRevoked("revoked"),
				"Bearer",
				"invalid_token",
			],
			[
				"InsufficientScope",
				new InsufficientScope("needs tools/admin"),
				"Bearer",
				"insufficient_scope",
			],
			[
				"DPoPProofMissing",
				new DPoPProofMissing("no proof"),
				"DPoP",
				"invalid_token",
			],
			[
				"InvalidDPoPProof",
				new InvalidDPoPProof("bad sig"),
				"DPoP",
				"invalid_token",
			],
			[
				"DPoPReplayDetected",
				new DPoPReplayDetected("jti seen"),
				"DPoP",
				"invalid_token",
			],
			[
				"DPoPBindingMismatch",
				new DPoPBindingMismatch("cnf.jkt mismatch"),
				"DPoP",
				"invalid_token",
			],
		])(
			"%s → %s scheme with %s",
			(_name, error, scheme, errorCode) => {
				const header = wwwAuthenticate(error);
				expect(header.startsWith(`${scheme} `)).toBe(true);
				expect(header).toContain(`error="${errorCode}"`);
			},
		);

		it("DPoPNotSupported → Bearer scheme (carve-out — the request wasn't DPoP-bound, retry as bearer)", () => {
			const header = wwwAuthenticate(
				new DPoPNotSupported("resource has not opted into DPoP"),
			);
			expect(header.startsWith("Bearer ")).toBe(true);
			expect(header).toContain('error="invalid_token"');
			expect(header).not.toMatch(/^DPoP /);
		});
	});

	describe("options", () => {
		it("appends realm when provided", () => {
			const header = wwwAuthenticate(new TokenExpired("x"), {
				realm: "mcp",
			});
			expect(header).toContain('realm="mcp"');
		});

		it("appends resource_metadata when provided", () => {
			const header = wwwAuthenticate(new TokenExpired("x"), {
				resourceMetadataUrl:
					"https://api.example.com/.well-known/oauth-protected-resource/mcp",
			});
			expect(header).toContain(
				'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"',
			);
		});

		it("appends scope when non-empty (space-joined per RFC 6750)", () => {
			const header = wwwAuthenticate(
				new InsufficientScope("needs admin"),
				{ scope: ["tools/read", "tools/admin"] },
			);
			expect(header).toContain('scope="tools/read tools/admin"');
		});

		it("omits scope when array is empty", () => {
			const header = wwwAuthenticate(new TokenExpired("x"), { scope: [] });
			expect(header).not.toContain("scope=");
		});
	});

	describe("sanitisation (RFC 9110 §11.4) — quoted-string values cannot contain CR/LF/quote/backslash", () => {
		it("strips CR/LF/quotes from error.message", () => {
			const header = wwwAuthenticate(
				new TokenExpired('crafted "value"\r\nInjected: header'),
			);
			expect(header).not.toMatch(/[\r\n]/);
			expect(header).not.toContain('value"');
			// The malicious payload text is preserved (just defanged), so the
			// real error description still reaches the client.
			expect(header).toContain("Injected: header");
		});

		it("strips CR/LF/quotes from resourceMetadataUrl", () => {
			const header = wwwAuthenticate(new TokenExpired("benign"), {
				resourceMetadataUrl: 'https://api.example.com/path"\r\nX-Foo: bar',
			});
			expect(header).not.toMatch(/[\r\n]/);
			expect(header).not.toContain('path"');
		});

		it("strips CR/LF/quotes from realm", () => {
			const header = wwwAuthenticate(new TokenExpired("benign"), {
				realm: 'mcp"\r\nX-Foo: bar',
			});
			expect(header).not.toMatch(/[\r\n]/);
			expect(header).not.toContain('mcp"');
		});
	});
});

describe("ConsentRequiredError.describe", () => {
	it("formats message with serviceId and causeDetail", () => {
		const err = new ConsentRequiredError("Consent needed", {
			serviceId: "calendar",
			causeDetail: "approval_pending",
			consentUrl: "https://example.com/consent",
		});
		expect(err.describe()).toBe("Consent needed (calendar: approval_pending)");
	});

	it("falls back to unknown_service when serviceId is empty", () => {
		const err = new ConsentRequiredError("Consent needed", {
			serviceId: "",
			causeDetail: "approval_pending",
		});
		expect(err.describe()).toContain("unknown_service");
	});

	it("falls back to message when causeDetail is empty", () => {
		const err = new ConsentRequiredError("Consent needed", {
			serviceId: "drive",
			causeDetail: "",
		});
		expect(err.describe()).toBe("Consent needed (drive: Consent needed)");
	});
});

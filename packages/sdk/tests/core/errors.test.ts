import { describe, expect, it } from "vitest";

import {
	AuthError,
	ConsentRequiredError,
	DPoPProofMissing,
	DPoPReplayDetected,
	InsufficientScope,
	InvalidClaims,
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

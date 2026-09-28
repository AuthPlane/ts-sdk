import { describe, expect, it } from "vitest";

import {
	AccessDeniedError,
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
	InvalidTargetError,
	JWKSFetchError,
	MetadataFetchError,
	MissingMetadataEndpoint,
	MultipleDPoPProofs,
	ProtocolError,
	TokenExpired,
	TokenMissing,
	TokenRevoked,
	VerifierRuntimeError,
	errorResponseBody,
	httpStatus,
	mapOAuthError,
	wwwAuthenticate,
	wwwAuthenticateChallenges,
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

	it("maps access_denied (403, cross-client exchange not allowlisted) into AccessDeniedError", () => {
		const err = mapOAuthError("token exchange", 403, {
			error: "access_denied",
			error_description: "client is not allowed to exchange for this resource",
		});

		expect(err).toBeInstanceOf(AccessDeniedError);
		expect(err).not.toBeInstanceOf(ConsentRequiredError);
		expect(err.code).toBe("access_denied");
		expect(err.statusCode).toBe(403);
		expect(err.message).toBe(
			"authplane: token exchange: client is not allowed to exchange for this resource",
		);
	});

	it("maps invalid_target (RFC 8707 §2.2) into InvalidTargetError", () => {
		const err = mapOAuthError("token exchange", 400, {
			error: "invalid_target",
		});

		expect(err).toBeInstanceOf(InvalidTargetError);
		expect(err.code).toBe("invalid_target");
		expect(err.statusCode).toBe(400);
		expect(err.message).toBe("authplane: token exchange: invalid_target");
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
			// RFC 9449 §7.1 carve-out: §4.3 multi-DPoP-header rejection uses
			// the spec-defined invalid_dpop_proof code, not invalid_token like
			// the other DPoPError shapes.
			[
				"MultipleDPoPProofs",
				new MultipleDPoPProofs("two DPoP headers"),
				"DPoP",
				"invalid_dpop_proof",
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

		// An `insufficient_scope` challenge that names no scope tells the client
		// it was refused but not what to step up to.
		it("falls back to InsufficientScope.requiredScopes when no scope is passed", () => {
			const header = wwwAuthenticate(
				new InsufficientScope("needs admin", ["tools/admin"]),
			);
			expect(header).toContain('scope="tools/admin"');
			expect(
				wwwAuthenticateChallenges(
					new InsufficientScope("needs admin", ["tools/admin"]),
					{ schemes: ["Bearer", "DPoP"] },
				).every((challenge) => challenge.includes('scope="tools/admin"')),
			).toBe(true);
		});

		it("lets an explicit scope win over requiredScopes, empty included", () => {
			const error = new InsufficientScope("needs admin", ["tools/admin"]);
			expect(wwwAuthenticate(error, { scope: ["tools/read"] })).toContain(
				'scope="tools/read"',
			);
			expect(wwwAuthenticate(error, { scope: [] })).not.toContain("scope=");
		});
	});

	// The challenge answers a caller who has not authenticated, so
	// `error_description` is chosen by the error code. The SDK's own messages
	// name the unknown `kid`, the claim that failed, or the audience the
	// resource expects — the last of which is exactly what the caller would
	// need in order to request a token for it.
	describe("error_description carries no SDK-internal detail", () => {
		it.each([
			[
				"invalid_token",
				new InvalidClaims("aud mismatch: expected 'https://api.example.com/mcp'"),
				"The access token is missing or not valid for this resource",
			],
			[
				"insufficient_scope",
				new InsufficientScope("token carries [read], route needs tools/admin"),
				"The access token does not carry the scope this operation requires",
			],
			[
				"invalid_dpop_proof",
				new MultipleDPoPProofs("two DPoP headers: proofA, proofB"),
				"The DPoP proof is missing or not valid for this request",
			],
		])("%s → a fixed description", (_code, error, description) => {
			const header = wwwAuthenticate(error);
			expect(header).toContain(`error_description="${description}"`);
			expect(header).not.toContain(error.message);
		});

		it("emits no comma inside the description a lenient parser could split on", () => {
			const header = wwwAuthenticate(new MultipleDPoPProofs("a, b"));
			const description = /error_description="([^"]*)"/.exec(header)?.[1];
			expect(description).not.toContain(",");
		});

		it("verboseDescription restores the exception message (development only)", () => {
			const header = wwwAuthenticate(
				new InvalidClaims("aud mismatch: expected 'https://api.example.com/mcp'"),
				{ verboseDescription: true },
			);
			expect(header).toContain(
				"error_description=\"aud mismatch: expected 'https://api.example.com/mcp'\"",
			);
		});
	});

	describe("sanitisation (RFC 9110 §11.4) — quoted-string values cannot contain CR/LF/quote/backslash", () => {
		it("strips CR/LF/quotes from a verbose error.message", () => {
			const header = wwwAuthenticate(
				new TokenExpired('crafted "value"\r\nInjected: header'),
				{ verboseDescription: true },
			);
			expect(header).not.toMatch(/[\r\n]/);
			expect(header).not.toContain('value"');
			// The malicious payload text is preserved (just defanged), so the
			// real error description still reaches the operator who opted in.
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

describe("wwwAuthenticateChallenges", () => {
	it("derives the single scheme from the error when schemes is omitted", () => {
		const error = new DPoPReplayDetected("jti seen");
		expect(wwwAuthenticateChallenges(error)).toEqual([wwwAuthenticate(error)]);
	});

	// RFC 9449 §7.2: a resource running inbound DPoP in optional mode takes
	// both schemes and has to say so, and two challenges cannot be comma-joined
	// because the comma also separates parameters inside one.
	it("emits one header value per scheme, in the order given", () => {
		const challenges = wwwAuthenticateChallenges(new TokenExpired("past exp"), {
			schemes: ["Bearer", "DPoP"],
		});
		expect(challenges).toHaveLength(2);
		expect(challenges[0]?.startsWith("Bearer ")).toBe(true);
		expect(challenges[1]?.startsWith("DPoP ")).toBe(true);
	});

	it("canonicalises scheme case and collapses duplicates", () => {
		expect(
			wwwAuthenticateChallenges(new TokenExpired("x"), {
				schemes: ["dpop", " DPOP ", "bearer"],
			}).map((challenge) => challenge.split(" ")[0]),
		).toEqual(["DPoP", "Bearer"]);
	});

	it("keeps invalid_dpop_proof off the Bearer challenge that names it alongside", () => {
		const [bearer, dpop] = wwwAuthenticateChallenges(
			new MultipleDPoPProofs("two DPoP headers"),
			{ schemes: ["Bearer", "DPoP"] },
		);
		expect(bearer).toContain('error="invalid_token"');
		expect(dpop).toContain('error="invalid_dpop_proof"');
	});

	it("rejects an unsupported scheme rather than sanitising it into the header", () => {
		expect(() =>
			wwwAuthenticateChallenges(new TokenExpired("x"), { schemes: ["Basic"] }),
		).toThrow(TypeError);
		expect(() =>
			wwwAuthenticateChallenges(new TokenExpired("x"), { schemes: [] }),
		).toThrow(/non-empty/);
	});

	describe("algs (RFC 9449 §7.1)", () => {
		it("omits the parameter when algs is not passed", () => {
			const [challenge] = wwwAuthenticateChallenges(new TokenExpired("x"), {
				schemes: ["DPoP"],
			});
			expect(challenge).not.toContain("algs=");
		});

		it("advertises the default set when algs is explicitly undefined", () => {
			// `InboundDPoPOptions.allowedProofAlgorithms` is `undefined` on an
			// options object built from defaults, and passing it straight through
			// has to advertise what the resource accepts, not nothing.
			const [challenge] = wwwAuthenticateChallenges(new TokenExpired("x"), {
				schemes: ["DPoP"],
				algs: undefined,
			});
			expect(challenge).toContain('algs="ES256 RS256"');
		});

		it("advertises the given set, space-separated", () => {
			const [challenge] = wwwAuthenticateChallenges(new TokenExpired("x"), {
				schemes: ["DPoP"],
				algs: ["ES256"],
			});
			expect(challenge).toContain('algs="ES256"');
		});

		it("omits the parameter for an empty array", () => {
			const [challenge] = wwwAuthenticateChallenges(new TokenExpired("x"), {
				schemes: ["DPoP"],
				algs: [],
			});
			expect(challenge).not.toContain("algs=");
		});

		it("never rides the Bearer challenge", () => {
			const [bearer] = wwwAuthenticateChallenges(new TokenExpired("x"), {
				schemes: ["Bearer", "DPoP"],
				algs: ["ES256"],
			});
			expect(bearer).not.toContain("algs=");
		});

		// Validated, not escaped: escaping lets a comma through, and a comma is
		// what a lenient client-side parser splits a joined challenge on.
		it("rejects an unsupported algorithm", () => {
			expect(() =>
				wwwAuthenticateChallenges(new TokenExpired("x"), {
					schemes: ["DPoP"],
					algs: ["ES256,HS256"],
				}),
			).toThrow(TypeError);
		});

		it("rejects a bare string that would join one character at a time", () => {
			expect(() =>
				wwwAuthenticateChallenges(new TokenExpired("x"), {
					schemes: ["DPoP"],
					algs: "ES256" as unknown as readonly string[],
				}),
			).toThrow(/not a bare string/);
		});
	});

	it("carries realm, scope and resource_metadata onto every challenge", () => {
		for (const challenge of wwwAuthenticateChallenges(
			new InsufficientScope("needs admin"),
			{
				schemes: ["Bearer", "DPoP"],
				realm: "mcp",
				scope: ["tools/admin"],
				resourceMetadataUrl: "https://api.example.com/.well-known/x",
				verboseDescription: true,
			},
		)) {
			expect(challenge).toContain('realm="mcp"');
			expect(challenge).toContain('scope="tools/admin"');
			expect(challenge).toContain(
				'resource_metadata="https://api.example.com/.well-known/x"',
			);
			expect(challenge).toContain('error_description="needs admin"');
		}
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

describe("errorResponseBody", () => {
	const INVALID_TOKEN =
		"The access token is missing or not valid for this resource";
	const INSUFFICIENT_SCOPE =
		"The access token does not carry the scope this operation requires";
	const INVALID_DPOP_PROOF =
		"The DPoP proof is missing or not valid for this request";

	it("never carries the exception's own message", () => {
		// The body reaches a caller who has not authenticated, and core's
		// messages name the failing detail — here the exact audience the
		// resource expects, which is the value a caller would need in order to
		// go request a token for it.
		const body = errorResponseBody(
			new InvalidClaims(
				"Token 'aud' claim mismatch: expected https://api.example.com/mcp",
			),
		);

		expect(body.error_description).toBe(INVALID_TOKEN);
		expect(body.error_description).not.toMatch(/aud|api\.example\.com/);
	});

	it("names the same error code the challenge does, per error type", () => {
		expect(errorResponseBody(new TokenExpired()).error).toBe("invalid_token");
		expect(errorResponseBody(new InsufficientScope("x", ["a"])).error).toBe(
			"insufficient_scope",
		);
		// The two-way branch the adapters used to hand-roll got this one wrong:
		// it said `invalid_token` in the body while the challenge above it said
		// `invalid_dpop_proof` (RFC 9449 §7.1).
		expect(errorResponseBody(new MultipleDPoPProofs()).error).toBe(
			"invalid_dpop_proof",
		);
	});

	it("picks the description from the error code", () => {
		expect(errorResponseBody(new TokenExpired()).error_description).toBe(
			INVALID_TOKEN,
		);
		expect(
			errorResponseBody(new InsufficientScope("x", ["a"])).error_description,
		).toBe(INSUFFICIENT_SCOPE);
		expect(
			errorResponseBody(new MultipleDPoPProofs()).error_description,
		).toBe(INVALID_DPOP_PROOF);
	});

	it("emits the same text the challenge emits, for the same error", () => {
		// One table, two surfaces: a client reads whichever half it finds, so
		// they must not drift.
		const error = new InsufficientScope("missing scope", ["tools/delete"]);
		const challenge = wwwAuthenticate(error);
		const body = errorResponseBody(error);

		expect(challenge).toContain(
			`error_description="${body.error_description}"`,
		);
		expect(challenge).toContain(`error="${body.error}"`);
	});

	it("honours an explicit scheme when a multi-scheme set is emitted", () => {
		// `invalid_dpop_proof` is defined for the DPoP scheme, so the Bearer
		// half of a combined challenge keeps `invalid_token` — and a body
		// pinned to that half has to say the same.
		const error = new MultipleDPoPProofs();

		expect(errorResponseBody(error, { scheme: "Bearer" }).error).toBe(
			"invalid_token",
		);
		expect(errorResponseBody(error, { scheme: "DPoP" }).error).toBe(
			"invalid_dpop_proof",
		);
	});

	it("restores the message under verboseDescription, unsanitised", () => {
		// The development escape hatch. Unlike the header path, the body needs
		// no sanitising: JSON escaping already handles the quotes and the CRLF
		// that would break a quoted-string.
		const body = errorResponseBody(
			new TokenExpired('Token has expired: "exp" claim\r\ncheck'),
			{ verboseDescription: true },
		);

		expect(body.error_description).toBe(
			'Token has expired: "exp" claim\r\ncheck',
		);
		expect(JSON.parse(JSON.stringify(body)).error_description).toBe(
			'Token has expired: "exp" claim\r\ncheck',
		);
	});
});

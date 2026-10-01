import { describe, expect, it } from "vitest";

import { shouldTripCircuit } from "../../src/core/circuitPolicy.js";
import {
	AccessDeniedError,
	AuthError,
	InvalidClientError,
	InvalidGrantError,
	InvalidRequestError,
	InvalidTargetError,
	ProtocolError,
	ServerError,
	UnauthorizedClientError,
} from "../../src/core/errors.js";
import { SSRFError } from "../../src/core/fetching/ssrf.js";

describe("shouldTripCircuit", () => {
	it("does not trip on SSRF", () => {
		expect(shouldTripCircuit(new SSRFError("blocked"))).toBe(false);
	});

	it("trips on non-AuthError (transport / protocol)", () => {
		expect(shouldTripCircuit(new Error("net"))).toBe(true);
		expect(shouldTripCircuit(new ProtocolError())).toBe(true);
	});

	it("trips on HTTP 5xx", () => {
		expect(shouldTripCircuit(new ServerError("down", 503))).toBe(true);
	});

	it("trips on invalid_client and unauthorized_client", () => {
		expect(shouldTripCircuit(new InvalidClientError("bad secret", 401))).toBe(
			true,
		);
		expect(
			shouldTripCircuit(new UnauthorizedClientError("not allowed", 400)),
		).toBe(true);
	});

	it("does not trip on listed per-request OAuth errors", () => {
		for (const Err of [InvalidGrantError, InvalidRequestError] as const) {
			expect(shouldTripCircuit(new Err("x", 400))).toBe(false);
		}
		expect(
			shouldTripCircuit(
				new AuthError("dpop", { code: "invalid_dpop_proof", statusCode: 400 }),
			),
		).toBe(false);
		expect(
			shouldTripCircuit(
				new AuthError("consent", { code: "consent_required", statusCode: 400 }),
			),
		).toBe(false);
	});

	it("does not trip on access_denied (403) or invalid_target (400)", () => {
		// Both are policy answers from a healthy AS (exchanging client not
		// allowlisted on the target Resource; `resource` not matching a granted
		// resource byte for byte), never an outage — listed explicitly so the
		// exclusion does not depend on the generic 4xx fallthrough.
		expect(shouldTripCircuit(new AccessDeniedError("not allowed", 403))).toBe(
			false,
		);
		expect(shouldTripCircuit(new InvalidTargetError("no match", 400))).toBe(
			false,
		);
		// The code alone is enough, independent of the status the AS attached.
		expect(
			shouldTripCircuit(new AuthError("denied", { code: "access_denied" })),
		).toBe(false);
		expect(
			shouldTripCircuit(new AuthError("target", { code: "invalid_target" })),
		).toBe(false);
	});

	it("does not trip on unknown OAuth 4xx codes", () => {
		expect(
			shouldTripCircuit(
				new AuthError("slow", { code: "slow_down", statusCode: 400 }),
			),
		).toBe(false);
	});
});

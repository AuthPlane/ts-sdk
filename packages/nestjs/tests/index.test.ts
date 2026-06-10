import { describe, expect, it } from "vitest";

import * as pkg from "../src/index.js";

describe("@authplane/nestjs public barrel", () => {
	const REQUIRED_VALUE_EXPORTS = [
		// Module + composition
		"AuthplaneModule",
		"AuthplaneShutdownHook",
		"AUTHPLANE_CLIENT",
		"AUTHPLANE_MODULE_OPTIONS",
		"AUTHPLANE_REQUEST_ADAPTER",
		"AUTHPLANE_RESOURCE",
		"AUTHPLANE_TOKEN_VERIFIER",
		// Guard, filter, decorators
		"AuthplaneAuthGuard",
		"AuthplaneExceptionFilter",
		"AuthInfo",
		"RequireScopes",
		"SkipAuth",
		"METADATA_KEY_REQUIRED_SCOPES",
		"METADATA_KEY_SKIP_AUTH",
		// Infrastructure
		"AUTH_INFO_REQUEST_KEY",
		"defaultRequestAdapter",
		"REQUIRED_SCOPES_REQUEST_KEY",
		// Re-exports from core (the user-guide options table references these)
		"AuthplaneError",
		"DPoPProvider",
		"InsufficientScope",
		"TokenExpired",
		"TokenMissing",
		"VerifiedClaims",
	] as const;

	it.each(REQUIRED_VALUE_EXPORTS)("exports %s", (symbol) => {
		expect(symbol in pkg).toBe(true);
		expect((pkg as unknown as Record<string, unknown>)[symbol]).toBeDefined();
	});

	it("does not leak internal helpers", () => {
		const exported = Object.keys(pkg);
		expect(exported).not.toContain("headersOf");
		expect(exported).not.toContain("readHeader");
		expect(exported).not.toContain("buildOptionsProvider");
		// Removed adapter-specific symbols (use core equivalents):
		expect(exported).not.toContain("AuthplaneNestAuthError");
		expect(exported).not.toContain("InvalidTokenError");
		expect(exported).not.toContain("InsufficientScopeError");
		expect(exported).not.toContain("AuthplaneTokenVerifier");
		expect(exported).not.toContain("AuthplaneNestAuthInfo");
		expect(exported).not.toContain("buildRequestUrl");
		expect(exported).not.toContain("deriveProtectedResourceMetadataPath");
	});
});

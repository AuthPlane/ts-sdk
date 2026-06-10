import { describe, expect, it } from "vitest";

import * as pkg from "../src/index.js";

/**
 * Snapshot of the `@authplane/hono` public surface.
 *
 * The runtime barrel exports are recorded here as a single sorted list so any
 * addition, removal, or rename is immediately visible as a diff on this test.
 * Types are checked structurally by `tsc` elsewhere.
 */
describe("@authplane/hono public surface", () => {
	it("exposes the documented value exports", () => {
		const names = Object.keys(pkg).sort();
		expect(names).toEqual([
			"REQUIRED_SCOPE_CONTEXT_KEY",
			"authplaneHonoAuth",
			"bearerAuth",
			"protectedResourceMetadataHandler",
			"requireScope",
		]);
	});
});

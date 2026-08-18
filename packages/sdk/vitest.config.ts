import { defineConfig } from "vitest/config";
import { logicalCoverageDefaults } from "../../vitest.coverage.shared.mjs";
import { TEST_INCLUDE_GLOBS } from "./conformance-tests/collected.js";

export default defineConfig({
	test: {
		environment: "node",
		// Derived, not restated. run.complete's denominator is "modules that
		// declare a catalog case", and it can only be honest if the scanner that
		// builds it looks exactly where vitest collects. Listing the globs here
		// and the directories there let the two drift.
		include: TEST_INCLUDE_GLOBS,
		pool: "forks",
		// A `forks: { maxForks, minForks }` key sat here and was never a Vitest
		// option at this level — the worker cap it looks like it sets has never
		// been in effect. Removing it changes nothing at runtime. If a cap is
		// actually wanted, Vitest 4 spells it `maxWorkers`, and that should be a
		// deliberate change rather than a silent revival of dead config.
		//
		// The conformance report is generated in the globalSetup teardown rather
		// than by a test file, so it reads the JSONL after every writer has
		// finished instead of racing them. See conformance-tests/globalSetup.ts.
		globalSetup: ["./conformance-tests/globalSetup.ts"],
		coverage: logicalCoverageDefaults,
	},
});

import { defineConfig } from "vitest/config";
import { logicalCoverageDefaults } from "../../vitest.coverage.shared.mjs";

/**
 * Tighter coverage thresholds for `@authplane/hono`. The adapter is small,
 * fully-unit-tested, and exercised end-to-end by the integration tests in
 * `tests/auth.integration.test.ts`, so the package actually hits ~100% lines
 * / statements / functions and ~95%+ branches. Raising the floor above
 * `logicalCoverageDefaults` in `vitest.coverage.shared.mts` gates regressions
 * immediately rather than allowing a slow drift back to the repo-wide
 * minimum. The shared numbers are deliberately not restated here: a second
 * copy of them is one more thing that goes stale unread.
 */
export default defineConfig({
	test: {
		environment: "node",
		include: ["tests/**/*.test.ts"],
		coverage: {
			...logicalCoverageDefaults,
			thresholds: {
				lines: 95,
				statements: 95,
				functions: 95,
				branches: 90,
			},
		},
	},
});

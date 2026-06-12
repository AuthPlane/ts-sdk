import { defineConfig } from "vitest/config";
import { logicalCoverageDefaults } from "../../vitest.coverage.shared";

/**
 * Tighter coverage thresholds for `@authplane/hono`. The adapter is small,
 * fully-unit-tested, and exercised end-to-end by the integration tests in
 * `tests/auth.integration.test.ts`, so the package actually hits ~100% lines
 * / statements / functions and ~95%+ branches. Raising the floor above the
 * shared defaults (80 / 80 / 80 / 70) gates regressions immediately rather
 * than allowing a slow drift back to the repo-wide minimum.
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

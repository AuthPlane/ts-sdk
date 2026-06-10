import { defineConfig } from "vitest/config";
import { logicalCoverageDefaults } from "../../vitest.coverage.shared";

/**
 * Coverage thresholds for `@authplane/nestjs`. The adapter is small, fully
 * unit-tested, and exercised end-to-end by the integration suite in
 * `tests/integration/auth.integration.test.ts`. Raising the floor above the
 * shared defaults (80 / 80 / 80 / 70) gates regressions immediately rather
 * than allowing a slow drift back to the repo-wide minimum.
 */
export default defineConfig({
	test: {
		environment: "node",
		include: ["tests/**/*.test.ts"],
		coverage: {
			...logicalCoverageDefaults,
			exclude: [
				...logicalCoverageDefaults.exclude,
				// Type-only file: interfaces and type aliases that emit no runtime
				// code. v8 reports it as 0% because there are no executable lines
				// to hit, which drags the package-wide percentage down even though
				// every interface is exercised by the TypeScript compiler.
				"src/module/authplane.options.ts",
			],
			thresholds: {
				lines: 95,
				statements: 95,
				functions: 95,
				branches: 90,
			},
		},
	},
});

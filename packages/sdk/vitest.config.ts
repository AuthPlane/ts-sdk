import { defineConfig } from "vitest/config";
import { logicalCoverageDefaults } from "../../vitest.coverage.shared";

export default defineConfig({
	test: {
		environment: "node",
		include: [
			"tests/core/**/*.test.ts",
			"tests/auth/**/*.test.ts",
			"conformance-tests/**/*.test.ts",
		],
		pool: "forks",
		forks: { maxForks: 4, minForks: 1 },
		coverage: logicalCoverageDefaults,
	},
});

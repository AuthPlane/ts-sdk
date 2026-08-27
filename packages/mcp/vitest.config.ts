import { defineConfig } from "vitest/config";
import { logicalCoverageDefaults } from "../../vitest.coverage.shared.mjs";

export default defineConfig({
	test: {
		environment: "node",
		include: ["tests/**/*.test.ts"],
		coverage: logicalCoverageDefaults,
	},
});

import type { CoverageOptions } from "vitest/node";

/**
 * Coverage defaults shared by every package's `vitest.config.ts`.
 *
 * `satisfies CoverageOptions` rather than a bare object literal: the value is
 * spread into each package's `coverage` block, so without a contextual type
 * nothing here was ever checked against Vitest's own option shape. It is
 * `.mts` for the same reason — the repo root has no `"type": "module"`, so a
 * plain `.ts` file here sits in a CommonJS scope while every consumer imports
 * it as ESM.
 *
 * `CoverageOptions` and not `CoverageV8Options`: the latter is `@deprecated` in
 * the pinned Vitest and declared as `interface CoverageV8Options extends
 * CoverageOptions {}`, so it adds nothing but the deprecation.
 */
export const logicalCoverageDefaults = {
	provider: "v8",
	reporter: ["text", "html"],
	include: ["src/**/*.ts"],
	thresholds: {
		lines: 85,
		statements: 85,
		functions: 85,
		branches: 85,
	},
	exclude: [
		"**/*.d.ts",
		"**/*.test.ts",
		"**/tests/**",
		"**/conformance-tests/**",
		"**/demo/**",
		"**/dist/**",
		"**/coverage/**",
	],
} satisfies CoverageOptions;

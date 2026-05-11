export const logicalCoverageDefaults = {
  provider: "v8" as const,
  reporter: ["text", "html"] as const,
  all: true,
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
};

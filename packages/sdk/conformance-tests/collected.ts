/**
 * The directories vitest collects tests from — the single definition.
 *
 * `vitest.config.ts` builds its `include` from this, and `declarationScanDirs`
 * scans exactly these, so "the scanner looks where vitest collects" is one fact
 * rather than two that have to be kept equal by hand.
 *
 * It was two. The scanner walked all of `tests/`, the config collects only
 * `tests/core/**` and `tests/auth/**`, and a comment in the scanner asserted
 * they were the same set. A catalog case declared anywhere else under `tests/`
 * — `tests/integration/`, say — therefore entered `run.complete`'s denominator
 * and could never be collected, so a fully green run published
 * `{complete: false, not_run: 0, exit_status: 0}` and no amount of running
 * fixed it. That is the previous round's finding one level up: the scanner and
 * catalogAlignment agreed with each other and neither agreed with vitest.
 */
export const COLLECTED_DIRS = [
	"tests/core",
	"tests/auth",
	"conformance-tests",
] as const;

/** `include` patterns for vitest.config.ts, derived from {@link COLLECTED_DIRS}. */
export const TEST_INCLUDE_GLOBS: string[] = COLLECTED_DIRS.map(
	(d) => `${d}/**/*.test.ts`,
);

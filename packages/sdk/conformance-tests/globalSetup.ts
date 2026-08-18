import { randomUUID } from "node:crypto";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { TestProject } from "vitest/node";
import { writeConformanceReport } from "./report.js";

/**
 * Generate the conformance report after the suite finishes, not during it.
 *
 * The report aggregates `.conformance-results/*.jsonl`, which the test files
 * write as they run. Generating it from inside a test file meant it competed
 * with those writers: with `pool: "forks"` the report file could be scheduled
 * before the others had flushed, and the `z_` name prefix ordered it
 * alphabetically, not temporally. A clean run produced
 * `{ total: 104, passed: 0, not_run: 104 }` — the artifact that answers "are we
 * conformant to this catalog" was answering from an empty read.
 *
 * `teardown` runs once in the main process after every test file has
 * completed, which is the ordering the aggregation always needed.
 */

// Typed as vitest's own TestProject rather than a hand-rolled structural type.
// The optional-everything shape this replaced degraded a vitest API change into
// false facts: `getFiles?.()` resolving to undefined gave `modules = []`, which
// reported a complete run as `{complete: false, modules_executed: 0}` instead of
// omitting the fields it could no longer establish. This directory is under
// `tsc -p tsconfig.test.json` at full strictness now, so the next upgrade is a
// build failure instead of a silently wrong artifact.
let project: TestProject | undefined;

export function setup(p: TestProject): void {
	project = p;

	// Scope this run's records, always — and to *this invocation*, not to
	// whatever the environment happens to carry.
	//
	// Deriving the scope from the env var only when it was absent made the
	// documented public knob able to defeat the thing it documents. Export
	// AUTHPLANE_CONFORMANCE_RUN_ID once and every invocation writes under the
	// same slug, so pruneForeignRunRecords classifies the previous run's files
	// as this run's and keeps them, loadResults accepts their records, and
	// nothing is ever retired. A green run then republishes an earlier run's
	// failure:
	//
	//   run 1 (one case throwing)   413 tests, 1 failed   {passed 103, failed 1, exit 1}
	//   run 2 (failure removed)     413 passed            {passed 103, failed 1, exit 1}
	//                                                     complete: true, fresh generated_at
	//
	// and with the failing module deleted from disk outright, eleven of its
	// twelve catalog cases still read `passed` under `not_run: 0`.
	//
	// The failure-first merge is what makes that permanent rather than
	// self-healing: it is the right rule *within* a run and has no time bound of
	// its own, so it inherits whatever the scope turns out to be. Making the
	// scope a property of the invocation is what gives it one.
	//
	// The env value is kept as a label so a caller can still find its own run's
	// files; the random suffix is what makes the scope unique.
	//
	// Random rather than pid+timestamp. Two calls in the same millisecond from
	// the same process produce the same pid+ms pair, so a regression test for
	// "two invocations do not share a scope" would have been racing its own
	// subject. Uniqueness here is structural instead of probabilistic, which is
	// also what lets the results-file matcher rely on no two slugs prefixing one
	// another.
	const label = process.env.AUTHPLANE_CONFORMANCE_RUN_ID;
	process.env.AUTHPLANE_CONFORMANCE_RUN_ID = `${label || "vitest"}-${randomUUID()}`;

	// No wipe here. It used to live in this function, and it fired on every
	// vitest invocation — including `vitest run conformance-tests/catalogAlignment.test.ts`,
	// which the README and the drift workflow both tell you to run, and which
	// records nothing. That run deleted the previous full run's records and left
	// its report standing: the artifact outlived the evidence for it.
	//
	// Retiring old records is now the publishing run's job, after it has
	// published. See pruneForeignRunRecords in report.ts.
}

export function teardown(): void {
	if (process.env.AUTHPLANE_CONFORMANCE_SKIP_CATALOG === "1") return;

	const dir = dirname(fileURLToPath(import.meta.url));
	const packageRoot = resolve(dir, "..");

	// Per module, and unfiltered. Which modules declare a catalog case is a
	// question about the catalog, and this function has vitest's state but no
	// catalog — writeConformanceReport has both, so it does the intersection.
	//
	// Module ids are relative to the package root rather than basenames.
	// `tests/**` and `conformance-tests/**` are both collected, so matching a
	// declaring module by basename let a same-named file under `tests/` stand in
	// for the conformance module of that name.
	const modules = (project?.vitest.state.getTestModules() ?? []).map((m) => {
		let ran = 0;
		let skipped = 0;
		for (const test of m.children.allTests()) {
			// Only passed and failed are evidence that a test ran. "pending" was
			// counted as ran, and a pending test has produced no result at all.
			const state = test.result().state;
			if (state === "passed" || state === "failed") ran += 1;
			else skipped += 1;
		}
		return {
			id: relative(packageRoot, m.moduleId),
			ran,
			skipped,
			failed: m.state() === "failed",
		};
	});

	try {
		writeConformanceReport(dir, { modules });
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.error(
			`[conformance] report generation failed, report left stale: ${message}`,
		);
		process.exitCode = 1;
	}
}

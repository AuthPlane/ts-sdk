import { it } from "vitest";
import { appendFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { RESULTS_DIR, currentRunId, resultsFileName } from "./resultsStore.js";

export type ConformanceCoverage = {
	level?: "full" | "partial";
	gaps?: string[];
	note?: string;
};

export type ConformanceFailure = {
	message: string;
	stack?: string;
};

export type ConformanceResult = {
	caseId: string;
	testName: string;
	status: "passed" | "failed";
	coverage: {
		level: "full" | "partial";
		gaps: string[];
		note: string;
	};
	failure?: ConformanceFailure;
};

declare global {
	/**
	 * Internal hook for coverage/unit tests.
	 * When set to `false`, `conformanceCase()` will record failures but will not re-throw,
	 * so the suite can keep passing while still covering the `catch` path.
	 */
	// eslint-disable-next-line no-var
	var __AUTHPLANE_CONFORMANCE_RETHROW_ERRORS__: boolean | undefined;
}

type ConformanceResultRecord = ConformanceResult & { writtenAt: number };

// globalSetup assigns a run id unconditionally, so an absent one means this
// module is running without the globalSetup that owns the scope. Falling back
// to a constant was the quietest possible failure: workers would tag records
// `default`, the teardown would read the generated id, every record would be
// filtered out, and `results.size === 0` would skip the write with no report
// and nothing on either stream.
// Exported for the same reason as normalizeConformanceError below: it is a
// guard whose only purpose is to fire, and its one caller runs inside an `it`
// in a suite that always has a run id — so nothing in a normal run reaches it,
// and `?? "default"` could be put back with the suite fully green.
export function resolveRunId(): string {
	const runId = currentRunId();
	if (runId === undefined) {
		throw new Error(
			"conformanceCase: AUTHPLANE_CONFORMANCE_RUN_ID is unset — " +
				"conformance-tests/globalSetup.ts must run before any conformance case.",
		);
	}
	return runId;
}

function appendResultRecord(record: ConformanceResultRecord): void {
	// Vitest can run test files in isolated workers; file-based aggregation keeps the report stable.
	const runId = resolveRunId();
	const workerId = process.env.VITEST_WORKER_ID ?? String(process.pid);
	const file = resolve(RESULTS_DIR, resultsFileName(runId, workerId));
	mkdirSync(RESULTS_DIR, { recursive: true });
	appendFileSync(file, `${JSON.stringify({ ...record, runId })}\n`, "utf-8");
}

// Extracted for unit-test coverage:
// - `conformanceCase()` records failures in its `catch` block.
// - Coverage for that block is hard to drive without deliberately failing a conformance `it`.
// - This helper keeps the production behavior while allowing focused unit tests.
export function normalizeConformanceError(err: unknown): Error {
	return err instanceof Error ? err : new Error(String(err));
}

// Extracted for unit-test coverage.
// Allows covering the "rethrow" branch without having to register a failing `it`.
export function maybeRethrowConformanceError(
	err: unknown,
	shouldRethrow: boolean,
): void {
	if (shouldRethrow) {
		throw err;
	}
}

/**
 * Declare a conformance test case.
 *
 * - `catalogAlignment.test.ts` extracts IDs statically from call sites.
 * - This helper also records runtime pass/fail info for report generation.
 */
export function conformanceCase(
	id: string,
	testName: string,
	fn: () => unknown | Promise<unknown>,
	coverage: ConformanceCoverage = {},
): void {
	const resolvedCoverage = {
		level: coverage.level ?? "full",
		gaps: coverage.gaps ?? [],
		note: coverage.note ?? "",
	};

	it(testName, async () => {
		try {
			await fn();
			const resolved = {
				caseId: id,
				testName,
				status: "passed",
				coverage: resolvedCoverage,
			} satisfies ConformanceResult;
			appendResultRecord({ ...resolved, writtenAt: Date.now() });
		} catch (err) {
			const e = normalizeConformanceError(err);
			const resolved = {
				caseId: id,
				testName,
				status: "failed",
				coverage: resolvedCoverage,
				failure: {
					message: e.message,
					// exactOptionalPropertyTypes: `stack?: string` means absent, not
					// `undefined`. Error.stack is optional, so omit it when missing —
					// which is also what JSON.stringify does to the record downstream.
					...(e.stack === undefined ? {} : { stack: e.stack }),
				},
			} satisfies ConformanceResult;
			appendResultRecord({ ...resolved, writtenAt: Date.now() });
			maybeRethrowConformanceError(
				err,
				globalThis.__AUTHPLANE_CONFORMANCE_RETHROW_ERRORS__ !== false,
			);
		}
	});
}

import { it } from "vitest";
import { appendFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";

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
  // eslint-disable-next-line no-var
  var __AUTHPLANE_CONFORMANCE_RESULTS__:
    | Map<string, ConformanceResult>
    | undefined;

  /**
   * Internal hook for coverage/unit tests.
   * When set to `false`, `conformanceCase()` will record failures but will not re-throw,
   * so the suite can keep passing while still covering the `catch` path.
   */
  // eslint-disable-next-line no-var
  var __AUTHPLANE_CONFORMANCE_RETHROW_ERRORS__:
    | boolean
    | undefined;
}

function ensureResultsMap(): Map<string, ConformanceResult> {
  if (!globalThis.__AUTHPLANE_CONFORMANCE_RESULTS__) {
    globalThis.__AUTHPLANE_CONFORMANCE_RESULTS__ = new Map<string, ConformanceResult>();
  }
  return globalThis.__AUTHPLANE_CONFORMANCE_RESULTS__!;
}

type ConformanceResultRecord = ConformanceResult & { writtenAt: number };

function resolveRunId(): string {
  return process.env.AUTHPLANE_CONFORMANCE_RUN_ID ?? "default";
}

function appendResultRecord(record: ConformanceResultRecord): void {
  // Vitest can run test files in isolated workers; file-based aggregation keeps the report stable.
  const dir = resolve(process.cwd(), ".conformance-results");
  const workerId = process.env.VITEST_WORKER_ID ?? String(process.pid);
  const file = resolve(dir, `conformance-results-${workerId}.jsonl`);
  mkdirSync(dir, { recursive: true });
  appendFileSync(file, JSON.stringify({ ...record, runId: resolveRunId() }) + "\n", "utf-8");
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
      ensureResultsMap().set(id, resolved);
      appendResultRecord({ ...resolved, writtenAt: Date.now() });
    } catch (err) {
      const e = normalizeConformanceError(err);
      const resolved = {
        caseId: id,
        testName,
        status: "failed",
        coverage: resolvedCoverage,
        failure: { message: e.message, stack: e.stack },
      } satisfies ConformanceResult;
      ensureResultsMap().set(id, resolved);
      appendResultRecord({ ...resolved, writtenAt: Date.now() });
      maybeRethrowConformanceError(
        err,
        globalThis.__AUTHPLANE_CONFORMANCE_RETHROW_ERRORS__ !== false,
      );
    }
  });
}


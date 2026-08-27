import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  conformanceCase,
  maybeRethrowConformanceError,
  normalizeConformanceError,
} from "../../conformance-tests/conformanceCase.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { ConformanceResult } from "../../conformance-tests/conformanceCase.js";
import {
  RESULTS_DIR,
  currentRunId,
  resultsFileName,
} from "../../conformance-tests/resultsStore.js";

// Enable catch-path coverage inside conformanceCase without failing the test suite.
beforeAll(() => {
  globalThis.__AUTHPLANE_CONFORMANCE_RETHROW_ERRORS__ = false;
});

// These conformanceCase invocations intentionally throw to exercise the production `catch` path.
conformanceCase("cov-conformanceCase-throw-string", "conformanceCase catch: non-Error throwable", async () => {
  throw "not-an-error";
});

conformanceCase("cov-conformanceCase-throw-error", "conformanceCase catch: Error instance", async () => {
  throw new Error("boom");
});

describe("conformanceCase helpers", () => {
  it("normalizeConformanceError returns the same Error instance", () => {
    const err = new Error("boom");
    const normalized = normalizeConformanceError(err);
    expect(normalized).toBe(err);
    expect(normalized.message).toBe("boom");
  });

  it("normalizeConformanceError converts non-Error throwables to Error", () => {
    const normalized = normalizeConformanceError("not-an-error");
    expect(normalized).toBeInstanceOf(Error);
    expect(normalized.message).toBe("not-an-error");
  });

  it("maybeRethrowConformanceError throws when shouldRethrow=true", () => {
    let caught: unknown;
    try {
      maybeRethrowConformanceError("boom", true);
    } catch (err) {
      caught = err;
    }

    expect(caught).toBe("boom");
  });

  it("maybeRethrowConformanceError does not throw when shouldRethrow=false", () => {
    expect(() => maybeRethrowConformanceError("boom", false)).not.toThrow();
  });
});

// Asserts against the records conformanceCase actually publishes, rather than
// against an in-process map.
//
// That map was the last reader of `__AUTHPLANE_CONFORMANCE_RESULTS__`, and the
// map itself had become write-only: the report is aggregated from the JSONL
// records now, and the fallback in the old in-suite report generator that used
// to consult it is gone. Asserting here on the same path the report reads means
// this case covers the `catch` block *and* the record it is supposed to leave
// behind, instead of a parallel structure nothing else looks at.
/**
 * This worker's records only.
 *
 * `loadResultsFromJsonlFiles([RESULTS_DIR])` read every file for the run,
 * including ones other forks were appending to as it read — tolerated only
 * because of the torn-line handling, and the same cross-worker coupling this
 * directory exists to remove. The ids asserted below are written synchronously
 * by this file in this worker, so its own file is the whole of what it needs.
 */
function ownRecords(): Map<string, ConformanceResult> {
  const runId = currentRunId();
  if (runId === undefined) throw new Error("no run id; globalSetup did not run");
  const workerId = process.env.VITEST_WORKER_ID ?? String(process.pid);

  const text = readFileSync(
    resolve(RESULTS_DIR, resultsFileName(runId, workerId)),
    "utf-8",
  );
  const map = new Map<string, ConformanceResult>();
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    const parsed = JSON.parse(line) as ConformanceResult;
    map.set(parsed.caseId, parsed);
  }
  return map;
}

afterAll(() => {
  const results = ownRecords();

  expect(results.get("cov-conformanceCase-throw-string")?.status).toBe("failed");
  expect(results.get("cov-conformanceCase-throw-error")?.status).toBe("failed");
  expect(results.get("cov-conformanceCase-throw-error")?.failure?.message).toBe(
    "boom",
  );
});


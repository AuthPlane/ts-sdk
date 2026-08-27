import { describe, expect, it } from "vitest";
import type { ConformanceResult } from "./conformanceCase.js";
import { buildReportPayload, parseCatalog } from "./report.js";

/**
 * Deterministic tests for the report payload.
 *
 * The generation itself moved to the globalSetup teardown, because as a test
 * file it raced the workers writing the records it reads — which means nothing
 * in the test graph exercises it any more. These cover the shape it produces, from
 * synthetic results rather than from a suite run, so they cannot race anything.
 */

const CATALOG_YAML = `
catalog_id: test-catalog
catalog_version: "2026-08-04"
cases:
  - id: case-ran
  - id: case-never-ran
`;

// Parsed once here rather than accepted as text by buildReportPayload: a
// parameter with two shapes is one more thing for a caller to get right.
const CATALOG = parseCatalog(CATALOG_YAML);

const PKG = { name: "@authplane/sdk", version: "0.4.0-dev.0" };

function result(overrides: Partial<ConformanceResult> = {}): ConformanceResult {
	return {
		caseId: "case-ran",
		testName: "a case that ran",
		status: "passed",
		coverage: { level: "full", gaps: [], note: "" },
		...overrides,
	};
}

describe("buildReportPayload", () => {
	it("reports a case with no recorded result as not_run with unknown coverage", () => {
		const payload = buildReportPayload(CATALOG, new Map(), PKG) as {
			summary: Record<string, number>;
			cases: {
				case_id: string;
				status: string;
				coverage: { level: string; gaps: string[] };
			}[];
		};

		expect(payload.summary).toEqual({
			total: 2,
			passed: 0,
			failed: 0,
			skipped: 0,
			not_run: 2,
		});
		// Not "full" — claiming full coverage for a case that never ran is the
		// false statement the per-case declarations exist to remove.
		for (const c of payload.cases) {
			expect(c.coverage.level).toBe("unknown");
			expect(c.coverage.gaps).toHaveLength(1);
		}
	});

	it("carries a recorded case's own coverage through", () => {
		const results = new Map<string, ConformanceResult>([
			[
				"case-ran",
				result({
					coverage: { level: "partial", gaps: ["edge case x"], note: "why" },
				}),
			],
		]);

		const payload = buildReportPayload(CATALOG, results, PKG) as {
			summary: Record<string, number>;
			cases: {
				case_id: string;
				status: string;
				test_name?: string;
				coverage: { level: string; gaps: string[]; note: string };
			}[];
		};

		expect(payload.summary).toEqual({
			total: 2,
			passed: 1,
			failed: 0,
			skipped: 0,
			not_run: 1,
		});

		const ran = payload.cases.find((c) => c.case_id === "case-ran");
		expect(ran?.status).toBe("passed");
		expect(ran?.test_name).toBe("a case that ran");
		expect(ran?.coverage).toEqual({
			level: "partial",
			gaps: ["edge case x"],
			note: "why",
		});

		const never = payload.cases.find((c) => c.case_id === "case-never-ran");
		expect(never?.status).toBe("not_run");
		expect(never?.coverage.level).toBe("unknown");
	});

	it("sets a non-zero runner exit status when a case failed", () => {
		const results = new Map<string, ConformanceResult>([
			[
				"case-ran",
				result({
					status: "failed",
					failure: { message: "boom", stack: "at x" },
				}),
			],
		]);

		const payload = buildReportPayload(CATALOG, results, PKG) as {
			runner: { exit_status: number };
			summary: Record<string, number>;
			cases: { case_id: string; failure?: { message: string } }[];
		};

		expect(payload.runner.exit_status).toBe(1);
		expect(payload.summary.failed).toBe(1);
		expect(
			payload.cases.find((c) => c.case_id === "case-ran")?.failure?.message,
		).toBe("boom");
	});

	it("reports a result whose case is not in the catalog as absent, not as an extra row", () => {
		// The catalog is the index: the report has one row per catalog case, so a
		// stale record from a renamed case must not appear.
		const results = new Map<string, ConformanceResult>([
			[
				"case-that-no-longer-exists",
				result({ caseId: "case-that-no-longer-exists" }),
			],
		]);

		const payload = buildReportPayload(CATALOG, results, PKG) as {
			summary: Record<string, number>;
			cases: { case_id: string }[];
		};

		expect(payload.cases.map((c) => c.case_id)).toEqual([
			"case-ran",
			"case-never-ran",
		]);
		expect(payload.summary.not_run).toBe(2);
	});
});

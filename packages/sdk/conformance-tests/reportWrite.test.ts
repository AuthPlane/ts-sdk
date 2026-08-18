import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	listDeclaringModules,
	loadResultsFromJsonlFiles,
	writeConformanceReport,
} from "./report.js";
import { resultsFileName } from "./resultsStore.js";

/**
 * Tests for the write/skip decision — the behaviour this file's module
 * introduced, and the one that had no coverage when it shipped.
 *
 * Both defects it hid were of the same kind: the guard asked "did this run
 * record anything" when the honest question is "did this run cover the
 * catalog". A unit run records the `cov-*` ids from
 * tests/core/conformanceCaseCoverage.test.ts, so the first predicate says yes
 * for a run that touched no catalog case at all.
 *
 * Everything here works on a tmpdir, so it races nothing and needs no suite run.
 */

const CATALOG = `
catalog_id: test-catalog
catalog_version: "2026-08-04"
cases:
  - id: case-a
  - id: case-b
`;

/** Package root, as `packages/sdk` is in production. */
let dir: string;
/** The `conformance-tests/` directory writeConformanceReport is called with. */
let fromDir: string;
let prevCwd: string;
let prevCatalog: string | undefined;
let prevRunId: string | undefined;

function record(
	caseId: string,
	status: "passed" | "failed" = "passed",
	runId = "test-run",
): string {
	return `${JSON.stringify({
		caseId,
		testName: `test for ${caseId}`,
		status,
		coverage: { level: "full", gaps: [], note: "" },
		writtenAt: Date.now(),
		runId,
	})}\n`;
}

function resultsPath(runId = "test-run", worker = "1"): string {
	return resolve(dir, ".conformance-results", resultsFileName(runId, worker));
}

function writeRecords(lines: string[], runId = "test-run"): void {
	mkdirSync(resolve(dir, ".conformance-results"), { recursive: true });
	writeFileSync(resultsPath(runId), lines.join(""), "utf-8");
}

/** One collected module that ran `ran` tests and skipped none. */
function mod(
	id: string,
	ran = 1,
	skipped = 0,
	failed = false,
): { id: string; ran: number; skipped: number; failed: boolean } {
	return { id, ran, skipped, failed };
}

function readReport(): {
	summary: Record<string, number>;
	run: Record<string, unknown>;
} {
	return JSON.parse(
		readFileSync(resolve(dir, "conformance-report.json"), "utf-8"),
	);
}

beforeEach(() => {
	dir = mkdtempSync(resolve(tmpdir(), "conformance-report-"));
	fromDir = resolve(dir, "conformance-tests");
	mkdirSync(fromDir, { recursive: true });
	prevCwd = process.cwd();
	prevCatalog = process.env.CONFORMANCE_CATALOG_PATH;
	prevRunId = process.env.AUTHPLANE_CONFORMANCE_RUN_ID;

	const catalogPath = resolve(dir, "catalog.yaml");
	writeFileSync(catalogPath, CATALOG, "utf-8");
	process.env.CONFORMANCE_CATALOG_PATH = catalogPath;
	process.env.AUTHPLANE_CONFORMANCE_RUN_ID = "test-run";
	writeFileSync(
		resolve(dir, "package.json"),
		JSON.stringify({ name: "t", version: "0" }),
		"utf-8",
	);
	process.chdir(dir);
});

afterEach(() => {
	process.chdir(prevCwd);
	if (prevCatalog === undefined) delete process.env.CONFORMANCE_CATALOG_PATH;
	else process.env.CONFORMANCE_CATALOG_PATH = prevCatalog;
	if (prevRunId === undefined) delete process.env.AUTHPLANE_CONFORMANCE_RUN_ID;
	else process.env.AUTHPLANE_CONFORMANCE_RUN_ID = prevRunId;
	rmSync(dir, { recursive: true, force: true });
});

describe("writeConformanceReport", () => {
	it("skips the write when the run recorded nothing", () => {
		expect(writeConformanceReport(fromDir)).toBe(false);
		expect(() => readReport()).toThrow();
	});

	it("skips the write when the run recorded only non-catalog cases", () => {
		// The regression that shipped: tests/core/conformanceCaseCoverage.test.ts
		// records two ids that are deliberately absent from the catalog, so a
		// "did we record anything" guard passes and a unit-only run overwrites a
		// real report with an all-unknown one.
		writeRecords([
			record("cov-conformanceCase-throw-string"),
			record("cov-conformanceCase-throw-error"),
		]);

		expect(writeConformanceReport(fromDir)).toBe(false);
		expect(() => readReport()).toThrow();
	});

	it("does not overwrite an existing report on a non-catalog run", () => {
		writeRecords([record("case-a"), record("case-b")]);
		expect(writeConformanceReport(fromDir)).toBe(true);
		const before = readReport();
		expect(before.summary.passed).toBe(2);

		rmSync(resolve(dir, ".conformance-results"), {
			recursive: true,
			force: true,
		});
		writeRecords([record("cov-conformanceCase-throw-string")]);
		expect(writeConformanceReport(fromDir)).toBe(false);

		expect(readReport()).toEqual(before);
	});

	it("writes, and reports the run complete when every module ran", () => {
		writeRecords([record("case-a"), record("case-b")]);

		expect(
			writeConformanceReport(fromDir, {
				modules: [mod("conformance-tests/test_a.test.ts", 2)],
				declaringModules: ["conformance-tests/test_a.test.ts"],
			}),
		).toBe(true);
		const report = readReport();
		expect(report.summary).toEqual({
			total: 2,
			passed: 2,
			failed: 0,
			skipped: 0,
			not_run: 0,
		});
		expect(report.run).toMatchObject({
			complete: true,
			conformance_tests_ran: 2,
			alignment_ok: true,
		});
	});

	it("reports the run incomplete when conformance tests were skipped", () => {
		// The `-t <pattern>` case: vitest collects every module and skips the
		// tests that do not match, so module membership says the run was
		// complete while most of the catalog never executed. Counting tests is
		// what distinguishes them.
		writeRecords([record("case-a")]);

		expect(
			writeConformanceReport(fromDir, {
				modules: [mod("conformance-tests/test_a.test.ts", 1, 4)],
				declaringModules: ["conformance-tests/test_a.test.ts"],
			}),
		).toBe(true);
		const report = readReport();
		expect(report.summary.not_run).toBe(1);
		expect(report.run).toMatchObject({
			complete: false,
			conformance_tests_ran: 1,
			conformance_tests_skipped: 4,
		});
		// summary.skipped stays 0: it counts *cases* with that status, and the
		// catalog's invariant is total === cases.length. The skipped tests are
		// a property of the run and live in run.conformance_tests_skipped.
		expect(report.summary.skipped).toBe(0);
	});

	it("reports the run incomplete when a declaring module was never collected", () => {
		// The file-filter case, and the one a per-test predicate cannot see:
		// vitest only reports modules it collected, so under `-- <one file>`
		// the others do not exist for it and nothing is skipped. The on-disk
		// list of case-declaring modules is the only signal that notices.
		writeRecords([record("case-a")]);

		expect(
			writeConformanceReport(fromDir, {
				modules: [mod("conformance-tests/test_a.test.ts", 1)],
				declaringModules: [
					"conformance-tests/test_a.test.ts",
					"conformance-tests/test_b.test.ts",
				],
			}),
		).toBe(true);
		const report = readReport();
		expect(report.run).toMatchObject({
			complete: false,
			modules_collected: 1,
			modules_declaring: 2,
		});
	});

	it("does not claim the run was filtered when every module ran and a case is still not_run", () => {
		// The defect this replaced: `not_run > 0` was read as "filtered", so a
		// catalog case with no test — which the catalog defines as an alignment
		// bug — was reported as an artefact of a file filter. Complete run, one
		// uncovered case: `complete` must stay true.
		writeRecords([record("case-a")]);

		writeConformanceReport(fromDir, {
			modules: [mod("conformance-tests/test_a.test.ts", 1)],
			declaringModules: ["conformance-tests/test_a.test.ts"],
		});
		const report = readReport();
		expect(report.summary.not_run).toBe(1);
		expect(report.run).toMatchObject({ complete: true });
		// The alignment verdict the catalog defines — "a missing case is treated
		// as not_run and fails alignment" — published as its own field rather
		// than folded into runner.exit_status, which answers the runner's
		// question and is populated from the literal process status in go.
		expect(report.run).toMatchObject({ alignment_ok: false });
		expect(
			(report as unknown as { runner: { exit_status: number } }).runner
				.exit_status,
		).toBe(0);
	});

	it("omits the alignment verdict when not_run is only a filter artifact", () => {
		// The other side of the same rule. Under `complete: false` the not_run
		// cases say nothing about alignment — they are what the filter left out —
		// so the verdict is omitted rather than guessed.
		writeRecords([record("case-a")]);

		writeConformanceReport(fromDir, {
			modules: [mod("conformance-tests/test_a.test.ts", 1)],
			declaringModules: [
				"conformance-tests/test_a.test.ts",
				"conformance-tests/test_b.test.ts",
			],
		});
		const report = readReport();
		expect(report.run).toMatchObject({ complete: false });
		expect(report.summary.not_run).toBe(1);
		expect(report.run).not.toHaveProperty("alignment_ok");
		expect(
			(report as unknown as { runner: { exit_status: number } }).runner
				.exit_status,
		).toBe(0);
	});

	it("sets a non-zero exit status when a module failed, even with no failed case", () => {
		// "Non-zero on any failure" per the catalog. A module that throws on
		// import fails no case — it turns them into not_run — and the old
		// count-derived formula wrote exit_status 0 for it.
		writeRecords([record("case-a"), record("case-b")]);

		writeConformanceReport(fromDir, {
			modules: [mod("conformance-tests/test_a.test.ts", 2, 0, true)],
			declaringModules: ["conformance-tests/test_a.test.ts"],
		});
		const report = readReport() as unknown as {
			runner: { exit_status: number };
		};
		expect(report.runner.exit_status).toBe(1);
	});

	it("skips a malformed record line and records that it did", () => {
		mkdirSync(resolve(dir, ".conformance-results"), { recursive: true });
		writeFileSync(
			resultsPath(),
			record("case-a") + "not-json\n" + record("case-b"),
			"utf-8",
		);

		// A torn line used to throw out of the teardown and leave the report
		// stale on an otherwise green run — permanently, since nothing prunes
		// this directory.
		expect(writeConformanceReport(fromDir)).toBe(true);
		const report = readReport();
		expect(report.summary.passed).toBe(2);
		expect(report.run).toMatchObject({ malformed_result_lines: 1 });
	});

	it("reports the run incomplete when a collected module ran no test", () => {
		// The import-time throw, and the shape a summed count cannot represent:
		// vitest reports the module (collection failed, not the module),
		// `allTests()` yields nothing for it, so nothing is skipped and the
		// module list is complete. Totals said `complete: true` while the twelve
		// cases that module declares went not_run. Per-module counts are what
		// make "collected" and "ran" different facts.
		writeRecords([record("case-a")]);

		expect(
			writeConformanceReport(fromDir, {
				modules: [
					mod("conformance-tests/test_a.test.ts", 1),
					mod("conformance-tests/test_b.test.ts", 0),
				],
				declaringModules: [
					"conformance-tests/test_a.test.ts",
					"conformance-tests/test_b.test.ts",
				],
			}),
		).toBe(true);
		const report = readReport();
		expect(report.run).toMatchObject({
			complete: false,
			conformance_tests_ran: 1,
			conformance_tests_skipped: 0,
			modules_collected: 2,
			modules_declaring: 2,
		});
	});

	it("does not call a run complete on an empty denominator", () => {
		// `[].every(...)` is vacuously true, so a scan that matched nothing
		// published `{complete: true, modules_declaring: 0}` off a set it had
		// failed to find.
		writeRecords([record("case-a")]);

		writeConformanceReport(fromDir, { modules: [], declaringModules: [] });
		expect(readReport().run).toMatchObject({
			complete: false,
			modules_declaring: 0,
		});
	});

	it("retires another run's records once this run has published", () => {
		writeRecords(
			[record("case-a", "passed", "an-earlier-run")],
			"an-earlier-run",
		);
		writeRecords([record("case-a")]);
		expect(writeConformanceReport(fromDir)).toBe(true);

		// Whole files, not filtered lines: a torn record carries no readable run
		// id, so nothing scoped by run id could ever retire it, and it was
		// counted on every subsequent run forever. Its file is attributable even
		// when its contents are not.
		expect(existsSync(resultsPath("an-earlier-run"))).toBe(false);
		expect(existsSync(resultsPath())).toBe(true);
	});

	it("leaves records alone when the run published nothing", () => {
		// The wipe used to fire in `setup`, on every vitest invocation — so
		// `vitest run conformance-tests/catalogAlignment.test.ts`, which the
		// README and the drift workflow both tell you to run, deleted the last
		// full run's records and left its report standing.
		writeRecords(
			[record("case-a", "passed", "an-earlier-run")],
			"an-earlier-run",
		);
		writeRecords([record("cov-not-in-catalog")]);

		expect(writeConformanceReport(fromDir)).toBe(false);
		expect(existsSync(resultsPath("an-earlier-run"))).toBe(true);
	});

	it("does not carry a previous run's records under a reused run id", () => {
		// The scope has to be a property of the invocation, not of the
		// environment. When AUTHPLANE_CONFORMANCE_RUN_ID was exported and left
		// pinned, every run wrote under the same slug, the pruner classified the
		// previous run's files as this run's and kept them, and the failure-first
		// merge — right within a run, and with no time bound of its own — made an
		// old failure permanent instead of self-healing. A fully green run
		// published `failed: 1` and `exit_status: 1` under `complete: true`.
		writeRecords([record("case-a", "failed")], "pinned");
		expect(writeConformanceReport(fromDir)).toBe(false); // not this run's file

		// The second run reuses the label but not the scope, which is what
		// globalSetup now guarantees by folding pid and timestamp in.
		writeRecords([record("case-a", "passed", "pinned-2")], "pinned-2");
		process.env.AUTHPLANE_CONFORMANCE_RUN_ID = "pinned-2";
		expect(writeConformanceReport(fromDir)).toBe(true);

		const report = readReport();
		expect(report.summary).toMatchObject({ passed: 1, failed: 0 });
		expect(
			(report as unknown as { runner: { exit_status: number } }).runner
				.exit_status,
		).toBe(0);
	});

	it("does not report another run's torn line as its own", () => {
		// malformed_result_lines has to be a claim about this run's evidence.
		// Counting a foreign file's torn line meant a run reported a defect it
		// did not produce — and then pruned the file that would have shown
		// otherwise, so the claim was unverifiable afterwards.
		const facts = {
			modules: [mod("conformance-tests/test_a.test.ts", 2)],
			declaringModules: ["conformance-tests/test_a.test.ts"],
		};

		mkdirSync(resolve(dir, ".conformance-results"), { recursive: true });
		writeFileSync(
			resultsPath("an-earlier-run"),
			record("case-a", "passed", "an-earlier-run") + "not-json-torn\n",
			"utf-8",
		);
		writeRecords([record("case-a"), record("case-b")]);

		expect(writeConformanceReport(fromDir, facts)).toBe(true);
		expect(readReport().run).not.toHaveProperty("malformed_result_lines");

		// And the assertion is not vacuous: a torn line in *this* run's file is
		// still counted.
		writeFileSync(resultsPath(), record("case-a") + "not-json-torn\n", "utf-8");
		expect(writeConformanceReport(fromDir, facts)).toBe(true);
		expect(readReport().run).toMatchObject({ malformed_result_lines: 1 });
	});

	it("does not claim a run id that merely prefixes this one", () => {
		// Prefix matching let run `X` claim run `X-1`'s files: kept as this run's
		// and so never pruned, while their records were rejected on the way in.
		// They accumulated, and a torn line in one was counted forever — the
		// permanence the prune exists to end.
		writeRecords([record("case-a", "passed", "test-run-1")], "test-run-1");
		writeRecords([record("case-a"), record("case-b")]);

		expect(writeConformanceReport(fromDir)).toBe(true);
		expect(existsSync(resultsPath("test-run-1"))).toBe(false);
		expect(existsSync(resultsPath())).toBe(true);
	});

	it("does not publish the json when its pair could not be written", () => {
		// The `.json` is what consumers read, so it goes last. Written in the old
		// order an unwritable `.md` left the `.json` already replaced — two
		// artifacts describing different runs, a "report left stale" message that
		// was false for one of them, and the prune skipped.
		//
		// This pins the ordering. The staging-and-rename beside it buys per-file
		// atomicity, which is not observable from out here — two renames cannot be
		// made one operation, and the comment in report.ts says so rather than
		// claiming the pair is transactional.
		writeRecords([record("case-a"), record("case-b")]);
		expect(writeConformanceReport(fromDir)).toBe(true);
		const before = readReport();

		// A directory where the `.md` has to go, so its rename fails. The `.json`
		// is renamed after it, so it must still hold the previous run's payload.
		rmSync(resolve(dir, "conformance-report.md"), { force: true });
		mkdirSync(resolve(dir, "conformance-report.md", "occupied"), {
			recursive: true,
		});
		writeRecords([record("case-a", "failed")]);

		expect(() => writeConformanceReport(fromDir)).toThrow();
		expect(readReport()).toEqual(before);
	});

	it("stamps an execution timestamp", () => {
		writeRecords([record("case-a")]);
		writeConformanceReport(fromDir);
		const report = readReport() as unknown as { generated_at: string };
		expect(Date.parse(report.generated_at)).not.toBeNaN();
	});
});

describe("loadResultsFromJsonlFiles", () => {
	it("ignores records from another run when a run id is set", () => {
		const resultsDir = resolve(dir, ".conformance-results");
		mkdirSync(resultsDir, { recursive: true });
		writeFileSync(
			resultsPath(),
			record("case-a") +
				`${JSON.stringify({
					caseId: "case-b",
					testName: "stale",
					status: "passed",
					coverage: { level: "full", gaps: [], note: "" },
					writtenAt: Date.now(),
					runId: "an-earlier-run",
				})}\n`,
			"utf-8",
		);

		const results = loadResultsFromJsonlFiles([resultsDir]);
		expect([...results.keys()]).toEqual(["case-a"]);
	});

	function dup(
		testName: string,
		status: "passed" | "failed",
		writtenAt: number,
	): string {
		return `${JSON.stringify({
			caseId: "case-a",
			testName,
			status,
			coverage: { level: "full", gaps: [], note: "" },
			writtenAt,
			runId: "test-run",
		})}\n`;
	}

	it("keeps the most recently written record among records that agree", () => {
		const resultsDir = resolve(dir, ".conformance-results");
		mkdirSync(resultsDir, { recursive: true });
		writeFileSync(
			resultsPath(),
			dup("older", "passed", 1) + dup("newer", "passed", 2),
			"utf-8",
		);

		const results = loadResultsFromJsonlFiles([resultsDir]);
		expect(results.get("case-a")?.testName).toBe("newer");
	});

	it("lets a failing declaration win over a passing one, either order", () => {
		// Four catalog ids are declared in two modules each, and those modules
		// run in parallel forks. Under last-writtenAt-wins the merge was decided
		// by wall clock: a failing declaration was published as `passed` in three
		// runs out of four, so the report read `104 passed, complete: true` with
		// `exit_status: 1` as the only true field in it.
		const resultsDir = resolve(dir, ".conformance-results");
		mkdirSync(resultsDir, { recursive: true });

		for (const [first, second] of [
			[dup("fail", "failed", 1), dup("pass", "passed", 2)],
			[dup("pass", "passed", 1), dup("fail", "failed", 2)],
		] as const) {
			writeFileSync(resultsPath(), first + second, "utf-8");
			const results = loadResultsFromJsonlFiles([resultsDir]);
			expect(results.get("case-a")?.status).toBe("failed");
		}
	});
});

describe("listDeclaringModules", () => {
	// The denominator `run.complete` rests on, and until now the one thing in
	// this file passed in as a fixture rather than derived.

	function declare(rel: string, ids: string[]): void {
		const path = resolve(dir, rel);
		mkdirSync(resolve(path, ".."), { recursive: true });
		// Built by concatenation, not by a template literal. Spelling the call
		// out inline made *this file* match the declaration regex, so the scanner
		// read `${id}` as a declared case id out of its own source. Inert only by
		// accident today — listDeclaringModules drops it because it is not in the
		// catalog, and catalogAlignment only checks catalog -> declared — but the
		// reverse drift check is the natural next assertion and would turn red.
		const call = 'conformanceCase("';
		writeFileSync(
			path,
			ids.map((id) => `${call}${id}", "t", async () => {});\n`).join(""),
			"utf-8",
		);
	}

	it("finds a catalog case declared under tests/, recursively", () => {
		// report.ts read one directory, flat; catalogAlignment walked both,
		// recursively — and accepts a declaration from `tests/` explicitly. The
		// module was therefore missing from the denominator, so its absence from
		// a run could not be detected.
		declare("conformance-tests/test_a.test.ts", ["case-a"]);
		declare("tests/core/nested/test_b.test.ts", ["case-b"]);

		expect(
			listDeclaringModules(fromDir, new Set(["case-a", "case-b"])),
		).toEqual([
			"conformance-tests/test_a.test.ts",
			"tests/core/nested/test_b.test.ts",
		]);
	});

	it("excludes a module that declares no catalog case", () => {
		// tests/core/conformanceCaseCoverage.test.ts declares ids deliberately
		// absent from the catalog. Counting it would make a conformance-only run
		// report itself incomplete for skipping a module with no catalog case in
		// it — an honest denominator counts a module exactly when skipping it
		// leaves a catalog case unexercised.
		declare("conformance-tests/test_a.test.ts", ["case-a"]);
		declare("tests/core/coverage.test.ts", ["cov-not-in-catalog"]);

		expect(listDeclaringModules(fromDir, new Set(["case-a"]))).toEqual([
			"conformance-tests/test_a.test.ts",
		]);
	});

	it("ignores a declaration in a directory vitest does not collect", () => {
		// The scanner and catalogAlignment agreed with each other and neither
		// agreed with vitest: the scan walked all of `tests/`, the config
		// collects only `tests/core/**` and `tests/auth/**`. A catalog case
		// declared under `tests/integration/` therefore entered the denominator
		// and could never be collected, so a fully green run published
		// `{complete: false, not_run: 0, exit_status: 0}` on every subsequent
		// run, permanently. Both now come from COLLECTED_DIRS.
		declare("conformance-tests/test_a.test.ts", ["case-a"]);
		declare("tests/integration/probe.test.ts", ["case-b"]);

		expect(
			listDeclaringModules(fromDir, new Set(["case-a", "case-b"])),
		).toEqual(["conformance-tests/test_a.test.ts"]);
	});

	it("returns paths, not basenames", () => {
		// `tests/**` and `conformance-tests/**` are both collected, and the
		// collected-module match was `endsWith("/" + basename)` — so a same-named
		// file under tests/ could stand in for the conformance module.
		declare("conformance-tests/shared.test.ts", ["case-a"]);
		declare("tests/core/shared.test.ts", ["case-b"]);

		expect(
			listDeclaringModules(fromDir, new Set(["case-a", "case-b"])),
		).toEqual([
			"conformance-tests/shared.test.ts",
			"tests/core/shared.test.ts",
		]);
	});
});

import {
	existsSync,
	readdirSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import yaml from "yaml";
import type { ConformanceResult } from "./conformanceCase.js";
import { COLLECTED_DIRS } from "./collected.js";
import {
	currentRunId,
	isResultsFile,
	isResultsFileForRun,
} from "./resultsStore.js";

type CatalogCase = { id: string };
type Catalog = {
	catalog_id?: string;
	catalog_version?: string;
	cases: CatalogCase[];
};

// Report-only. "unknown" says the case never ran, so nothing is known about its
// coverage — it is not something a declaration can select, which is why it
// widens ConformanceResult's level here rather than ConformanceCoverage, the
// parameter type conformanceCase() takes.
export type ReportCoverage = {
	level: ConformanceResult["coverage"]["level"] | "unknown";
	gaps: string[];
	note: string;
};

/**
 * The directories a catalog case may be declared in, from `conformance-tests/`.
 *
 * Exactly the directories vitest collects, because they come from the same
 * constant vitest.config.ts builds its `include` from. Scanning a directory
 * vitest does not collect puts a module in `complete`'s denominator that can
 * never satisfy it — a permanent `complete: false` on a green run — and
 * scanning one it does collect too narrowly is the round-five Major.
 */
export function declarationScanDirs(fromDir: string): string[] {
	const packageRoot = resolve(fromDir, "..");
	return COLLECTED_DIRS.map((d) => resolve(packageRoot, d));
}

function walkTestFiles(dir: string): string[] {
	if (!existsSync(dir)) return [];
	const out: string[] = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const p = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...walkTestFiles(p));
		else if (entry.isFile() && p.endsWith(".test.ts")) out.push(p);
	}
	return out;
}

/**
 * Every `conformanceCase(...)` declaration under `dirs`: case id → modules.
 *
 * One scanner for the two readers that have to agree. They previously shared a
 * regex and nothing else: catalogAlignment walked `tests/` and
 * `conformance-tests/` recursively, this file read one directory flat. So a
 * catalog case declared under `tests/` — an arrangement catalogAlignment
 * documents and accepts — was absent from `complete`'s denominator, and its
 * absence from a run could not be detected. Sharing a regex is not sharing a
 * set; this is the set.
 *
 * Paths come back relative to `root`, so a module is identified by where it
 * lives rather than by its basename. `tests/**` and `conformance-tests/**` are
 * both collected, and matching on basename let a same-named file under `tests/`
 * stand in for a conformance module.
 */
export function scanConformanceDeclarations(
	root: string,
	dirs: string[],
): Map<string, string[]> {
	const idRe = /conformanceCase\s*\(\s*["'`]([^"'`]+)["'`]\s*,/g;
	const byId = new Map<string, string[]>();

	for (const dir of new Set(dirs)) {
		for (const file of walkTestFiles(dir)) {
			const rel = relative(root, file);
			for (const m of readFileSync(file, "utf-8").matchAll(idRe)) {
				const id = m[1];
				if (id === undefined) continue;
				const mods = byId.get(id);
				if (mods === undefined) byId.set(id, [rel]);
				else if (!mods.includes(rel)) mods.push(rel);
			}
		}
	}

	return byId;
}

/**
 * Modules on disk that declare at least one *catalog* case.
 *
 * The denominator for `run.complete`, and it has to come from disk: vitest's
 * state only reports modules it collected, so under a file filter the others do
 * not exist for it and there is nothing to detect as missing.
 *
 * `catalogIds` is required, not optional. It is what keeps the denominator
 * honest: `tests/core/conformanceCaseCoverage.test.ts` declares two ids
 * deliberately absent from the catalog, to cover the `catch` path, and without
 * the filter it would enter the denominator and make `vitest run
 * conformance-tests/` report itself incomplete for not collecting a module that
 * exercises no catalog case. A module counts exactly when skipping it would
 * leave a catalog case unexercised, which is the question `complete` is asked —
 * and there is no caller that wants the other behaviour, so the signature
 * should not offer it.
 */
export function listDeclaringModules(
	fromDir: string,
	catalogIds: ReadonlySet<string>,
): string[] {
	const root = resolve(fromDir, "..");
	const byId = scanConformanceDeclarations(root, declarationScanDirs(fromDir));
	const modules = new Set<string>();

	for (const [id, mods] of byId) {
		if (!catalogIds.has(id)) continue;
		for (const m of mods) modules.add(m);
	}

	return [...modules].sort();
}

export function resolveCatalogPath(fromDir: string): string {
	const envPath = process.env.CONFORMANCE_CATALOG_PATH;

	const candidates = [
		envPath,
		// oss-repo/conformance/ — sibling of ts-sdk, from this file's location
		resolve(
			fromDir,
			"..",
			"..",
			"..",
			"..",
			"conformance",
			"oauth-sdk-conformance-catalog.yaml",
		),
		// oss-repo/conformance/ — when cwd is packages/sdk (npm -w invocation)
		resolve(
			process.cwd(),
			"..",
			"..",
			"..",
			"conformance",
			"oauth-sdk-conformance-catalog.yaml",
		),
		// oss-repo/conformance/ — when cwd is the ts-sdk repo root
		resolve(
			process.cwd(),
			"..",
			"conformance",
			"oauth-sdk-conformance-catalog.yaml",
		),
	];

	for (const c of candidates) {
		if (!c) continue;
		if (existsSync(c)) return c;
	}

	throw new Error(
		"Missing conformance catalog. Set CONFORMANCE_CATALOG_PATH or ensure oauth-sdk-conformance-catalog.yaml exists.",
	);
}

function buildConformanceMarkdown(payload: unknown): string {
	// Keep it simple and deterministic (alignment suite is already strict).
	return JSON.stringify(payload, null, 2) + "\n";
}

/**
 * Whether an incoming record replaces the one already held for its case id.
 *
 * Failure first, then recency. Two records for one case id are not a fault
 * condition here: four catalog ids are declared in two modules each, and both
 * declarations run. What was a fault is that the merge was decided by arrival
 * order alone, so a passing declaration overwrote a failing one whenever it
 * flushed second — the modules run in parallel forks, so that is a wall-clock
 * race. A case is reported passing only when every declaration of it passed.
 */
function supersedes(
	prev: ConformanceResult,
	next: ConformanceResult & { writtenAt: number },
	prevWrittenAt: number,
): boolean {
	if (prev.status === "failed" && next.status !== "failed") return false;
	if (prev.status !== "failed" && next.status === "failed") return true;
	return next.writtenAt >= prevWrittenAt;
}

export function loadResultsFromJsonlFiles(
	dirs: string[],
): Map<string, ConformanceResult> {
	return loadResults(dirs).results;
}

/** As {@link loadResultsFromJsonlFiles}, plus what had to be skipped. */
export function loadResults(dirs: string[]): {
	results: Map<string, ConformanceResult>;
	malformedLines: number;
} {
	const map = new Map<string, ConformanceResult>();
	const writtenAtByCase = new Map<string, number>();
	let malformedLines = 0;

	const expectedRunId = currentRunId();

	for (const dir of new Set(dirs)) {
		if (!existsSync(dir)) continue;

		// Filter by *file* first, not only by record. The run id is in the
		// filename, so a foreign run's file can be skipped unread — which is what
		// makes `malformed_result_lines` a claim about this run's own evidence.
		// Counting another run's torn line meant a run reported a defect it did
		// not produce, and then pruned the file that would have shown otherwise,
		// so the claim was not reproducible afterwards.
		//
		// The record-level check below is kept rather than dropped as redundant:
		// the filename is the writer's claim about a file, the `runId` in each
		// record is the authoritative one, and a mislabelled file should not be
		// able to leak records into a report.
		const files = readdirSync(dir).filter(
			(n) =>
				isResultsFile(n) &&
				(expectedRunId === undefined || isResultsFileForRun(n, expectedRunId)),
		);

		for (const file of files) {
			const text = readFileSync(resolve(dir, file), "utf-8");
			for (const line of text.split("\n")) {
				if (!line.trim()) continue;
				// Skip a torn line rather than taking down the aggregation. These
				// files are appended to concurrently by forked workers, so a
				// partial write is a real possibility — and one malformed line
				// used to throw out of the teardown and leave the report stale
				// on an otherwise green run, permanently, since nothing prunes
				// this directory.
				let parsed:
					| (ConformanceResult & { writtenAt: number; runId?: string })
					| undefined;
				try {
					parsed = JSON.parse(line) as ConformanceResult & {
						writtenAt: number;
						runId?: string;
					};
				} catch {
					malformedLines += 1;
					continue;
				}
				if (expectedRunId && parsed.runId !== expectedRunId) continue;

				// Failure wins, then recency. Four catalog ids are declared in two
				// modules each, those modules run in parallel forks, and
				// last-writtenAt-wins therefore let a passing declaration overwrite
				// a failing one whenever it happened to flush second — three runs
				// in four, measured. The published artifact was a clean bill of
				// conformance for all 104 cases on a run with a failing conformance
				// test, with `runner.exit_status: 1` the only true field in it.
				//
				// Failure-wins makes those ids deterministic without needing the
				// duplicates removed: a case is reported as passing only when every
				// declaration of it passed.
				const prev = map.get(parsed.caseId);
				const prevWrittenAt = writtenAtByCase.get(parsed.caseId) ?? 0;
				if (prev !== undefined && !supersedes(prev, parsed, prevWrittenAt))
					continue;
				writtenAtByCase.set(parsed.caseId, parsed.writtenAt);
				map.set(parsed.caseId, parsed);
			}
		}
	}

	return { results: map, malformedLines };
}

/** What one collected module did this run. */
export type ModuleRunFacts = {
	/** Path relative to the package root, e.g. `conformance-tests/x.test.ts`. */
	id: string;
	/** Tests vitest collected in this module and ran (passed or failed). */
	ran: number;
	/** Tests vitest collected in this module but did not run. */
	skipped: number;
	/** Whether vitest reported the module itself as failed. */
	failed?: boolean;
};

export type RunFacts = {
	/**
	 * Case-declaring modules vitest collected, one entry each.
	 *
	 * Per module, not summed. Summed counts cannot distinguish "every module
	 * ran something" from "one module ran everything and another ran nothing",
	 * and the second is what an import-time throw produces: vitest reports the
	 * module (collection failed, not the module), `allTests()` yields nothing
	 * for it, so the totals showed zero skipped tests and a full module list
	 * while twelve catalog cases went `not_run` under `complete: true`.
	 */
	modules?: ModuleRunFacts[];
	/** Case-declaring modules present on disk, relative to the package root. */
	declaringModules?: string[];
	/** JSONL lines that could not be parsed and were skipped. */
	malformedLines?: number;
	/** ISO timestamp; injected rather than read so the payload stays pure. */
	generatedAt?: string;
};

/** Parse catalog YAML. For callers that hold the text rather than the document. */
export function parseCatalog(catalogText: string): Catalog {
	return yaml.parse(catalogText) as Catalog;
}

/**
 * Build the report payload from a catalog and the results collected for it.
 *
 * Pure: takes the results rather than reading them, so it can be exercised
 * without a suite run. The `results` map is what `loadResultsFromJsonlFiles`
 * returns.
 */
export function buildReportPayload(
	doc: Catalog,
	results: Map<string, ConformanceResult>,
	pkg: { name?: string; version?: string },
	facts: RunFacts = {},
): Record<string, unknown> {
	const catalogIds = doc.cases.map((c) => c.id);

	const entries = catalogIds.map((id) => {
		const r = results.get(id);
		if (!r) {
			// Not "full". A case with no conformanceCase(...) call at all — or one
			// whose result did not reach this reader — has an unknown coverage
			// level, and claiming full coverage for it is the same false statement
			// the per-case declarations exist to remove, at the scale of the whole
			// catalog.
			return {
				case_id: id,
				status: "not_run",
				coverage: {
					level: "unknown",
					gaps: ["The case did not run, so its coverage was never determined."],
					note: "",
				} satisfies ReportCoverage,
			};
		}
		return {
			case_id: id,
			status: r.status,
			test_name: r.testName,
			coverage: r.coverage,
			failure: r.failure
				? { message: r.failure.message, stack: r.failure.stack }
				: undefined,
		};
	});

	const total = entries.length;
	const passed = entries.filter((e) => e.status === "passed").length;
	const failed = entries.filter((e) => e.status === "failed").length;
	const not_run = entries.filter((e) => e.status === "not_run").length;

	// State what was observed, not what it might imply.
	//
	// Three earlier shapes got this wrong in the same direction — each one
	// answering a question next to the one `complete` is asked. Inferring "the
	// run was filtered" from `not_run > 0` said the opposite of the truth
	// whenever a catalog case had no test, which the catalog calls an alignment
	// bug rather than a filter artefact. Deriving it from module membership then
	// missed `-t`, which filters *tests* while collecting every module. Summing
	// tests across modules then missed the module that collected none.
	//
	// Three ways for a module's cases to go unexercised, and the summed form is
	// blind to the third:
	//
	//   -t <pattern>   every module collected, most tests skipped
	//   file filter    modules absent from vitest's state entirely
	//   import throw   module present, zero tests, nothing skipped
	//
	// Per module, the three collapse into one question — did every module that
	// declares a catalog case actually run a test, and did nothing get skipped.
	// The first two clauses are what the earlier shapes each caught separately;
	// the `ran > 0` in the first is what catches the third.
	const modules = facts.modules;
	const declaring = facts.declaringModules;
	const byId = new Map((modules ?? []).map((m) => [m.id, m]));
	const ran = modules?.reduce((n, m) => n + m.ran, 0);
	const skippedTests = modules?.reduce((n, m) => n + m.skipped, 0);
	const complete =
		modules === undefined || declaring === undefined
			? undefined
			: // An empty denominator is not a complete run. `declaring.every(...)`
				// on an empty list is vacuously true, so a scan that matched nothing
				// used to publish `{complete: true, modules_declaring: 0}` off a set
				// it had failed to find.
				declaring.length > 0 &&
				declaring.every((d) => (byId.get(d)?.ran ?? 0) > 0) &&
				modules.every((m) => m.skipped === 0);

	const run: Record<string, unknown> = {
		...(complete === undefined ? {} : { complete }),
		...(ran === undefined ? {} : { conformance_tests_ran: ran }),
		...(skippedTests === undefined
			? {}
			: { conformance_tests_skipped: skippedTests }),
		...(modules === undefined || declaring === undefined
			? {}
			: {
					modules_collected: modules.length,
					modules_declaring: declaring.length,
				}),
		// Only when the run was complete. "A missing case is treated as not_run
		// and fails alignment" (catalog README), but that verdict is only
		// readable off a run that actually covered the catalog — under
		// `complete: false` the not_run cases are what the filter left out and
		// say nothing about alignment. Omitted rather than guessed there.
		...(complete === true ? { alignment_ok: not_run === 0 } : {}),
		...(facts.malformedLines
			? { malformed_result_lines: facts.malformedLines }
			: {}),
	};

	return {
		catalog_id: doc.catalog_id ?? "oauth-sdk-conformance-catalog",
		catalog_version: doc.catalog_version ?? "",
		// The catalog's usage_guidance asks for an execution timestamp, and
		// go-sdk emits generated_at. Without it a stale report is indistinguishable
		// from a fresh one — which matters now that generation can be skipped.
		...(facts.generatedAt ? { generated_at: facts.generatedAt } : {}),
		...(Object.keys(run).length > 0 ? { run } : {}),
		implementation: {
			name: pkg.name ?? "authplane-core",
			version: pkg.version ?? "",
			language: "TypeScript",
		},
		// "Non-zero on any failure" (conformance README, runner.exit_status). A
		// count of failed *cases* misses a module that never got to report one —
		// an import-time throw failed twelve cases into not_run and still wrote
		// exit_status 0. go-sdk threads the real runner status through; this now
		// does the same, falling back to the case count when the caller has no
		// runner state to give (buildReportPayload is also called directly by
		// tests).
		runner: {
			tool: "vitest",
			// The runner's status, and only that. An earlier revision folded "a
			// complete run left cases not_run" in here on the grounds that the
			// catalog calls a missing case an alignment failure — defensible as a
			// reading, wrong as a place to put it. go populates this field with
			// the literal process exit code (`generateReports(exitStatus int)`),
			// so two SDKs would answer one Field Contract field with two
			// different questions and a consumer diffing across languages could
			// not tell which. It also overwrote a fact the payload no longer
			// carried anywhere else. The alignment verdict lives in
			// `run.alignment_ok` instead, which is additive — the shape the
			// catalog explicitly permits.
			exit_status: modules?.some((m) => m.failed) || failed > 0 ? 1 : 0,
		},
		// `skipped` counts *cases*, not tests. The catalog defines summary over
		// cases — "total MUST equal cases.length" — and `skipped` as a per-case
		// status meaning "intentionally not exercised, with coverage.note
		// explaining why". A test count here broke the invariant outright:
		// 12+0+109+92 = 213 against a total of 104, while zero cases carried
		// that status. The skipped *tests* are a property of the run, and they
		// live in run.conformance_tests_skipped.
		summary: {
			total,
			passed,
			failed,
			skipped: entries.filter((e) => e.status === "skipped").length,
			not_run,
		},
		cases: entries,
	};
}

/**
 * Read the collected results and write conformance-report.{json,md}.
 *
 * Called from the vitest globalSetup teardown, i.e. after every test file has
 * finished and flushed its JSONL — not from inside a test file, where it
 * raced the workers writing the records it reads.
 *
 * Returns false without writing when this run covered no catalog case. The
 * teardown fires on every vitest invocation, including a unit-only one, and
 * writing then would replace a real report with an all-`unknown` one.
 *
 * The predicate is "did this run cover the catalog", not "did it record
 * anything". Those differ: `tests/core/conformanceCaseCoverage.test.ts` calls
 * `conformanceCase()` with ids that are deliberately not in the catalog, so a
 * unit run records two results and a `size === 0` check would wave it through.
 */
export function writeConformanceReport(
	fromDir: string,
	facts: RunFacts = {},
): boolean {
	// One directory, derived the same way the writer derives it — from the
	// package, not from the cwd. The reader used to try two candidates because
	// the writer's was cwd-dependent, and the wipe cleared only one of them.
	const packageRoot = resolve(fromDir, "..");
	const resultsDir = resolve(packageRoot, ".conformance-results");
	const { results, malformedLines } = loadResults([resultsDir]);
	// Cheap short-circuit first. Reading the catalog above this regressed a case
	// that used to be clean: with no catalog present and the skip flag unset,
	// `vitest run tests/core/errors.test.ts` threw out of the teardown, because
	// resolveCatalogPath ran before anything could bail. Only the id
	// intersection needs the catalog, so it can wait until there is something
	// to intersect.
	if (results.size === 0) return false;

	const catalogPath = resolveCatalogPath(fromDir);
	const catalogText = readFileSync(catalogPath, "utf-8");
	// Parsed once and handed down. buildReportPayload used to re-parse the same
	// text from the string, so a catalog of this size was walked twice per run
	// for one list of ids.
	const catalog = parseCatalog(catalogText);
	const catalogIds = new Set(catalog.cases.map((c) => c.id));
	// "Did this run cover the catalog", not "did it record anything". Those
	// differ: tests/core/conformanceCaseCoverage.test.ts records ids that are
	// deliberately absent from the catalog, so a unit-only run has size > 0.
	if (![...results.keys()].some((id) => catalogIds.has(id))) return false;

	const pkg = JSON.parse(
		readFileSync(resolve(packageRoot, "package.json"), "utf-8"),
	) as {
		name?: string;
		version?: string;
	};

	// Scoped to the catalog, and scoped here rather than in the teardown: the
	// caller has vitest's module list but no catalog, and "declares a catalog
	// case" is the only definition of the denominator that makes `complete`
	// answerable. Restricting the collected list to the same set is what keeps
	// `runner.exit_status` off unit-test failures the catalog never heard of.
	const declaring =
		facts.declaringModules ?? listDeclaringModules(fromDir, catalogIds);
	const modules = facts.modules?.filter((m) => declaring.includes(m.id));

	const payload = buildReportPayload(catalog, results, pkg, {
		...facts,
		...(modules === undefined ? {} : { modules }),
		declaringModules: declaring,
		malformedLines,
		generatedAt: facts.generatedAt ?? new Date().toISOString(),
	});

	// Both files land or neither does.
	//
	// Rendering before writing was not enough: it removes a *render* failure
	// between the two writes, and the likelier failure is on the second write
	// itself — permissions, ENOSPC, the file open elsewhere. With sequential
	// writes an unwritable `.md` left the `.json` already replaced, so the two
	// artifacts described different runs, the teardown printed "report left
	// stale" (false for the one it had just rewritten), and the prune was
	// skipped, leaving two runs' records under a report that had moved on.
	//
	// Two mechanisms, and it is worth being exact about which does what, because
	// neither makes this a transaction.
	//
	// Staging to a temporary and renaming buys atomicity *per file*: `rename(2)`
	// within a directory is atomic, so a reader never observes a half-written
	// report, and a write that fails partway (ENOSPC, a short write) leaves the
	// published file untouched rather than truncated.
	//
	// Ordering is what buys the pair. Two renames cannot be one operation, so
	// one of them can always fail after the other succeeded — the `.md` goes
	// first and the `.json` last, so the file consumers actually read only
	// appears once its pair is already in place. That is the property the test
	// pins; staging is not separately observable from the outside.
	const outputs: Array<[string, string]> = [
		["conformance-report.md", buildConformanceMarkdown(payload)],
		["conformance-report.json", JSON.stringify(payload, null, 2) + "\n"],
	];

	const staged = outputs.map(([name, body]) => {
		const tmp = resolve(packageRoot, `.${name}.tmp`);
		writeFileSync(tmp, body, "utf-8");
		return [tmp, resolve(packageRoot, name)] as const;
	});
	for (const [tmp, final] of staged) renameSync(tmp, final);

	pruneForeignRunRecords(resultsDir);
	return true;
}

/**
 * Retire records that are not this run's, once this run has published.
 *
 * Replaces an unconditional wipe in `setup`. That wipe fired on every vitest
 * invocation, including the alignment-only run the README and the drift
 * workflow tell you to make, so a filtered run destroyed the previous full
 * run's records while leaving its report in place — the artifact survived and
 * the evidence behind it did not.
 *
 * Deleting whole files rather than filtering lines is what retires a torn line:
 * a malformed record has no readable run id, so nothing scoped by run id could
 * ever have removed it, and it was reported on every subsequent run forever.
 * Its *file* is attributable even when its contents are not.
 *
 * Only after a successful catalog write, so a run that published nothing —
 * unit-only, name-filtered, crashed — leaves everything it found untouched.
 */
function pruneForeignRunRecords(resultsDir: string): void {
	const runId = currentRunId();
	if (runId === undefined || !existsSync(resultsDir)) return;

	for (const name of readdirSync(resultsDir)) {
		if (!isResultsFile(name)) continue;
		if (isResultsFileForRun(name, runId)) continue;
		rmSync(resolve(resultsDir, name), { force: true });
	}
}

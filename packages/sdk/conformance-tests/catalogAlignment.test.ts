import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
	declarationScanDirs,
	loadCatalogIds,
	scanConformanceDeclarations,
} from "./report.js";

/**
 * The declared-id set, from the scanner `run.complete`'s denominator uses.
 *
 * These two readers used to share a regex and nothing else — this file walked
 * `tests/` and `conformance-tests/` recursively, report.ts read one directory
 * flat — while report.ts's docstring claimed they agreed by construction. A
 * catalog case declared under `tests/`, which the call below explicitly accepts,
 * was therefore invisible to the denominator. One function now, so the claim is
 * structural rather than asserted.
 */
function extractConformanceIdsFromDirs(dirs: string[]): Set<string> {
	return new Set(extractConformanceDeclarations(dirs).keys());
}

/** The same scan, keeping which module declared each id. */
function extractConformanceDeclarations(dirs: string[]): Map<string, string[]> {
	return scanConformanceDeclarations(resolve(__dirname, ".."), dirs);
}

/**
 * The module the harness self-test ids are allowed to be declared in.
 *
 * Keying the exemption on the id alone made the carve-out "these two ids,
 * anywhere in the collected tree" — copying one of those declarations into a
 * real conformance module left it exempt, and both directions stayed green.
 * That is the open namespace the prefix form had, narrowed to two names rather
 * than closed. The scanner already returns id → modules, so pinning the
 * declaring module costs nothing and makes the exemption say what it means.
 */
const HARNESS_SELF_TEST_MODULE = "tests/core/conformanceCaseCoverage.test.ts";

/** Whether `id` is exempt: named, and declared only in the harness self-test. */
function isHarnessSelfTest(id: string, declaringModules: string[]): boolean {
	return (
		HARNESS_SELF_TEST_IDS.includes(id) &&
		declaringModules.length > 0 &&
		declaringModules.every((mod) => mod === HARNESS_SELF_TEST_MODULE)
	);
}

/**
 * Declared ids that belong to the harness's own tests, not to the catalog.
 *
 * `tests/core/conformanceCaseCoverage.test.ts` drives `conformanceCase`'s
 * `catch` path — a non-Error throwable and an Error instance — through the real
 * production function, so those declarations go through the same call site a
 * catalog case does. That is the point of them, and it is also why the scanner
 * sees them. They describe the harness rather than a protocol requirement, so
 * no catalog case will ever carry these ids.
 *
 * Named one by one, deliberately, rather than matched on a `cov-` prefix. A
 * prefix is an open namespace: every future id starting with `cov-` leaves the
 * invariant without anyone deciding that it should, including one written in a
 * real conformance module. That was not hypothetical — a declaration of the id
 * `cov-rfc8414-this-case-does-not-exist`, added to
 * test_rfc8414_conformance.test.ts, passed green under the prefix form. Two
 * names cost one line each to extend, and extending them is then a visible act
 * in the diff.
 *
 * The id above is named, not written as a call: the scanner reads this
 * directory, and a marker-shaped call in a comment is a declaration as far as
 * the regex is concerned. The assertion below caught exactly that in this
 * docstring on its first run.
 *
 * The suite below also holds this list to its claim, so it cannot quietly
 * outlive the tests it exists for.
 */
const HARNESS_SELF_TEST_IDS: readonly string[] = [
	// conformanceCase records a non-Error throwable and does not rethrow it.
	"cov-conformanceCase-throw-string",
	// conformanceCase records an Error instance; the published record is then
	// asserted to carry its message.
	"cov-conformanceCase-throw-error",
];

const skipCatalog = process.env.AUTHPLANE_CONFORMANCE_SKIP_CATALOG === "1";

describe.skipIf(skipCatalog)("conformance catalog alignment", () => {
	it("catalog cases and conformanceCase declarations agree in both directions", () => {
		const catalogIds = loadCatalogIds(__dirname);

		// Same directories the denominator scans, from the same helper.
		const declarations = extractConformanceDeclarations(
			declarationScanDirs(__dirname),
		);
		const conformanceIds = new Set(declarations.keys());

		// Direction one: a catalog case nothing declares. Bumping the pin
		// without adding coverage lands here.
		const uncovered = [...catalogIds]
			.filter((id) => !conformanceIds.has(id))
			.sort();

		// Direction two: a declaration the catalog does not carry — a typo, a
		// renamed case, a case dropped from the pin. report.ts silently ignores
		// declarations it cannot match, so without this the marker claims
		// coverage that maps to nothing and the run stays green while the
		// catalog case it was meant to cover has none.
		const orphaned = [...conformanceIds]
			.filter(
				(id) =>
					!catalogIds.has(id) &&
					!isHarnessSelfTest(id, declarations.get(id) ?? []),
			)
			.sort();

		// Both directions in one verdict, rather than two sequential
		// expectations. A typo'd id breaks both at once — the real case goes
		// uncovered and the misspelling is an orphan — and short-circuiting on
		// the first named only the case that lost its coverage, never the
		// misspelling that took it. That reads as "add coverage for a case that
		// already has some" and sends the reader looking in the wrong place.
		const problems = [
			...uncovered.map(
				(id) =>
					`catalog case "${id}" has no conformanceCase(...) declaration — add coverage, or drop the case from the pinned catalog`,
			),
			...orphaned.map(
				(id) =>
					`conformanceCase("${id}") names a case the pinned catalog does not carry — correct the id, or bump .conformance-catalog-ref to a catalog that has it`,
			),
		];

		expect(problems).toEqual([]);
	});

	it("every harness self-test exception is still earning its exemption", () => {
		const catalogIds = loadCatalogIds(__dirname);
		const conformanceIds = extractConformanceIdsFromDirs(
			declarationScanDirs(__dirname),
		);

		// An exemption for an id nothing declares any more is dead weight that
		// reads as a live carve-out, and it is exactly what a future reader
		// would copy when adding the next one.
		const stale = HARNESS_SELF_TEST_IDS.filter(
			(id) => !conformanceIds.has(id),
		).map(
			(id) =>
				`"${id}" is exempted but no longer declared anywhere — drop it from HARNESS_SELF_TEST_IDS`,
		);

		// An exemption that shadows a real catalog case is worse than none: the
		// case would be exempted from the coverage direction it is supposed to
		// be held to.
		const shadowing = HARNESS_SELF_TEST_IDS.filter((id) =>
			catalogIds.has(id),
		).map(
			(id) =>
				`"${id}" is exempted but the catalog now carries it — remove the exemption so the case is held to the coverage assertion`,
		);

		// An exemption only holds where it was granted. A declaration of an
		// exempt id in a real conformance module is the open namespace again,
		// one name at a time.
		const declarations = extractConformanceDeclarations(
			declarationScanDirs(__dirname),
		);
		const misplaced = HARNESS_SELF_TEST_IDS.flatMap((id) =>
			(declarations.get(id) ?? [])
				.filter((mod) => mod !== HARNESS_SELF_TEST_MODULE)
				.map(
					(mod) =>
						`"${id}" is exempted but declared in ${mod} — the exemption covers ${HARNESS_SELF_TEST_MODULE} only`,
				),
		);

		expect([...stale, ...shadowing, ...misplaced]).toEqual([]);
	});
});

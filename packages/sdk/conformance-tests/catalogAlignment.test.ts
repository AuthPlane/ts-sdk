import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import yaml from "yaml";
import { declarationScanDirs, scanConformanceDeclarations } from "./report.js";

type CatalogCase = { id: string };

type Catalog = {
	cases: CatalogCase[];
};

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
	return new Set(
		scanConformanceDeclarations(resolve(__dirname, ".."), dirs).keys(),
	);
}

const skipCatalog = process.env.AUTHPLANE_CONFORMANCE_SKIP_CATALOG === "1";

describe.skipIf(skipCatalog)("conformance catalog alignment", () => {
	it("all catalog case ids are covered by conformance tests", () => {
		const envPath = process.env.CONFORMANCE_CATALOG_PATH;

		const candidates = [
			envPath,
			// oss-repo/conformance/ — sibling of ts-sdk, from test file location
			resolve(
				__dirname,
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

		const catalogPath =
			candidates
				.filter((p): p is string => typeof p === "string")
				.find((p) => existsSync(p)) ??
			candidates.find((p): p is string => typeof p === "string") ??
			candidates[0];

		if (!catalogPath || !existsSync(catalogPath)) {
			throw new Error(
				"Missing conformance catalog. Set CONFORMANCE_CATALOG_PATH or ensure oauth-sdk-conformance-catalog.yaml exists.",
			);
		}

		const text = readFileSync(catalogPath, "utf-8");
		const doc = yaml.parse(text) as Catalog;
		const catalogIds = new Set(doc.cases.map((c) => c.id));

		// Same directories the denominator scans, from the same helper.
		const conformanceIds = extractConformanceIdsFromDirs(
			declarationScanDirs(__dirname),
		);

		const missing = Array.from(catalogIds).filter(
			(id) => !conformanceIds.has(id),
		);

		expect(missing).toEqual([]);
	});
});

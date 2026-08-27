import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The on-disk contract for conformance records, in one place.
 *
 * Three parties touch `.conformance-results/`: the workers that append records
 * (conformanceCase.ts), the reader that aggregates them (report.ts), and the
 * pruner that retires the previous run's (globalSetup.ts). They disagreed.
 *
 * The writer resolved the directory against `process.cwd()`; the reader tried
 * two candidate directories; the wipe cleared exactly one of them. So
 * `npx vitest run --root packages/sdk` from the repo root wrote records into a
 * directory the wipe never reached, which is what made a single torn line
 * permanent: a malformed line has no readable run id, so no scoping could
 * retire it, and nothing deleted the file it lived in.
 *
 * The run id is now part of the filename rather than only of each record. That
 * is what lets the prune be evidence-preserving — a run can retire *files* it
 * knows are not its own, including files it cannot parse, without having to
 * read a run id out of them.
 */

/**
 * Where conformance records live in a real run.
 *
 * Anchored on this file so writer, reader and pruner agree regardless of the
 * cwd vitest was started from. `writeConformanceReport` derives the same path
 * from its `fromDir` argument instead, so it can be pointed at a tmpdir.
 */
export const RESULTS_DIR = resolve(
	dirname(fileURLToPath(import.meta.url)),
	"..",
	".conformance-results",
);

/**
 * Filename-safe form of a run id.
 *
 * Run ids arrive from `AUTHPLANE_CONFORMANCE_RUN_ID`, i.e. from whoever invoked
 * vitest, so they can contain path separators.
 */
export function runIdSlug(runId: string): string {
	return runId.replace(/[^A-Za-z0-9._-]/g, "_") || "unscoped";
}

const PREFIX = "conformance-results-";
const SUFFIX = ".jsonl";

export function resultsFileName(runId: string, workerId: string): string {
	return `${PREFIX}${runIdSlug(runId)}-${workerId}${SUFFIX}`;
}

/** Any results file, including ones this run cannot attribute or parse. */
export function isResultsFile(name: string): boolean {
	return name.startsWith(PREFIX) && name.endsWith(SUFFIX);
}

/**
 * The run a results file belongs to, or undefined if the name is not one.
 *
 * Split at the last `-`, which is the worker id. Matching by prefix instead
 * meant run `X` claimed run `X-1`'s files: kept as this run's and so never
 * pruned, while their records were rejected by the exact run-id check on the
 * way in — so they accumulated, and a torn line in one was counted on every
 * subsequent run forever, which is the permanence the prune exists to end.
 */
export function runIdOfResultsFile(name: string): string | undefined {
	if (!isResultsFile(name)) return undefined;
	const stem = name.slice(PREFIX.length, -SUFFIX.length);
	const cut = stem.lastIndexOf("-");
	return cut === -1 ? undefined : stem.slice(0, cut);
}

export function isResultsFileForRun(name: string, runId: string): boolean {
	return runIdOfResultsFile(name) === runIdSlug(runId);
}

/**
 * This run's id, or undefined when the environment carries none.
 *
 * `??=` was used to default this and does not replace an empty string, so
 * `AUTHPLANE_CONFORMANCE_RUN_ID= npx vitest run` kept the empty value — which
 * the reader treats as "no run id" and therefore as "accept every record".
 * An explicitly empty value has to read as absent, not as a scope that matches
 * everything.
 */
export function currentRunId(): string | undefined {
	const fromEnv = process.env.AUTHPLANE_CONFORMANCE_RUN_ID;
	return fromEnv === undefined || fromEnv === "" ? undefined : fromEnv;
}

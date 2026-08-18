# Conformance Test Suite (TypeScript)

This directory is structured as follows:

- Tests are mapped to the shared OAuth SDK Conformance Catalog via a case ID.
- A meta-test enforces that **every** catalog case ID is represented by at least one conformance test in this package.

## Mapping to the Catalog

TS uses a small helper to declare conformance cases:

```ts
import { conformanceCase } from "./conformanceCase.js";

conformanceCase(
  "rfc9068-valid-at-jwt-must-verify",
  "RFC 9068: validates a correct token",
  async () => {
    // test body
  },
);
```

The catalog case ID lives on the test itself (in the `conformanceCase(...)` call).

## Catalog Alignment (Meta-test)

`catalogAlignment.test.ts` loads the shared OAuth SDK Conformance Catalog YAML (auto-discovered from the sibling [`AuthPlane/conformance`](https://github.com/AuthPlane/conformance) checkout at `../conformance/oauth-sdk-conformance-catalog.yaml`, or via the `CONFORMANCE_CATALOG_PATH` env override), extracts all `case-id`s, and verifies that every `case-id` appears in this package's conformance suite by scanning conformance test files for `conformanceCase("<id>", ...)`.

If any catalog case is missing, the alignment test fails.

CI pins the catalog to a fixed revision, single-sourced in
[`.conformance-catalog-ref`](../../../.conformance-catalog-ref) at the repo
root, so a catalog change can never break CI on its own. Check out that same
revision in your sibling clone to match CI (from the repo root, `git -C
../conformance checkout "$(cat .conformance-catalog-ref)"`; see
[CONTRIBUTING.md](../../../CONTRIBUTING.md#local-verification)). A weekly
`conformance-catalog-drift` workflow re-runs this meta-test against the catalog's
latest default branch and fails the scheduled run — without blocking PR CI, which
has no drift trigger — when new cases need coverage and a pin bump.

## Coverage Metadata and Reporting

`conformanceCase()` accepts optional coverage metadata as a fourth argument, with a `level`/`gaps`/`note` shape:

```ts
conformanceCase(
  "rfc9068-valid-at-jwt-must-verify",
  "RFC 9068: validates a correct token",
  async () => { /* ... */ },
  { level: "partial", gaps: ["edge-case-x"], note: "optional explanation" },
);
```

Each case records its pass/fail outcome plus coverage metadata to `.conformance-results/conformance-results-<runId>-<workerId>.jsonl` (one JSONL file per vitest worker, so parallel forks aggregate cleanly). The directory is resolved from the package root, not from the working directory, so it is the same directory wherever vitest is invoked from. The report is generated in the vitest `globalSetup` teardown (`conformance-tests/globalSetup.ts`), which runs once in the main process after every test file has finished — so it reads the records after the writers have flushed them rather than racing them. It merges those records against the catalog and writes two reports to the package root:

- `conformance-report.json` — structured payload: catalog id/version, implementation info, per-case status (`passed` | `failed` | `not_run`), coverage metadata, and failure details when applicable. A `not_run` case is reported with `level: "unknown"` — a harness state, not a coverage verdict: the case did not run, so its coverage was never determined. A declaration cannot select `unknown`; only the report emits it.
- `conformance-report.md` — human-readable mirror of the JSON payload.

### Run scoping and record retention

`globalSetup` assigns a run id on every invocation, unconditionally, and scoping is per *invocation* rather than per environment. `AUTHPLANE_CONFORMANCE_RUN_ID`, if set, is folded in as a **label** — the scope is `<label>-<pid>-<timestamp>`.

That is deliberate and it is not the knob it looks like. When the env var *was* the scope, exporting it once made every run write under the same slug: the pruner classified the previous run's files as this run's and kept them, `loadResults` accepted their records, and nothing was ever retired. A fully green run then republished an earlier run's failure — `failed: 1`, `exit_status: 1`, `complete: true`, fresh `generated_at` — because the failure-first merge below is right *within* a run and has no time bound of its own. Making the scope a property of the invocation is what gives it one.

Records are retired by the run that *publishes*, after it has published, not on startup: a run that writes no report (unit-only, name-filtered, alignment-only, crashed) leaves everything it found in place. Retiring whole files rather than filtering lines is what retires a torn record — a partial write has no readable run id, so nothing scoped by run id could remove it, but the file it lives in is still attributable.

### Reading `run`

The report carries a `run` object describing the run itself, alongside `generated_at`:

| field | meaning |
| --- | --- |
| `complete` | Every module declaring a catalog case was collected, each ran at least one test, and no collected test was skipped. When false, a `not_run` case may be an artifact of the filter rather than an alignment bug. |
| `conformance_tests_ran` | Tests in case-declaring modules that passed or failed. Higher than the case count when a case id is declared in more than one module. |
| `conformance_tests_skipped` | Tests vitest collected in those modules but did not run. |
| `modules_collected` / `modules_declaring` | Case-declaring modules vitest collected, against those found on disk. |
| `alignment_ok` | Whether a complete run exercised every catalog case. Omitted when `complete` is false. |
| `malformed_result_lines` | JSONL lines in *this run's* files that could not be parsed and were skipped. |

`complete` needs all three clauses because there are three ways for a module's cases to go unexercised and no two of them look alike: `-t <pattern>` collects every module and skips tests; a file filter removes modules from vitest's state entirely; a module that throws at import is present with zero tests and nothing skipped.

A case id declared in two modules merges failure-first, then by recency — so a case is reported passing only when every declaration of it passed, regardless of which fork flushed last.

The report is written only when the run actually covered a catalog case, so a unit-only run cannot replace a real report with an all-`unknown` one.

### `runner.exit_status` and `run.alignment_ok`

`runner.exit_status` is the runner's status and only that: non-zero when a conformance module failed or a case reported `failed`. go populates the same field with the literal process exit code, so keeping it to that question is what lets a report be diffed across languages.

The alignment verdict is separate. "A missing case is treated as `not_run` and fails alignment" (catalog README), so `run.alignment_ok` is `false` when a complete run left cases `not_run`. It is **omitted** under `complete: false` — there the `not_run` cases are what the filter left out and say nothing about alignment, which is the distinction `complete` exists to draw. `run` is an additive extension, which the catalog explicitly permits; redefining a Field Contract field would not be.

Note that `summary.skipped` is structurally always `0` here: this SDK has no path that emits `skipped` for a case, because nothing calls `conformanceCase` with a deferral. It is not that the SDK skips nothing by coincidence — the status is currently unreachable. go-sdk sets it from `t.Skipped()`.

### Where a case may be declared

`conformance-tests/collected.ts` holds the one list of directories vitest collects, and `vitest.config.ts` builds its `include` from it while the declaration scanner scans exactly those. A catalog case may be declared in any of them.

This is one constant rather than two lists because they have to agree: a scanner that looks somewhere vitest does not collect puts a module in `complete`'s denominator that can never satisfy it, and one that looks in fewer places misses a declaration that is genuinely covered. Both have happened.

Not yet supported: `xfail`-style markers for intentionally-failing not-yet-implemented cases. Use `{ level: "partial", gaps: [...] }` coverage annotations on passing cases for now, or omit the case until implemented.

## Running

From `packages/sdk`:

```bash
# Run the meta-test only (from repo root)
npm run test -w @authplane/sdk -- conformance-tests/catalogAlignment.test.ts

# Run the full core suite (includes conformance tests)
npm run test -w @authplane/sdk

# Skip catalog-dependent work (catalogAlignment + report generation)
AUTHPLANE_CONFORMANCE_SKIP_CATALOG=1 npm run test -w @authplane/sdk
```

See [CONTRIBUTING.md](../../../CONTRIBUTING.md#local-verification) for the full setup, including the expected sibling-checkout layout.

## Test Files

- `test_rfc8414_conformance.test.ts`: RFC 8414
- `test_oauth_protocol_conformance.test.ts`: RFC 6749, RFC 7009, RFC 7662, RFC 8693, RFC 8707
- `test_jwt_and_dpop_conformance.test.ts`: RFC 9068, RFC 8725, RFC 9449, RFC 9728


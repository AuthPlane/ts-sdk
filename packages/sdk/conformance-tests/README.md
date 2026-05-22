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

Each case records its pass/fail outcome plus coverage metadata to `.conformance-results/conformance-results-<workerId>.jsonl` (one JSONL file per vitest worker, so parallel forks aggregate cleanly). After the conformance suite finishes, `z_conformanceReport.test.ts` merges those records against the catalog and writes two reports to the package root:

- `conformance-report.json` — structured payload: catalog id/version, implementation info, per-case status (`passed` | `failed` | `not_run`), coverage metadata, and failure details when applicable.
- `conformance-report.md` — human-readable mirror of the JSON payload.

The `AUTHPLANE_CONFORMANCE_RUN_ID` env var (set automatically by the `test` and `test:coverage` scripts) scopes aggregation to the current run so stale JSONL entries from a prior run aren't mixed in.

Not yet supported: `xfail`-style markers for intentionally-failing not-yet-implemented cases. Use `{ level: "partial", gaps: [...] }` coverage annotations on passing cases for now, or omit the case until implemented.

## Running

From `packages/sdk`:

```bash
# Run the meta-test only (from repo root)
npm run test -w @authplane/sdk -- conformance-tests/catalogAlignment.test.ts

# Run the full core suite (includes conformance tests)
npm run test -w @authplane/sdk

# Skip catalog-dependent tests (catalogAlignment + z_conformanceReport)
AUTHPLANE_CONFORMANCE_SKIP_CATALOG=1 npm run test -w @authplane/sdk
```

See [CONTRIBUTING.md](../../../CONTRIBUTING.md#local-verification) for the full setup, including the expected sibling-checkout layout.

## Test Files

- `test_rfc8414_conformance.test.ts`: RFC 8414
- `test_oauth_protocol_conformance.test.ts`: RFC 6749, RFC 7009, RFC 7662, RFC 8693, RFC 8707
- `test_jwt_and_dpop_conformance.test.ts`: RFC 9068, RFC 8725, RFC 9449, RFC 9728


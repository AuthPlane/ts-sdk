# Contributing to the Authplane TypeScript SDK

Thanks for your interest in contributing. This repository is an npm workspaces monorepo publishing three packages:

| npm package | Import | Directory |
|---|---|---|
| `@authplane/sdk` | `@authplane/sdk` (subpath exports: `./core`, `./auth`) | `packages/sdk/` |
| `@authplane/mcp` | `@authplane/mcp` | `packages/mcp/` |
| `@authplane/fastmcp` | `@authplane/fastmcp` | `packages/fastmcp/` |

Adapters depend on `@authplane/sdk`. A single tagged release publishes all three at the same version (see [RELEASE_POLICY.md](RELEASE_POLICY.md)).

## Reporting Issues

- **Bugs:** open a [bug report](https://github.com/AuthPlane/ts-sdk/issues/new?template=bug-report.md). Include package name, version, Node version, and a minimal reproduction.
- **MCP client compatibility:** use the [MCP Compatibility Report](https://github.com/AuthPlane/ts-sdk/issues/new?template=mcp-compatibility.md) template.
- **Feature requests:** open a [feature request](https://github.com/AuthPlane/ts-sdk/issues/new?template=feature-request.md). Describe the problem, then the proposed solution.
- **Security vulnerabilities:** do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Development Setup

### Prerequisites

- Node.js 22 LTS (or newer)
- npm 10.x (bundled with Node 22) — the repo uses npm workspaces; pnpm/yarn are not supported
- `git`

### Install

Clone the repo and install the workspace:

```bash
git clone https://github.com/AuthPlane/ts-sdk.git
cd ts-sdk
npm ci
```

`npm ci` installs against the committed `package-lock.json`. Use `npm install` only when deliberately updating dependencies — otherwise prefer `ci` for reproducibility.

## Local Verification

Run the same checks CI runs before opening a PR.

**Lint and format (biome):**

```bash
npm run lint              # biome lint --error-on-warnings
npm run format            # biome format (writes changes)
```

`npm run lint` runs across all three workspace packages. Use `npm run format` to auto-fix formatting.

**Type-check and build (tsc):**

```bash
npm run typecheck         # same as: tsc -b
npm run build             # same as: tsc -b
```

The workspace uses [TypeScript project references](https://www.typescriptlang.org/docs/handbook/project-references.html). `tsc -b` at the root (or in any package) walks the reference graph — it builds `@authplane/sdk` first, then `@authplane/mcp` and `@authplane/fastmcp`. Adapter packages resolve cross-package types directly from `sdk`'s source, so you never need to manually rebuild the SDK before working on an adapter.

Incremental state lives in each package's `tsconfig.tsbuildinfo`; repeat invocations only recompile what changed. Clean state: `rm -rf packages/*/dist packages/*/tsconfig.tsbuildinfo`.

`typecheck` and `build` are the same command today (`tsc -b` emits `.d.ts` as a byproduct of type-checking with project references). Keeping two script names for habit and future divergence.

**Tests (vitest):**

```bash
npm test                  # all three workspaces
npm run test:coverage     # same, with v8 coverage output
```

Individual workspaces:

```bash
npm test -w @authplane/sdk
npm test -w @authplane/mcp
npm test -w @authplane/fastmcp
```

Coverage target: ≥ 85% on statements, branches, functions, and lines for every workspace — enforced in CI via the shared vitest config (`vitest.coverage.shared.ts`).

**Conformance tests (shared catalog required):**

`@authplane/sdk`'s conformance suite (`packages/sdk/conformance-tests/`) validates the SDK against the shared OAuth SDK Conformance Catalog, which lives in [`AuthPlane/conformance`](https://github.com/AuthPlane/conformance). Clone that repo as a **sibling** of your `ts-sdk/` clone:

```bash
# From the directory that contains your ts-sdk/ clone
git clone https://github.com/AuthPlane/conformance.git
```

Expected layout:

```
parent-dir/
├── ts-sdk/
└── conformance/
    └── oauth-sdk-conformance-catalog.yaml
```

With that layout in place, `npm test` auto-discovers the catalog — no configuration required. Override the path with `CONFORMANCE_CATALOG_PATH` if the catalog lives elsewhere:

```bash
CONFORMANCE_CATALOG_PATH=/path/to/oauth-sdk-conformance-catalog.yaml \
  npm run test -w @authplane/sdk
```

If the catalog isn't available at all, skip the two catalog-dependent tests with:

```bash
AUTHPLANE_CONFORMANCE_SKIP_CATALOG=1 npm test
```

`catalogAlignment.test.ts` and `z_conformanceReport.test.ts` then report as `skipped`; the rest of the SDK suite runs as normal. Without either the catalog present or the skip flag set, those two tests fail with a clear error.

**Package pack smoke test:**

```bash
cd packages/sdk && npm pack
cd ../mcp && npm pack
cd ../fastmcp && npm pack
```

Produces `.tgz` tarballs locally. `release.yml` and `publish-npm.yml` run this as part of validation; `npm publish` is never run locally against the real registry.

## Pull Request Guidelines

- Branch off `main`. Release branches (`release/v*`, `hotfix/v*`) are managed by the release flow — see [RELEASE_POLICY.md](RELEASE_POLICY.md).
- PR titles follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `ci:`, `deps:`, `refactor:`, `test:`, `chore:`.
- Link any related GitHub issue in the PR description (e.g., `Fixes #123`).
- Fill out the PR template (summary, testing, checklist).
- Keep PRs focused. Large, multi-theme PRs are hard to review and easy to stall.

## Changelog

User-facing changes go in [`CHANGELOG.md`](CHANGELOG.md) under the `[Unreleased]` heading. Follow the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Release tooling moves entries from `[Unreleased]` to the release version on tag.

## GitHub Actions — SHA-pinning

All workflow actions should be SHA-pinned with a version comment:

```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

When editing or adding a workflow, run [`pinact`](https://github.com/suzuki-shunsuke/pinact) to pin any new `uses:` lines before committing:

```bash
pinact run
```

Dependabot opens weekly PRs to bump the SHAs (see [`.github/dependabot.yml`](.github/dependabot.yml)).

## Running the Demo

The end-to-end demo exercises the FastMCP and MCP adapters against a local Authplane authorization server.

Prerequisites:

1. OAuth server running locally on `:9000`/`:9001` with client credentials, token exchange, and DPoP enabled.
2. Demo client registration with required grant types and scopes.
3. Adapter demo server (`packages/fastmcp/demo/run.sh` or `packages/mcp/demo/run.sh`).
4. Demo client execution (Python or TypeScript matrix client).

Entry points:

- `packages/fastmcp/demo/run.sh`
- `packages/mcp/demo/run.sh`

### Manual E2E smoke

Helper scripts in `scripts/` boot a local authserver and run a smoke check:

```bash
# Start local authserver and register client/scopes/user.
bash scripts/manual-e2e-setup.sh

# Smoke against the MCP adapter (default).
bash scripts/manual-e2e-smoke.sh --skip-setup

# Smoke against the FastMCP adapter.
bash scripts/manual-e2e-smoke.sh --adapter fastmcp --skip-setup
```

Optional overrides:

- `AUTHSERVER_DIR=/path/to/authserver`
- `ISSUER_URL=http://localhost:9000`
- `RESOURCE_URL=http://localhost:8080/mcp`

### Common demo failures

- `client_credentials grant is not enabled` — OAuth server is missing `AUTHPLANE_CLIENT_CREDENTIALS_ENABLED=true`.
- `client is not authorized for this grant type` — client registration is missing `urn:ietf:params:oauth:grant-type:token-exchange`.
- `requested scope is invalid or not allowed` — requested scopes are not registered or assigned to the demo client.
- `invalid API key` — admin API requests are using a different key than the server startup key.

## Code of Conduct

Be kind. Disagree on substance, not people. Projects that aren't kind don't last.

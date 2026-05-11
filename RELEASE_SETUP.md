# Release setup

One-time operator steps required before the release pipeline can publish to npm. All three packages (`@authplane/sdk`, `@authplane/mcp`, `@authplane/fastmcp`) share a single publish token under the `@authplane` scope.

## 1. npm publish token

Create an **Automation** token on [npmjs.com](https://www.npmjs.com/) for a user with publish access to the `@authplane` scope:

1. Sign in as the `@authplane` org owner (or any member with publish rights).
2. **Access Tokens → Generate New Token → Granular Access Token**.
3. Under **Packages and scopes**, select `@authplane/*` with **Read and write** permission.
4. Copy the token.

## 2. GitHub Environment

In the `AuthPlane/ts-sdk` repository:

1. **Settings → Environments → New environment → `npm`**.
2. Add the token as an environment secret named `NPM_TOKEN`.
3. (Optional) Add **required reviewers** so every release waits for a human approval before uploading to npm.
4. (Optional) Restrict the environment to tags matching `v*.*.*` so only the tag-triggered `publish-npm.yml` workflow can deploy. The release tag is pushed directly onto the `release/v*` / `hotfix/v*` source branch (no merge to the default branch); `publish-npm.yml` runs on the tag push and publishes to npm with Sigstore provenance (OIDC id-token).

## 3. CHANGELOG

The release workflow reads `CHANGELOG.md` for notes. Ensure:

- Every release has a `## [X.Y.Z]` heading on the source branch (`release/v*` or `hotfix/v*`) before running the release workflow.
- The default branch always carries `## [Unreleased]` between releases. The `cut-release` workflow enforces this on `release/v*` cuts (refuses to cut if missing); `hotfix/v*` cuts skip the check because they branch off an older tag.

## 4. Recovery: partial npm upload

npm does not support atomic multi-package uploads. If `publish-npm.yml` publishes one or two packages then fails:

1. Download the build artifact from the failed workflow run (named `dist-vX.Y.Z`). It preserves the repo's directory structure:
   ```
   packages/sdk/authplane-sdk-X.Y.Z.tgz
   packages/mcp/authplane-mcp-X.Y.Z.tgz
   packages/fastmcp/authplane-fastmcp-X.Y.Z.tgz
   ```
2. For each package still missing from npm, authenticate locally (`npm login` or `NODE_AUTH_TOKEN=<token>` in `~/.npmrc`) and publish the tarball from the artifact:
   ```bash
   npm publish --access public packages/sdk/authplane-sdk-X.Y.Z.tgz
   npm publish --access public packages/mcp/authplane-mcp-X.Y.Z.tgz
   npm publish --access public packages/fastmcp/authplane-fastmcp-X.Y.Z.tgz
   ```
   Sigstore provenance (`--provenance`) requires GitHub Actions OIDC and cannot be produced from a developer machine; the manual recovery publish ships without an attestation. Note this on the GitHub Release.
3. Manually create the GitHub Release if that step was also skipped:
   ```bash
   gh release create vX.Y.Z --title vX.Y.Z --notes-file <path-to-notes>
   ```
   No `--target` — the tag already points at the correct commit on the (now deleted) source branch.
4. If any commits on the source branch need to reach the default branch, dispatch the **Backport fixes** workflow with `fromBranch=vX.Y.Z` (the tag, not the branch — the branch was deleted after the atomic push).

The git tag is already live, so re-running the workflow is not an option (tag-exists pre-flight will refuse).

# Release Guide

How to ship a new version of `@authplane/{sdk,mcp,fastmcp}`. All three packages release together at the same version. See [`RELEASE_POLICY.md`](RELEASE_POLICY.md) for the policy this guide implements.

## Prerequisites

- You are an `@authplane` npm org member with publish rights and a maintainer on `AuthPlane/ts-sdk`.
- **Trusted Publisher** is configured on npmjs.com for each of `@authplane/sdk`, `@authplane/mcp`, `@authplane/fastmcp`, pointing at `AuthPlane/ts-sdk` + workflow `publish-npm.yml` + environment `npm`. (Once-per-package; see *Troubleshooting → First publish of a brand-new package* if a package hasn't been onboarded yet.)
- **Settings → Actions → General → Workflow permissions → "Allow GitHub Actions to create and approve pull requests"** is enabled on the repo. (Once-per-repo; required for the next-dev bump PR.)
- `CHANGELOG.md` on `main` has a populated `## [Unreleased]` section.

## Happy path: current-line release

For a normal forward-progress release off `main`.

### 1. Cut the release branch

Dispatch **Actions → Cut release branch** from `main`. Inputs:

- `releaseVersion`: target version, e.g. `1.3.0` (no prerelease suffix).
- Leave `hotfixBase` empty.
- `nextDevVersion`: optional override; defaults to next patch `-dev.0`.

The workflow:

- Branches off `main` as `release/v<X.Y.Z>` with all three `package.json` versions set to `<X.Y.Z>-rc.0`.
- Pushes a separate chore branch and opens a PR titled `chore: bump main to <next>-dev.0`. Attempts auto-merge.

### 2. Merge the next-dev bump PR

If auto-merge succeeded, nothing to do. Otherwise merge it manually. After merge, `main` reports `<next>-dev.0` across all four `package.json` files (root + three packages).

### 3. Stabilize the release branch

On `release/v<X.Y.Z>`:

- Move content from `## [Unreleased]` in `CHANGELOG.md` into a new `## [<X.Y.Z>]` section.
- Land any last-minute fixes (lint, doc updates, etc.).

### 4. (Optional) Dry-run the release workflow

Dispatch **Actions → Release** with `release/v<X.Y.Z>` selected and `dryRun: true`. Runs tests, bumps versions, builds, packs — but does **not** push the tag, create the Release, or trigger npm publish.

### 5. Dispatch the release workflow

Dispatch **Actions → Release** with `release/v<X.Y.Z>` selected and `dryRun: false`. The workflow:

- Reruns lint / typecheck / coverage against the branch.
- Bumps versions from `<X.Y.Z>-rc.N` to `<X.Y.Z>`, commits as `release: <X.Y.Z>`.
- Creates the annotated tag `v<X.Y.Z>`.
- Builds and packs locally as a pre-flight check.
- **Atomic-pushes** the branch and tag.
- Creates the GitHub Release with notes extracted from `CHANGELOG.md`.
- Deletes `release/v<X.Y.Z>` on the remote.

The tag push triggers `publish-npm.yml`:

- Verifies all three `package.json` versions match the tag.
- Builds, packs, publishes via Trusted Publisher (OIDC).
- Uploads the three tarballs as a `dist-v<X.Y.Z>` artifact (30-day retention) for recovery.

The `publish-npm.yml` job runs in the `npm` GitHub Environment, which is configured with **required reviewers**. A maintainer must approve the run before the publish steps execute — this is the deliberate human checkpoint between a tag push and an irreversible npm publish, and should remain enabled regardless of the auth mechanism in use.

### 6. Confirm

- `npm view @authplane/sdk version` and the same for `mcp` and `fastmcp` all report `<X.Y.Z>`.
- The GitHub Release page renders with `_Released commit: <sha>_` plus the CHANGELOG notes.
- Tag `v<X.Y.Z>` points at the release commit (`git ls-remote --tags origin 'v<X.Y.Z>^{}'`).

## Happy path: older-line hotfix

For patches to an older minor line — e.g. shipping `0.5.2` after `1.0.0` is already out.

### 1. Cut the hotfix branch

Dispatch **Actions → Cut release branch** from `main`. Inputs:

- `releaseVersion`: target patch, e.g. `0.5.2`.
- `hotfixBase`: the existing tag to branch from, e.g. `v0.5.1`. Must be on the same minor line as `releaseVersion` and strictly older than `main`'s latest tag.
- `nextDevVersion`: ignored for hotfixes.

The workflow branches off the tag as `hotfix/v<X.Y.Z>` with no version edits and no next-dev bump PR.

### 2. Stabilize the hotfix branch

- Add a `## [<X.Y.Z>]` section to `CHANGELOG.md` on the hotfix branch.
- Land the fix (cherry-pick from `main` or commit directly).

### 3. Dispatch the release workflow

Same as steps 4–6 of the current-line flow, but with `hotfix/v<X.Y.Z>` selected. `release.yml` writes the target version straight into `package.json` (no `-rc.N` to strip).

### 4. Backport if needed

After publish, if any commits on the hotfix branch should also reach `main`, dispatch **Actions → Backport fixes** with `fromBranch=v<X.Y.Z>` — the tag, because the hotfix branch is deleted by `release.yml` on success.

---

## Troubleshooting

### Partial npm upload

`publish-npm.yml` publishes the three packages sequentially. If a later publish fails after an earlier one succeeded, the version is already on the registry for the succeeded package(s); re-running the workflow won't help (the tag-exists check refuses, and npm forbids overwriting a published version).

Recovery:

1. Download the `dist-v<X.Y.Z>` build artifact from the failed workflow run. Structure:
   ```
   packages/sdk/authplane-sdk-X.Y.Z.tgz
   packages/mcp/authplane-mcp-X.Y.Z.tgz
   packages/fastmcp/authplane-fastmcp-X.Y.Z.tgz
   ```
2. For each missing package, authenticate locally (`npm login` as an `@authplane` org member) and publish the tarball from the artifact:
   ```bash
   npm publish --access public packages/<pkg>/authplane-<pkg>-X.Y.Z.tgz
   ```
3. If the workflow also failed before creating the GitHub Release:
   ```bash
   gh release create v<X.Y.Z> --title v<X.Y.Z> --notes-file <path-to-notes>
   ```
   No `--target` — the tag already points at the correct commit.
4. If any commits on the source branch need to reach `main`, dispatch **Backport fixes** with `fromBranch=v<X.Y.Z>` (the tag — the branch is deleted after the atomic push).

### Next-dev bump PR fails to open

If **Cut release branch** logs `GitHub Actions is not permitted to create or approve pull requests` at the *Open PR with next-dev bump* step, the repo setting is missing. Enable:

**Settings → Actions → General → Workflow permissions → "Allow GitHub Actions to create and approve pull requests"**

The chore branch with the version bump was already pushed by the previous step. Open the PR by hand against `main` from that branch, then continue from step 3 of the happy path.

### Source branch delete failed

`release.yml` deletes `release/v*` / `hotfix/v*` on success. If the branch ruleset doesn't allow the bot to delete, the workflow logs a warning but does not fail. Run:

```bash
git push origin --delete release/v<X.Y.Z>
```

### Tag push blocked by branch/tag ruleset

If a ruleset prevents `release.yml` from pushing `v<X.Y.Z>` (the bot can't create tags matching `v*`), fall back to a fully manual release from a maintainer's machine.

```bash
# Fresh clone keeps the release commit identity local to this release.
git clone git@github.com:AuthPlane/ts-sdk.git /tmp/ts-sdk-release-v<X.Y.Z>
cd /tmp/ts-sdk-release-v<X.Y.Z>
git checkout release/v<X.Y.Z>

# Maintainer identity — use YOUR AuthPlane identity, not a personal one.
git config user.name "<your-github-username>"
git config user.email "<your-authplane-email>"

node scripts/release/set-package-versions.mjs <X.Y.Z>
git add -A
git commit -m "release: <X.Y.Z>"
git tag -a v<X.Y.Z> -m "Release v<X.Y.Z>"
git push --atomic origin release/v<X.Y.Z> v<X.Y.Z>
```

`publish-npm.yml` triggers on the tag push and publishes via Trusted Publisher as usual.

After publish completes:

```bash
sha="$(git rev-parse HEAD)"
{ echo "_Released commit: \`$sha\`_"; echo;
  awk '/^## \[<X.Y.Z>\]/{f=1;next} /^## \[/{f=0} f' CHANGELOG.md;
} > /tmp/notes-<X.Y.Z>.md

gh release create v<X.Y.Z> --title v<X.Y.Z> --notes-file /tmp/notes-<X.Y.Z>.md
git push origin --delete release/v<X.Y.Z>
rm -rf /tmp/ts-sdk-release-v<X.Y.Z>
```

Then merge (or open by hand) the next-dev bump PR if it's still outstanding. Confirm via step 6 of the happy path.

### First publish of a brand-new `@authplane/*` package

Trusted Publisher cannot be configured on a package that doesn't exist yet — npmjs.com has no settings page for non-existent packages. Bootstrap a new `@authplane/<pkg>` in this order:

1. **Manual first publish from a maintainer machine.** Authenticate locally with a one-off granular token (`@authplane/*` write, `authplane` org read+write, bypass-2FA enabled) and publish the package's first version:
   ```bash
   npm publish --access public -w @authplane/<pkg>
   ```
   This can be a real `0.1.0` or a placeholder like `0.0.0-bootstrap.0`. The point is just to get the package onto the registry so it has a settings page.
2. **Configure Trusted Publisher** on the now-existing package's npmjs.com settings page → **Trusted Publishers → Add publisher** → **GitHub Actions**:
   - Organization or user: `AuthPlane`
   - Repository: `ts-sdk`
   - Workflow filename: `publish-npm.yml`
   - Environment: `npm`
3. **Revoke the bootstrap token** on npmjs.com. All subsequent releases of this package now flow through `publish-npm.yml` via OIDC.

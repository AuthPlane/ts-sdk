# Release Guide

How to ship a new version of `@authplane/{sdk,mcp,fastmcp,hono,nestjs}`. All five packages release together at the same version. See [`RELEASE_POLICY.md`](RELEASE_POLICY.md) for the policy this guide implements.

## Prerequisites

- You are an `@authplane` npm org member with publish rights and a maintainer on `AuthPlane/ts-sdk`.
- **Trusted Publisher** is configured on npmjs.com for each of `@authplane/sdk`, `@authplane/mcp`, `@authplane/fastmcp`, `@authplane/hono` and `@authplane/nestjs`, pointing at `AuthPlane/ts-sdk` + workflow `publish-npm.yml` + environment `npm`. (Once-per-package; see *Troubleshooting → First publish of a brand-new package* if a package hasn't been onboarded yet.)
- **Settings → Actions → General → Workflow permissions → "Allow GitHub Actions to create and approve pull requests"** is enabled on the repo. (Once-per-repo; required for the next-dev bump PR.)
- `CHANGELOG.md` on `main` has a populated `## [Unreleased]` section.

## Happy path: current-line release

For a normal forward-progress release off `main`.

### 1. Cut the release branch

Dispatch **Actions → Cut release branch** from `main`. Inputs:

- `releaseVersion`: target version, e.g. `1.3.0` (no prerelease suffix).
- Leave `hotfixBase` empty.
- `nextDevVersion`: optional override; defaults to next-patch `-dev.0`. **Pre-1.0 the default is usually wrong** — every minor bump can ship a breaking change in 0.x, so the next dev line after cutting `0.Y.0` is `0.<Y+1>.0-dev.0`, not `0.Y.1-dev.0`. Pass `nextDevVersion=0.<Y+1>.0-dev.0` explicitly until the project reaches `1.0.0`. Once we're past 1.0 the patch default lines up with SemVer.

The workflow:

- Branches off `main` as `release/v<X.Y.Z>` with all six `package.json` files (root + five packages) set to `<X.Y.Z>-rc.0`.
- Pushes a separate chore branch and opens a PR titled `chore: bump main to <next>-dev.0`. Attempts auto-merge.

### 2. Merge the next-dev bump PR

If auto-merge succeeded, nothing to do. Otherwise merge it manually. After merge, `main` reports `<next>-dev.0` across all six `package.json` files (root + five packages), and in `package-lock.json`'s workspace snapshots, which `scripts/release/set-package-versions.mjs` rewrites alongside them.

### 3. Stabilize the release branch

On `release/v<X.Y.Z>`:

- Rename `## [Unreleased]` in `CHANGELOG.md` to `## [<X.Y.Z>] - <date>`, without adding a fresh
  `## [Unreleased]` above it. Renaming rather than moving is what step 7's reason 1 relies on:
  the commit this produces is the one that must not be cherry-picked back to `main` on its own,
  precisely because it leaves no `[Unreleased]` behind.
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

- Verifies all five package `package.json` versions match the tag.
- Builds, packs, publishes via Trusted Publisher (OIDC).
- Uploads the five tarballs as a `dist-v<X.Y.Z>` artifact (30-day retention) for recovery.

The `publish-npm.yml` job runs in the `npm` GitHub Environment, which is configured with **required reviewers**. A maintainer must approve the run before the publish steps execute — this is the deliberate human checkpoint between a tag push and an irreversible npm publish, and should remain enabled regardless of the auth mechanism in use.

### 6. Confirm

- `npm view @authplane/sdk version` and the same for `mcp`, `fastmcp`, `hono` and `nestjs` all report `<X.Y.Z>`.
- The GitHub Release page renders with `_Released commit: <sha>_` plus the CHANGELOG notes.
- Tag `v<X.Y.Z>` points at the release commit (`git ls-remote --tags origin 'v<X.Y.Z>^{}'`).

### 7. Record the release on `main`

**Do not skip this.** The `## [X.Y.Z]` rename from step 3 lives on `release/v<X.Y.Z>`, which
`release.yml` deletes on success — so `main` still has those entries under `[Unreleased]`. Leave it
that way and the *next* cut folds this version's changelog into the following one: everything you
just published gets re-announced under the next version number.

Open a small docs-only PR against `main` that adds a `## [X.Y.Z] - <tag date>` section holding the
entries that actually shipped, and leaves anything added since the cut under `## [Unreleased]`.
Keep the `## [Unreleased]` heading even when nothing has landed since the cut and it ends up empty —
`scripts/release/verify-changelog-unreleased.mjs` exits 1 on a *missing* section, so deleting it
along with its last bullet fails the next cut for exactly the reason reason 1 below exists to
prevent. Post-release work supplies the bullet before then.

**Do not rename the whole section.** Step 3 is a manual stabilize, and the publish gates on a
required reviewer in the `npm` environment (step 5), so the window between the cut and this step is
hours to days, and entries land on `main`'s `[Unreleased]` during it — reason 2 below depends on
that being true. Renaming in bulk files them under a version that never shipped them.

The authoritative list of what shipped is the GitHub Release notes, which `release.yml` extracted
from the release branch's own `## [X.Y.Z]` section. Move those; leave the rest.

Use the tag's date, not today's:

```bash
git fetch --tags origin
git for-each-ref --format='%(taggerdate:short)' refs/tags/v<X.Y.Z>
```

(The fetch matters: `for-each-ref` reads *local* refs, and CI created this tag — without it the
command prints nothing and exits 0, feeding an empty string into the date. And
`git log -1 --format=%as v<X.Y.Z>` prints the *author date of the tagged commit*, which is the same
`release.yml` run in practice but not what this step means.)

> **Why a docs-only PR rather than `Backport fixes` for the changelog.** Two reasons, neither of
> them the version-bump commits — the script already excludes those. `scripts/backport-fixes.sh`
> filters subjects matching `^(release|release-prep):` by default (`:220-221`, documented at
> `:40-43` and `:56-59`), and `backport-fixes.yml` invokes it with `--from`/`--to` only, so the
> filter is always on. Dispatched with `fromBranch=v<X.Y.Z>` it picks the changelog commit — and
> nothing else, unless step 3 also landed fixes, which is the case the closing paragraph covers.
>
> The actual reasons:
>
> 1. The release-branch commit renames `## [Unreleased]` to `## [X.Y.Z]` but does **not** add a
>    fresh `## [Unreleased]`. Cherry-picking it alone leaves `main` without the section
>    `cut-release.yml` requires — `scripts/release/verify-changelog-unreleased.mjs` (wired at
>    `cut-release.yml:197`) fails the next cut when `[Unreleased]` is missing or empty.
> 2. It will usually conflict with entries added to `main`'s `[Unreleased]` after the cut, and the
>    workflow fails hard on any cherry-pick conflict (`backport-fixes.yml:66-74`).
>
> **Do use it for the step-3 commits — but curate the branch first.** If any non-release commits
> landed on `release/v<X.Y.Z>` at step 3 — a lint fix, a doc correction — they are on the deleted
> branch and nowhere else. Dispatch **Actions → Backport fixes** with `fromBranch=v<X.Y.Z>` (the
> tag, since the branch is gone).
>
> The version-bump commits are filtered out by default, but **the changelog commit is not** — the
> filter matches `^(release|release-prep):` and that commit's subject does not. So it arrives as a
> candidate, and merging the branch as-generated produces exactly what reasons 1 and 2 describe.
> Doing step 7 first does not help: `git cherry` matches by patch-id, and the step-7 PR leaves
> `main`'s `[Unreleased]` in place with its post-cut entries, so the ids differ and the commit is
> still offered.
>
> Drop it before merging. The generated PR body already spells out the curation step, verbatim:
>
> ```
> git fetch origin
> git checkout <backport branch>
> git rebase -i origin/main   # drop commits you don't want
> git push --force-with-lease
> ```

Do this promptly — not because a delay misattributes anything (moving only what the Release notes
list is what removed that risk), but because `## [X.Y.Z]` is simply absent from `main` until it
lands, so the changelog there does not show a version that has already shipped.

## Happy path: older-line hotfix

For patches to an older minor line — e.g. shipping `0.5.2` after `1.0.0` is already out.

### 1. Cut the hotfix branch

Dispatch **Actions → Cut release branch** from `main`. Inputs:

- `releaseVersion`: target patch, e.g. `0.5.2`.
- `hotfixBase`: the existing tag to branch from, e.g. `v0.5.1`. Must be on the same minor line as `releaseVersion` and strictly older than `main`'s latest tag.
- `nextDevVersion`: ignored for hotfixes.

The workflow branches off the tag as `hotfix/v<X.Y.Z>` with no version edits and no next-dev bump PR.

### 2. Stabilize the hotfix branch

- Add a `## [<X.Y.Z>] - <date>` section to `CHANGELOG.md` on the hotfix branch, leaving
  `## [Unreleased]` untouched.
- Land the fix (cherry-pick from `main` or commit directly).

### 3. Dispatch the release workflow

Same as steps 4–6 of the current-line flow, but with `hotfix/v<X.Y.Z>` selected. `release.yml` writes the target version straight into `package.json` (no `-rc.N` to strip).

### 4. Backport the fix if needed

After publish, if any commits on the hotfix branch should also reach `main`, dispatch
**Actions → Backport fixes** with `fromBranch=v<X.Y.Z>` — the tag, because the hotfix branch is
deleted by `release.yml` on success. Curate the generated branch before merging, per step 7 of the
current-line flow: the changelog commit is not filtered out and should be dropped here too.

### 5. Record the release on `main`

Same gap as the current-line flow, different shape. Step 2 adds `## [X.Y.Z]` to the changelog on
`hotfix/v<X.Y.Z>`, and `release.yml` deletes that branch — so `main` never learns the version
shipped. Step 4 does not cover it: that is for the fix commits, and `Backport fixes` is the wrong
tool for the changelog here — a cherry-pick lands the section where it sat on the hotfix branch,
which is not where it belongs on `main`.

Step 7's reason 1 does *not* transfer, which is why the reason above is stated rather than
cross-referenced: step 2 adds `## [X.Y.Z]` without touching `[Unreleased]`, so cherry-picking it
leaves `main`'s `[Unreleased]` intact and the next cut passes.

The procedure differs from step 7 too: an older-line patch is **inserted in version order** among
the existing sections, not renamed from `## [Unreleased]`. Open a docs-only PR against `main`
adding `## [X.Y.Z] - <tag date>` in its correct position, and leave `## [Unreleased]` alone —
nothing in it shipped in this hotfix.

---

## Troubleshooting

### Re-running the publish workflow against a tag (clean retries only)

If the publish workflow fails **before any package was published** (e.g. an OIDC handshake glitch, a transient registry error on the first publish step, runner timeout during build), re-dispatch `publish-npm.yml` against the tag ref. This keeps the OIDC Trusted Publisher flow in play and the retry publishes all five packages with `--provenance`.

```bash
# -r MUST be a tag ref (refs/tags/vX.Y.Z) — see OIDC ref gotcha below.
gh workflow run publish-npm.yml -r v<X.Y.Z>
```

Or via the UI: **Actions → Publish to npm → Run workflow → Use workflow from: `v<X.Y.Z>`** (select the tag in the branch picker; tags appear under the same dropdown).

> ⚠️ **OIDC ref gotcha.** The OIDC token the npm CLI exchanges is built from `GITHUB_REF` at run time, **not** from any input. Dispatching the workflow from a branch (`main`, `develop`, …) emits an OIDC token with `ref=refs/heads/<branch>`, which the tag-only Trusted Publisher policy on npmjs.com rejects. **Always dispatch against the tag ref directly** as shown above.

> ⚠️ **Not for partial uploads.** `npm publish` is **not** idempotent against an existing `name@version`: it fails with `EPUBLISHCONFLICT` (HTTP 403, "You cannot publish over the previously published versions"). If some of the five packages already published before the failure, a re-dispatch will halt at the first `npm publish` step that hits an already-published version and never reach the remaining packages. Use the manual artifact flow below instead.

> ⚠️ **Shared concurrency group with the original tag-push run.** The workflow keys its concurrency group on `github.ref` (`refs/tags/vX.Y.Z`) with `cancel-in-progress: false`, so the tag-push run and a `workflow_dispatch` retry against the same tag share one slot. If the original tag-push run is still **pending environment approval** in the `npm` environment, a retry dispatch queues behind it rather than replacing it — and the retry will never start until the pending one is approved or cancelled. **Cancel the stuck pending-approval run first**, then dispatch the retry.

### Failed or partial publish (one or more packages not yet on the registry)

Covers both shapes: the workflow failed *entirely* before any package landed (the first `npm publish` step blew up, so nothing else was attempted) and the partial shape where some `@authplane/*` packages at this version are already on the registry and others aren't. The whole-failure case happens when the *first* publish step fails atomically; the partial case happens when a later step fails. Recovery is the same flow either way — only the set of missing packages changes.

You cannot recover either shape via the workflow when there are *already-published* packages: `npm publish` rejects the published ones with `EPUBLISHCONFLICT` and the run dies before reaching the missing ones. Use the CI-built tarball artifact + a targeted manual publish.

**Manual publishes lose the `--provenance` Sigstore attestation** on the recovered packages — manual `npm publish` cannot produce the Sigstore signature because the OIDC exchange runs only inside GitHub Actions. Packages that did publish via CI keep their attestation; manually-recovered ones never get one for this version.

> ⚠️ **Downstream `npm audit signatures` impact.** After a manual recovery, consumers of the manually-published packages at this version will see `npm audit signatures` report missing/unverifiable attestations for exactly those packages (not the CI-published ones). This is permanent for this version — npm versions are immutable, and provenance attaches at publish time. The attestation gap closes from the next release tag onwards. If a consumer pipeline gates on `audit signatures`, they'll need a one-version allowlist for the affected `@authplane/<pkg>@<X.Y.Z>` entries, or to pin past this version.

1. Download the `dist-v<X.Y.Z>` build artifact from the failed workflow run. Structure:
   ```
   packages/sdk/authplane-sdk-X.Y.Z.tgz
   packages/mcp/authplane-mcp-X.Y.Z.tgz
   packages/fastmcp/authplane-fastmcp-X.Y.Z.tgz
   packages/hono/authplane-hono-X.Y.Z.tgz
   packages/nestjs/authplane-nestjs-X.Y.Z.tgz
   ```
2. **Verify tarball integrity before publishing.** Each `.tgz` carries a checksum that the failed workflow logged at pack time (look for `npm notice shasum:` and `npm notice integrity:` lines in the workflow log — the pack step emits one block per package). Compare locally to confirm you're shipping exactly what CI built:
   ```bash
   # SHA-1 — compare against `npm notice shasum: <hex>` (hex output).
   shasum -a 1 packages/<pkg>/authplane-<pkg>-X.Y.Z.tgz

   # SHA-512 — compare against `npm notice integrity: sha512-<base64>`.
   # npm's `integrity:` field is base64 (not hex), so pipe through base64.
   openssl dgst -sha512 -binary packages/<pkg>/authplane-<pkg>-X.Y.Z.tgz | openssl base64 -A
   ```
   For the whole-failure case the *pack-step* notices cover all five packages (every tarball was built before any publish). For a partial failure the *publish-step* notice covers the package that was mid-upload when the run died. Skip this check and you risk republishing a stale or wrong-version artifact.
3. **Publish in dependency order**: `@authplane/sdk` first, then `@authplane/mcp`, `@authplane/fastmcp`, `@authplane/hono` and `@authplane/nestjs` in any order. All four adapters peer-depend on `@authplane/sdk` (`packages/<adapter>/package.json`), so it must be on the registry first; publishing them ahead of `sdk` poisons consumer installs until `sdk` lands. (For a partial recovery, this matters only when `sdk` is among the missing set.)
   ```bash
   # `npm login` as an `@authplane` org member first.
   # NOTE: `--provenance` is intentionally absent — see the caveat above.
   npm publish --access public packages/sdk/authplane-sdk-X.Y.Z.tgz
   npm publish --access public packages/mcp/authplane-mcp-X.Y.Z.tgz
   npm publish --access public packages/fastmcp/authplane-fastmcp-X.Y.Z.tgz
   npm publish --access public packages/hono/authplane-hono-X.Y.Z.tgz
   npm publish --access public packages/nestjs/authplane-nestjs-X.Y.Z.tgz
   ```
   **Check all five.** Stopping after the packages you remember shipping is how a
   version ends up permanently incomplete: npm versions are immutable, so an
   adapter missed here can never be published at `X.Y.Z`.
   Skip packages already on the registry — `npm view @authplane/<pkg>@<X.Y.Z>` returns the manifest when present, errors with `E404` when not.
4. If the workflow also failed before creating the GitHub Release:
   ```bash
   gh release create v<X.Y.Z> --title v<X.Y.Z> --notes-file <path-to-notes>
   ```
   No `--target` — the tag already points at the correct commit.
5. If any commits on the source branch need to reach `main`, dispatch **Backport fixes** with `fromBranch=v<X.Y.Z>` (the tag — the branch is deleted after the atomic push).

### Publish fails with `ENEEDAUTH` (Trusted Publishing didn't engage)

`publish-npm.yml` authenticates to npm via Trusted Publishing (OIDC) — no long-lived `NPM_TOKEN` secret. The OIDC exchange requires **npm ≥ 11.5.1**; older npm versions silently *skip* the OIDC handshake and fall back to demanding a classic credential, which the workflow doesn't supply, so the publish step dies with:

```
npm error code ENEEDAUTH
npm error need auth This command requires you to be logged in to https://registry.npmjs.org/
```

Node 22 LTS bundles npm 10.x at install time, so a runner pinned to `node-version: 22` hit this even on a fresh install. **The durable fix is already in place**: `publish-npm.yml` pins `node-version: 24` (npm 11.x), so a *current* `ENEEDAUTH` in CI means a regression — most likely the `node-version` line got downgraded, or the publish runs through some surface that bypasses `setup-node`. A future operator hitting this should look for that regression first, not assume the fix needs applying.

When you see `ENEEDAUTH`:

- **Workflow CI failure**: confirm the runner's `npm --version` in the workflow log is ≥ 11.5.1. If lower, restore the `node-version: 24` pin (or higher), or add an explicit `npm install -g npm@latest` step before the publish — whichever is missing.
- **Manual recovery publish**: if you publish locally as a one-off, run `npm install -g npm@latest` first if you want provenance. If your local npm is < 11.5.1, the publish still succeeds *without* provenance (classic-credential path) — that's the same attestation-gap outcome as any other manual recovery (see *Failed or partial publish* above).

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

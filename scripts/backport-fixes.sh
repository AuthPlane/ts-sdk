#!/usr/bin/env bash
set -euo pipefail

# Cherry-pick commits from a release/hotfix branch — or from the tag that
# names them once the branch is gone — to a local backport branch off main
# (or another target). Does NOT push, create PRs, or touch remotes beyond
# `git fetch`.
#
# Conflicts use git's native cherry-pick state machine — resolve, then
# `git cherry-pick --continue` (or --skip / --abort). Re-running this
# script is not needed after a conflict; git's sequencer handles it.
#
# Uses `git cherry` for patch-ID-based matching, so commits already
# cherry-picked to the target (under different SHAs) are correctly
# detected and excluded.

usage() {
  cat <<'EOF'
Usage:
  backport-fixes.sh --from <branch|tag> [--to <branch>] [--branch <name>] [--no-filter]

Options:
  --from <branch|tag>
                     Source branch OR tag on origin (e.g. release/v0.6.0,
                     hotfix/v0.5.1, v0.6.0). Do not include 'origin/'.
                     Required. After a release, release.yml has deleted
                     release/vX.Y.Z, so the tag is the only ref naming
                     those commits — which is what the release guide and
                     backport-fixes.yml both tell you to pass. A branch
                     wins if a branch and a tag share the name.
  --to <branch>      Target branch on origin (default: main). Branch only:
                     backport-fixes.yml opens a PR with --base, which
                     needs a branch that exists on the remote.
  --branch <name>    Name for the local backport branch (default:
                     `backport/vX.Y.Z` derived from --from when it
                     matches release/vX.Y.Z or hotfix/vX.Y.Z. Anything
                     else — a tag included — is flattened into
                     `backport/<flattened-from>`, so --from v0.6.0
                     gives `backport/v0.6.0`).
  --no-filter        Include commits whose subject starts with
                     'release:' or 'release-prep:' (automated version
                     bumps). Default behavior excludes them to keep
                     main's own -dev.N versioning intact.
  -h, --help         Show this help.

Behavior:
  1. Asks origin what <from> and <to> name in one query (git ls-remote for
     refs/heads/<from>, refs/tags/<from> and refs/heads/<to>), then fetches
     only the two refs that resolved — not the whole remote. --branch is
     validated up front but never fetched; it names a branch to create.
  2. Lists commits on the resolved <from> ref — origin/<from> for a
     branch, refs/tags/<from> for a tag — that aren't already on
     origin/<to>, and commits that are already there (skipped).
  3. Creates the backport branch off origin/<to>.
  4. Runs `git cherry-pick -x` with the candidates, oldest-first.
  5. On conflict: stops. Resolve, then `git cherry-pick --continue`.

  By default, commits with subjects matching ^(release|release-prep):
  are excluded from the candidate list — in this repo these are always
  automated version-file edits that would conflict with main's own
  version string. Pass --no-filter to include them.

If the backport branch already exists locally, the script fails — delete
it (`git branch -D <name>`) or pass `--branch <other-name>` to override.

No push. No PR. The branch stays local; you decide what to do next.

Example:
  backport-fixes.sh --from release/v0.6.0
EOF
}

FROM=""
TO="main"
BRANCH_OVERRIDE=""
FROM_SET=0
BRANCH_SET=0
NO_FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    # Both spellings. `--from=v1.0.0` took the `*)` arm below and exited 2 as an
    # unknown argument, which is not a defensible answer for the flag --help
    # leads with, and the sibling scripts accept it.
    --from=*)   FROM="${1#*=}"; FROM_SET=1; shift ;;
    --to=*)     TO="${1#*=}";              shift ;;
    --branch=*) BRANCH_OVERRIDE="${1#*=}"; BRANCH_SET=1; shift ;;
    # A value-taking flag typed without its value left `shift 2` with one
    # argument to shift, which fails, and `set -e` turned that into exit 1 with
    # nothing on either stream — the same shape of unexplained failure the
    # resolver below exists to remove, one layer out. backport-fixes.yml cannot
    # reach it (`--from "${{ inputs.fromBranch }}"` always passes a word, empty
    # or not), so this is the local CLI only.
    --from|--to|--branch)
      if [[ $# -lt 2 ]]; then
        echo "error: $1 requires a value" >&2
        exit 2
      fi
      case "$1" in
        --from)   FROM="$2"; FROM_SET=1 ;;
        --to)     TO="$2" ;;
        --branch) BRANCH_OVERRIDE="$2"; BRANCH_SET=1 ;;
      esac
      shift 2 ;;
    --no-filter) NO_FILTER=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# "Required" and "empty" are different errors, and --from was the one member of
# the family that named the wrong one: `--from=` reported "--from is required"
# for an argument that was provided. --to and --branch both say "cannot be
# empty" — --to because it defaults to a non-empty value, --branch via
# BRANCH_SET. FROM_SET is the same distinction for --from. Loud and exit 2
# either way; only the reason was wrong.
if [[ "$FROM_SET" -eq 1 && -z "$FROM" ]]; then
  echo "error: --from cannot be empty" >&2
  exit 2
fi
if [[ -z "$FROM" ]]; then
  echo "error: --from is required" >&2
  usage >&2
  exit 2
fi
if [[ -z "$TO" ]]; then
  echo "error: --to cannot be empty" >&2
  exit 2
fi
# An empty --branch fell through to the derived name and exited 0, because
# "not passed" and "passed empty" are the same empty string in BRANCH_OVERRIDE.
# --to catches its own empty form above only because it defaults to a non-empty
# value; --branch defaults to empty and cannot tell the two apart on its own.
# BRANCH_SET is what separates them, so an argument the operator typed is no
# longer discarded without a word on the way to a branch nobody asked for.
if [[ "$BRANCH_SET" -eq 1 && -z "$BRANCH_OVERRIDE" ]]; then
  echo "error: --branch cannot be empty" >&2
  exit 2
fi
if [[ "$FROM" == origin/* || "$TO" == origin/* ]]; then
  echo "error: branch names must not include 'origin/'" >&2
  exit 2
fi
if [[ "$FROM" == "$TO" ]]; then
  echo "error: --from and --to must differ" >&2
  exit 2
fi

# Reject anything that is not a single ref name, before it reaches the network.
#
# `git ls-remote` matches its arguments as globs and `*` is legal in a fetch
# refspec, so `--from 'release/*'` resolved, fetched wildcard-expanded, and left
# FROM_REF naming something that is not a commit. `git cherry` then fatalled and
# the `|| true` it carried at the time swallowed that into exit 0 with "Nothing
# to backport" — a tooling failure reported as a fact about the refs, which is
# the collapse this script's resolver exists to prevent. `fromBranch` is a
# free-text workflow_dispatch input, so the value is typeable.
#
# `git check-ref-format` is git's own grammar, so this rejects `*`, `?`, `[`,
# `~`, `^`, `:`, `..`, control characters and trailing `.lock` without a
# hand-written metacharacter list here that would drift from git's. Checking
# before the network also means a typo costs no round trip and writes no refs:
# the pre-fix run fetched `release/v1.0.0` into the operator's repo on its way
# to reporting nothing to do.
require_ref_name() {
  if ! git check-ref-format "refs/heads/$2" 2>/dev/null; then
    echo "error: $1 '$2' is not a valid git ref name" >&2
    exit 2
  fi
}

# --branch is checked against *both* grammars, because they are complements and
# not a chain. `--branch` mode was added here alone on the claim that it is a
# superset of `refs/heads/<name>`; it is not, and the one name the two disagree
# about in that direction is the collapse this guard exists to remove:
#
#   name              refs/heads/<name>   --branch
#   @{-1}                     1              0  -> prints `other`
#   HEAD, -x                  0            128
#   foo*, a..b, foo.lock      1            128
#
# `--branch` does not *validate* `@{-N}`, it *resolves* it — exit 0, printing a
# different name than the one it was given. `git checkout -b` at :405 is then
# handed the raw `@{-1}`, so the guard checked one string and the branch is cut
# from another: an argument the operator typed silently replaced by a name they
# did not. With the previous checkout gone it is quiet — "Creating branch @{-1}"
# followed by "Switched to a new branch 'tmpwork'", exit 0, cherry-picked onto a
# branch nobody asked for. With it still present it is git's bare exit 128.
#
# Running both is exactly right over the names that matter: `backport/v1.0.0`,
# `v1.0.0`, `a/b/c` and `my-branch` pass both, `@{-1}` is caught by the ref-name
# grammar, `HEAD` and `-x` by the branch grammar, and the metacharacter class by
# either. Ordering matters only for the message, so the ref-name check goes
# first — it is the one that needs no repository.
require_branch_name() {
  if ! git check-ref-format "refs/heads/$1" 2>/dev/null; then
    echo "error: --branch '$1' is not a valid git ref name" >&2
    exit 2
  fi
  if ! git check-ref-format --branch "$1" >/dev/null 2>&1; then
    echo "error: --branch '$1' is not a valid git branch name" >&2
    exit 2
  fi
}

# Must be in a git repo. Ahead of the checks above on purpose: the ref-name
# grammar needs no repository, so running it first told someone outside a repo
# their ref name was wrong, and fixing it only earned them the real blocker on
# the next run. `check-ref-format --branch` also resolves the `@{-N}` forms,
# which do need one. Ordering only — both errors are still reported, and both
# guards are still ahead of the network.
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "error: not inside a git repository" >&2
  exit 1
fi

require_ref_name --from "$FROM"
require_ref_name --to "$TO"
# --branch is the third ref-shaped argument and was the one left out. It is not
# a remote name, so it cannot mis-resolve — but `git checkout -b` rejects it at
# the end of the run, after the ls-remote, the fetch and the candidate list have
# already happened, which is exactly the round trip the paragraph above says a
# rejected argument should not cost.
if [[ -n "$BRANCH_OVERRIDE" ]]; then
  require_branch_name "$BRANCH_OVERRIDE"
fi

# Detect in-progress cherry-pick first — gives a more actionable error
# than the generic dirty-tree check, which also trips during a conflict.
if [[ -f "$(git rev-parse --git-dir)/CHERRY_PICK_HEAD" ]]; then
  echo "error: a cherry-pick is already in progress. Finish or abort it first:" >&2
  echo "       git cherry-pick --continue | --skip | --abort" >&2
  exit 1
fi

# Require clean working tree — cherry-picks onto a dirty tree are unsafe.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree has uncommitted changes. Commit or stash first." >&2
  exit 1
fi

echo "Fetching origin..."

# Ask the remote what every name is in one query, decide what to fetch, then
# fetch once. Resolving and fetching per name wrote the source ref into the
# operator's repo before anything had asked whether --to existed, so a --to that
# is a valid ref name but absent on origin — `--to mian`, and toBranch is a
# free-text workflow_dispatch input exactly as fromBranch is — still left a new
# remote-tracking ref or a new tag behind on the way to an error. That is the
# same defect one input class over from the glob this script's resolver was
# rewritten for. Nothing is written now until all three names have resolved. It
# also costs 2 round trips where the per-name form cost 4 for a branch --from
# and 5 for a tag, which over SSH with a hardware-token key is one touch each.
#
# No --exit-code: it reports "none of the patterns matched", which is not the
# question being asked of a multi-pattern query. Without it, "the remote
# answered and has no such ref" is exit 0 with the name simply absent from the
# output, and any non-zero is unambiguously "could not ask" — unreachable, or
# refused. Reporting that as a missing ref sends the operator after a ref that
# is fine, so that arm exits without adding a claim about the ref; git has
# already described the failure on stderr and a guess on top would mislead.
ls_out=""
if ! ls_out="$(git ls-remote origin \
      "refs/heads/$FROM" "refs/tags/$FROM" "refs/heads/$TO")"; then
  exit 1
fi

# Exact match on the ref name, not a substring: an annotated tag also emits a
# `refs/tags/<name>^{}` peel line, and `refs/heads/v1.0` must not answer for
# `refs/heads/v1.0.1`.
has_remote_ref() {
  awk -v want="$1" '$2 == want { hit = 1 } END { exit hit ? 0 : 1 }' <<<"$ls_out"
}

# Fully qualified, always. `origin/<name>` is resolved through gitrevisions
# precedence, which tries `refs/heads/<name>` before `refs/remotes/<name>` — so a
# stray local branch literally named `origin/release/v1.0.0`, the `checkout -b
# origin/…` typo, wins over the remote-tracking ref the fetch just wrote and the
# run backports it. `warning: refname ... is ambiguous` on stderr is the only
# signal, and the run exits 0 having cherry-picked the wrong commits onto a
# `backport/<x>` branch. The --to side is loud but late: `git cherry` accepts the
# ambiguity and prints a candidate list computed against the wrong ref, then
# `checkout -b` dies at 128 — after the round trip a bad input is not supposed to
# cost. The `origin/` guard at :142 does not reach either: it rejects the prefix
# in the *argument*, not a local branch of that name in the repo. The tag arm was
# already immune because it sets refs/tags/<name> outright.
#
# FROM_PRETTY/TO_PRETTY keep the headers reading as before; java-sdk splits them
# the same way.
FROM_REF=""
FROM_PRETTY=""
TO_REF=""
TO_PRETTY=""
refspecs=()

# --from accepts a branch or a tag. After a release, release.yml has deleted
# release/vX.Y.Z, so the tag is the only ref naming those commits. A branch wins
# on a name collision, which is what --help states.
#
# A bare-name refspec — `git fetch origin v1.0.0` — writes FETCH_HEAD and
# nothing else: no refs/tags entry, no remote-tracking ref. That is why looking
# the name up as `origin/<name>` afterwards could never see a tag: true of a
# clone made after the release, false for the maintainer this path exists for,
# someone whose last fetch predates the tag. The explicit destinations below
# materialise it.
if has_remote_ref "refs/heads/$FROM"; then
  FROM_REF="refs/remotes/origin/$FROM"
  FROM_PRETTY="origin/$FROM"
  refspecs+=("+refs/heads/$FROM:refs/remotes/origin/$FROM")
elif has_remote_ref "refs/tags/$FROM"; then
  # A re-cut tag (deleted on origin and re-pushed at a new commit) lands here.
  # `+` overwrites the stale local tag, which otherwise keeps pointing at the
  # superseded release and would backport the wrong commits.
  FROM_REF="refs/tags/$FROM"
  FROM_PRETTY="refs/tags/$FROM"
  refspecs+=("+refs/tags/$FROM:refs/tags/$FROM")
else
  echo "error: $FROM not found on origin as a branch or a tag" >&2
  exit 1
fi

# --to is branch-only, deliberately. A tag would resolve and `git checkout -b`
# would even work, but backport-fixes.yml opens a PR with `--base "$TO"`, which
# needs a branch that exists on the remote.
if has_remote_ref "refs/heads/$TO"; then
  TO_REF="refs/remotes/origin/$TO"
  TO_PRETTY="origin/$TO"
  refspecs+=("+refs/heads/$TO:refs/remotes/origin/$TO")
else
  echo "error: $TO not found on origin as a branch (--to must be a branch)" >&2
  exit 1
fi

# Snapshot every destination the fetch is about to write, so the one resolve that
# cannot happen before the fetch can put the repository back exactly as it was.
#
# A tag on a non-commit is that resolve: ls-remote emits no `^{}` peel line for a
# lightweight tag either way, so the object type is unknowable until it is local,
# and the `^{commit}` check below necessarily runs after a write.
#
# Snapshotting values rather than tracking "did this ref exist" is what makes the
# rollback cover both arms. The previous flag covered neither: it skipped the tag
# when one was already present, on the grounds that the operator's tag should not
# be deleted — but the `+` on the refspec has already overwritten that tag's
# value by the time the check runs, so there was nothing left to protect and the
# operator was left with their tag pointing at a blob. And it never looked at
# `refs/remotes/origin/<to>` at all, which the same fetch also writes: with a
# --to the clone does not already track, a failed resolve left it behind.
pre_fetch_values=()
for spec in "${refspecs[@]}"; do
  dest="${spec#*:}"
  pre_fetch_values+=("$dest $(git rev-parse --verify --quiet "$dest" || true)")
done

# Undo what this run created; do not undo what the fetch legitimately learned.
#
# Deleting a destination that did not exist beforehand is the half that answers
# the original finding: the complaint is that a failed run *creates* refs on its
# way to an error, and a ref that was not there is junk left behind.
#
# Restoring a prior *value* is narrower, and the boundary is "this run created
# it", not "this namespace belongs to git". Both arms follow from the first
# sentence rather than from who owns the namespace:
#
#   created by this run  -> delete it; it is the junk the finding is about,
#                           whether or not origin really has that ref
#   existed before       -> restore it, except under `refs/remotes/*`
#
# The exception is what a restore would cost there. `refs/tags/<name>` is the
# operator's and the `+` clobbered it, so putting the old object back is a
# repair. A pre-existing `refs/remotes/origin/<to>` was only ever moved *forward*
# by the fetch, so reverting it moves the operator's repository backwards —
# `git status` on a branch tracking it then reports against a stale tip until the
# next fetch, with the objects already in the store and nothing in the output
# saying so. Undoing a write this run did not make is not what "nothing is
# written until every name has resolved" is asking for.
#
# Best-effort: this runs on a path that is already failing, and a ref that cannot
# be put back must not replace the error the operator needs to read.
rollback_fetch() {
  local entry dest old
  for entry in "${pre_fetch_values[@]}"; do
    dest="${entry%% *}"
    old="${entry#* }"
    if [[ -z "$old" ]]; then
      git update-ref -d "$dest" >/dev/null 2>&1 || true
    elif [[ "$dest" != refs/remotes/* ]]; then
      git update-ref "$dest" "$old" >/dev/null 2>&1 || true
    fi
  done
}

# Every refspec carries a leading `+` — the source branch, the source tag and
# the target branch alike. The bare-name form they replaced still got its
# remote-tracking update through `remote.origin.fetch`, whose refspec is forced.
# Writing the destinations out without the `+` silently drops that force, and a
# ref whose history was rewritten — a force-pushed release branch, a re-cut tag,
# a target branch that took a squashed or amended merge — stops fast-forwarding
# and fails a backport that used to work.
#
# Without -q on purpose: -q suppresses the per-ref status table, which is where
# `! [rejected]` is written, so a fetch that fails after ls-remote said the ref
# was there would exit with no explanation at all.
#
# --no-tags because --help promises "those two refs — not the whole remote", and
# tag auto-following breaks that promise on every run, successful ones included:
# fetching a release branch drags in every tag pointing at a commit it
# downloads. --no-tags disables auto-following only, so the explicit
# `refs/tags/<name>` refspec above still fetches exactly its one tag.
#
# No `|| exit 1`. Each of the three fetches carried one, and it did work then:
# they ran inside functions called as `if ! fetch_source_ref ...`, and `set -e`
# is suspended for the whole body of a command in a condition, so a failed fetch
# fell through to the arm's `return 1` and the script reported a ref origin had
# just confirmed as missing. One unconditional fetch at top level is not in that
# position — `set -e` ends the run on it — and the guard became a line no
# mutation could redden. The three t_failed_fetch_* cases pin the behaviour
# directly instead.
git fetch --no-tags origin "${refspecs[@]}"

# A tag can point at any object, and a tag naming a blob has a ref name git's
# grammar accepts, so `check-ref-format` cannot see it and ls-remote reports it
# like any other ref. It arrives here fully resolved and `git cherry` is the
# first thing to notice, which makes the run blame the comparison for an input
# problem it diagnosed correctly. Name the cause instead.
#
# --from only: --to is branch-only and git refuses to point refs/heads at a
# non-commit, so the same check on TO_REF could not fail.
#
# This is the one path that can reach here having written refs, so it is also the
# one that has to undo what it wrote — "nothing is written until every name has
# resolved" is stated without qualification above the resolver.
#
# rollback_fetch deletes every destination that did not exist before the fetch,
# and restores the prior object only outside `refs/remotes/*`. An updated
# remote-tracking ref is deliberately left where the fetch put it; see the
# reasoning above rollback_fetch for why that is not a gap.
if ! git rev-parse --verify --quiet "$FROM_REF^{commit}" >/dev/null; then
  echo "error: $FROM resolved to $FROM_PRETTY, which does not name a commit" >&2
  rollback_fetch
  exit 1
fi

# `git cherry -v <upstream> <head>` prints one line per commit:
#   + <sha> <subject>   -> not on upstream (candidate for backport)
#   - <sha> <subject>   -> already on upstream via patch-ID match
#
# Not `|| true`. git-cherry documents no exit status at all — its man page has
# no Exit Status section — so there is no documented non-zero to tolerate, and
# swallowing every one of them is what turned a `fatal: unknown commit` into
# "Nothing to backport." and exit 0. An empty candidate list is expressed by
# empty output, not by a non-zero exit.
#
# The input-level paths that used to reach this are now intercepted upstream —
# a glob by require_ref_name, a tag on a blob by the `^{commit}` check above —
# so what is left is object-level: an object missing from the local store that
# the revision walk needs and the fetch does not resupply, because the ref that
# names it is already up to date. t_cherry_failure_is_named builds exactly that.
if ! cherry_out="$(git cherry -v "$TO_REF" "$FROM_REF")"; then
  echo "error: git cherry could not compare $FROM_PRETTY against $TO_PRETTY" >&2
  exit 1
fi

all_candidates="$(echo "$cherry_out" | awk '$1 == "+" { sub(/^\+ /, ""); print }')"
already_pretty="$(echo  "$cherry_out" | awk '$1 == "-" { sub(/^- /, "");  print }')"

if [[ -n "$NO_FILTER" ]]; then
  candidates_pretty="$all_candidates"
  filtered_pretty=""
else
  filtered_pretty="$(echo "$all_candidates" | grep -E '^[0-9a-f]+ (release|release-prep):' || true)"
  candidates_pretty="$(echo "$all_candidates" | grep -Ev '^[0-9a-f]+ (release|release-prep):' || true)"
fi

shas="$(echo "$candidates_pretty" | awk 'NF { print $1 }')"

n_candidates=0
[[ -n "$candidates_pretty" ]] && n_candidates=$(echo "$candidates_pretty" | wc -l | tr -d ' ')
n_already=0
[[ -n "$already_pretty" ]] && n_already=$(echo "$already_pretty" | wc -l | tr -d ' ')
n_filtered=0
[[ -n "$filtered_pretty" ]] && n_filtered=$(echo "$filtered_pretty" | wc -l | tr -d ' ')

echo
echo "=== Commits on $FROM_PRETTY not yet on $TO_PRETTY ($n_candidates) ==="
if [[ "$n_candidates" -gt 0 ]]; then
  echo "$candidates_pretty"
else
  echo "(none)"
fi

if [[ "$n_already" -gt 0 ]]; then
  echo
  echo "=== Already on $TO_PRETTY, excluded ($n_already) ==="
  echo "$already_pretty"
fi

if [[ "$n_filtered" -gt 0 ]]; then
  echo
  echo "=== Skipped (version-bump commits; pass --no-filter to include) ($n_filtered) ==="
  echo "$filtered_pretty"
fi

if [[ "$n_candidates" -eq 0 ]]; then
  echo
  echo "Nothing to backport."
  exit 0
fi

if [[ -n "$BRANCH_OVERRIDE" ]]; then
  branch="$BRANCH_OVERRIDE"
elif [[ "$FROM" =~ ^(release|hotfix)/v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  branch="backport/v${BASH_REMATCH[2]}"
else
  flat="$(echo "$FROM" | sed -E 's|/|-|g; s/[^a-zA-Z0-9._-]+/-/g')"
  branch="backport/${flat}"
fi

if git show-ref --verify --quiet "refs/heads/$branch"; then
  echo "error: local branch '$branch' already exists." >&2
  echo "       Delete it (git branch -D $branch) or pass --branch <other-name>." >&2
  exit 1
fi

echo
echo "Creating branch $branch off $TO_PRETTY..."
git checkout -b "$branch" "$TO_REF"

echo
echo "Cherry-picking $n_candidates commit(s) with -x, oldest first..."
echo "If git stops on a conflict:"
echo "  - Resolve, 'git add <files>', then 'git cherry-pick --continue'."
echo "  - To drop the conflicting commit: 'git cherry-pick --skip'."
echo "  - To bail out entirely:           'git cherry-pick --abort'."
echo

# shellcheck disable=SC2086 # intentional word-split: $shas is a hex-only list
exec git cherry-pick -x $shas

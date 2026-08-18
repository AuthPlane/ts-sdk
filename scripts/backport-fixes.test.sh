#!/usr/bin/env bash
set -euo pipefail

# Tests for backport-fixes.sh argument handling and ref resolution.
#
# The script has no other test, and the case it regressed on is not one a reader
# would guess: --from accepts a branch OR a tag, and only the branch form has a
# remote-tracking ref. After a release, release.yml deletes the release branch,
# so the tag is the only ref naming those commits — the tag form is the one the
# workflow's input description and the release guide both tell you to use.
#
# Each case builds a throwaway origin + clone in a temp dir, so nothing here
# touches the real repository or the network.
#
# Run: scripts/backport-fixes.test.sh

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/backport-fixes.sh"
failures=0

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n     %s\n' "$1" "$2"; failures=$((failures + 1)); }

# Builds: origin with `main`, a v1.0.0 tag, and one commit after the tag that is
# only reachable from the tag's branch — the shape of a fix landed on a release
# branch at step 3 of the release flow.
make_fixture() {
  local root="$1"
  # -b main explicitly: the default branch name comes from init.defaultBranch,
  # which differs between a developer machine and a CI runner. Without it the
  # fixture builds `master` somewhere and every checkout of `main` fails.
  git init -q -b main "$root/origin"
  git -C "$root/origin" config user.email t@example.com
  git -C "$root/origin" config user.name "Test"
  echo base > "$root/origin/f.txt"
  git -C "$root/origin" add -A
  git -C "$root/origin" commit -qm "base"

  # Clone before the tag exists. A clone made afterwards fetches every tag, which
  # leaves refs/tags/v1.0.0 populated locally and hides whether the script's own
  # fetch materialises it — the exact blind spot that let a broken resolver pass.
  # The real scenario is a maintainer who last fetched before the release.
  git clone -q "$root/origin" "$root/clone"

  git -C "$root/origin" checkout -q -b release/v1.0.0
  echo fix > "$root/origin/f.txt"
  git -C "$root/origin" commit -qam "fix: something landed on the release branch"
  # Annotated, matching release.yml's `git tag -a`. A lightweight tag resolves
  # the same way here, but the fixture should produce what the flow it models
  # produces.
  git -C "$root/origin" tag -a v1.0.0 -m "v1.0.0"
  git -C "$root/origin" checkout -q main
  git -C "$root/clone" config user.email t@example.com
  git -C "$root/clone" config user.name "Test"
}

# --- a branch as --from keeps working -----------------------------------------
t_branch() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "landed on the release branch"; then
      pass "a branch as --from cherry-picks its commits"
    else
      fail "a branch as --from cherry-picks its commits" "branch created but the commit is missing"
    fi
  else
    fail "a branch as --from cherry-picks its commits" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a tag as --from: the regression ------------------------------------------
# Before the fix this exited 1 with "origin/v1.0.0 not found on remote", because
# origin/<name> resolves only against refs/remotes and a tag has none.
t_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "landed on the release branch"; then
      pass "a tag as --from cherry-picks its commits"
    else
      fail "a tag as --from cherry-picks its commits" "branch created but the commit is missing"
    fi
  else
    fail "a tag as --from cherry-picks its commits" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- an unknown ref fails, and leaves nothing behind ---------------------------
# It fails at the resolver, which is what the assertion below pins. The single
# multi-pattern `ls-remote` passes no --exit-code, so a name the remote does not
# have comes back as exit 0 with that name simply absent from the output; the
# script finds no match, prints its own message and stops before any fetch. What
# matters is the contract: non-zero, and no branch created.
t_unknown() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from does-not-exist --to main 2>&1)"; then
    fail "an unknown --from fails" "script exited zero"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "an unknown --from fails" "it created a backport branch anyway"
  elif ! grep -q "as a branch or a tag" <<<"$out"; then
    fail "an unknown --from fails" "reached the fetch, not the resolver: ${out##*$'\n'}"
  else
    pass "an unknown --from fails at the resolver, creating no branch"
  fi
}

# --- --to is branch-only ------------------------------------------------------
# A tag resolves and `git checkout -b` would even work, but the workflow opens a
# PR with `--base "$TO"`, which needs a branch on the remote. Rejecting it here
# beats failing after the cherry-picks have run.
t_to_rejects_a_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from main --to v1.0.0 2>&1)"; then
    fail "--to rejects a tag" "script exited zero"
  elif grep -q "must be a branch" <<<"$out"; then
    pass "--to rejects a tag, naming the reason"
  else
    fail "--to rejects a tag" "unexpected message: ${out##*$'\n'}"
  fi
}

# --- a force-pushed source branch still backports ------------------------------
# What the `+` on the refspecs is for. Without it the fetch is a non-fast-forward
# rejection, and the resolver reported that as "not found on origin as a branch
# or a tag" — sending the maintainer after a ref that is present and current.
# Amending a release commit during release prep is routine, and the bare-name
# form this replaced handled it, so losing it was a regression against main.
t_force_pushed_source() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # Seed the remote-tracking ref at the pre-amend commit: the state of a
  # maintainer who last fetched before the force-push. Without this the clone
  # has no origin/release/v1.0.0 at all and any fetch is trivially a
  # fast-forward, which is how the missing `+` went unnoticed.
  git -C "$root/clone" fetch -q origin \
    '+refs/heads/release/v1.0.0:refs/remotes/origin/release/v1.0.0'

  git -C "$root/origin" checkout -q release/v1.0.0
  echo amended > "$root/origin/f.txt"
  git -C "$root/origin" commit -q --amend -am "fix: something landed on the release branch (amended)"
  git -C "$root/origin" checkout -q main

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "(amended)"; then
      pass "a force-pushed source branch backports the rewritten commit"
    else
      fail "a force-pushed source branch backports the rewritten commit" \
        "it backported the pre-amend commit"
    fi
  else
    fail "a force-pushed source branch backports the rewritten commit" \
      "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a branch wins when a branch and a tag share the name ----------------------
# The order the resolver tests `refs/heads/$FROM` before `refs/tags/$FROM` in
# the ls-remote output decides this, and --help now states it, so it needs a
# case: a repo that tags v1.0.0 and later cuts a branch of the same name would
# otherwise silently change which commits get backported.
t_branch_beats_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # A branch literally named v1.0.0, carrying a commit the tag does not.
  git -C "$root/origin" checkout -q -b v1.0.0 main
  echo from-branch > "$root/origin/f.txt"
  git -C "$root/origin" commit -qam "fix: reached through the branch"
  git -C "$root/origin" checkout -q main

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --oneline main..HEAD | grep -q "reached through the branch"; then
      pass "a branch wins over a tag of the same name"
    else
      fail "a branch wins over a tag of the same name" "it resolved the tag instead"
    fi
  else
    fail "a branch wins over a tag of the same name" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a re-cut tag backports the new commit -------------------------------------
# What the `+` on the *tag* refspec is for. t_force_pushed_source covers the
# branch arm only, so without this case the `+` can be deleted from the tag arm
# and the suite still passes. Re-cutting a tag — deleting it on origin and
# re-pushing it at a new commit — is what happens when a release is pulled and
# redone, and it is the one time the local tag and origin's disagree.
#
# Without the `+` the fetch is rejected (`would clobber existing tag`), and the
# fetch runs unguarded at top level under `set -e`, so this fails on the exit
# code rather than on a wrong backport.
t_recut_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # The maintainer fetched at release time, so the clone holds v1.0.0 at the
  # original commit. Without this the local tag is simply absent, any fetch of
  # it is trivially new, and a missing `+` would go unnoticed — the same trap
  # t_force_pushed_source seeds around on the branch arm.
  git -C "$root/clone" fetch -q origin '+refs/tags/v1.0.0:refs/tags/v1.0.0'

  git -C "$root/origin" checkout -q release/v1.0.0
  echo recut > "$root/origin/f.txt"
  git -C "$root/origin" commit -qam "fix: shipped in the re-cut release"
  git -C "$root/origin" tag -d v1.0.0 >/dev/null
  git -C "$root/origin" tag -a v1.0.0 -m "v1.0.0"
  git -C "$root/origin" checkout -q main

  local out subjects
  if out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)"; then
    # Not `git log | grep -q`: this is the first case whose log is more than one
    # line with the match on the first of them, so grep -q exits before git has
    # finished writing, git takes SIGPIPE, and `set -o pipefail` reports the
    # pipeline as failed. Collect first, match second.
    subjects="$(git -C "$root/clone" log --format=%s main..HEAD)"
    if grep -q "re-cut release" <<<"$subjects"; then
      pass "a re-cut tag backports the commit it now names"
    else
      fail "a re-cut tag backports the commit it now names" \
        "it backported the superseded tag's commits"
    fi
  else
    fail "a re-cut tag backports the commit it now names" \
      "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- a rewritten target branch still backports ---------------------------------
# The third `+`, and the one neither case above reached: t_force_pushed_source
# pins the source branch refspec and t_recut_tag the source tag, so the `+` on
# the target refspec could be deleted with the suite fully green. Same failure
# mode as t_force_pushed_source, mirrored onto --to: origin/main whose history
# was rewritten — a squashed or amended merge, a force-push after a bad landing
# — stops fast-forwarding, the fetch is a non-fast-forward rejection and
# `set -e` ends the run on it.
t_force_pushed_target() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  git -C "$root/origin" checkout -q main
  echo target > "$root/origin/g.txt"
  git -C "$root/origin" add -A
  git -C "$root/origin" commit -qm "chore: landed on main"

  # Seed refs/remotes/origin/main at the pre-rewrite commit: the state of a
  # maintainer who last fetched before the force-push. Without this the clone's
  # origin/main is simply an ancestor of the rewritten history and the fetch is
  # trivially a fast-forward, which is how the missing `+` went unnoticed — the
  # same trap t_force_pushed_source seeds around on the source arm.
  git -C "$root/clone" fetch -q origin '+refs/heads/main:refs/remotes/origin/main'

  echo rewritten > "$root/origin/g.txt"
  git -C "$root/origin" commit -q --amend -am "chore: landed on main (amended)"

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)"; then
    if git -C "$root/clone" log --format=%s origin/main -1 | grep -q "(amended)"; then
      pass "a rewritten target branch still backports"
    else
      fail "a rewritten target branch still backports" \
        "origin/main was not updated to the rewritten commit"
    fi
  else
    fail "a rewritten target branch still backports" \
      "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- the fetches stay verbose --------------------------------------------------
# A source-level assertion, deliberately. `-q` suppresses the per-ref status
# table, which is where `! [rejected]` is written — and with the `+` in place
# nothing can produce a rejection, so no fixture reaches the case while the
# script is otherwise correct. Measured on a stale local tag against a re-cut
# origin tag, with the `+` removed:
#
#   without -q:  ! [rejected]  v1.0.0 -> v1.0.0  (would clobber existing tag)  rc 1
#   with    -q:  (nothing on either stream)                                    rc 1
#
# The run then ends on `set -e` with no explanation at all, which is what the
# comment above the resolver says must not happen. The t_failed_fetch_* cases do
# not catch it either: their `error:` lines come from the ref backend rather
# than the status table, and survive -q.
#
# What is scanned is the invocation, not the line. Matching any line carrying
# both `git fetch` and `-q` was wrong in both directions: the prose above the
# resolver names `git fetch origin v1.0.0` and reasons about `-q` at length, so
# rewording a comment reddened the suite, while a real `-q` on a continuation
# line was invisible to it. fetch_invocations skips comment lines, joins
# backslash continuations, and matches the command word wherever it can appear —
# not only at the start of a line. The previous anchor was `^[ \t]*git[ \t]+fetch`,
# so `if ! git fetch ...`, `git -c foo=bar fetch ...` and `exec git fetch ...`
# were all invisible to it. Safe only because there is exactly one fetch today
# and the empty-result guard below catches a total miss; it would have gone
# quiet the moment a second one arrived in a wrapped form.
fetch_invocations() {
  awk '
    /^[ \t]*#/ { next }
    {
      if (cont) { sub(/\\[ \t]*$/, "", inv); inv = inv " " $0 }
      else if ($0 ~ /(^|[ \t;&|(!])git([ \t]+-[^ \t]+([ \t]+[^ \t]+)?)*[ \t]+fetch([ \t]|$)/) { inv = $0; start = NR }
      else { next }
      cont = ($0 ~ /\\[ \t]*$/)
      if (cont) next
      printf "%d:%s\n", start, inv
      inv = ""
    }
  ' "$SCRIPT"
}

t_fetches_stay_verbose() {
  local invocations offenders
  invocations="$(fetch_invocations)"
  if [[ -z "$invocations" ]]; then
    fail "the fetches run without -q" "found no git fetch invocation to scan"
    return
  fi
  # Clustered short options too: -q is the flag, but so is the q in -nq.
  offenders="$(grep -E '(^|[[:space:]])(--quiet|-[a-zA-Z0-9]*q[a-zA-Z0-9]*)([[:space:]]|$)' \
    <<<"$invocations" || true)"
  if [[ -n "$offenders" ]]; then
    fail "the fetches run without -q" "${offenders//$'\n'/; }"
  else
    pass "the fetches run without -q"
  fi
}

# --- a failed fetch is not a missing ref ---------------------------------------
# A fetch can still fail after ls-remote has confirmed the ref, and the run must
# end on git's own explanation rather than on a claim about the refs — reporting
# a tooling failure as a missing ref sends the operator after a ref that is
# present and current.
#
# One case per refspec rather than per fetch: resolution happens in one ls-remote
# and all of it is fetched in a single call, but three destination paths can fail
# independently and each is a state a real clone reaches. Covering the source
# branch alone would leave the tag destination and the target destination
# unexercised.
#
# t_force_pushed_source is a fetch that must succeed and t_unreachable_remote
# never reaches a fetch, so neither reaches this ground. Every fixture below
# fails the fetch the same way, on a local ref-lock conflict: a ref already
# occupies part of the destination path, so the destination cannot be created.
# That is the one failure mode available to all three refspecs without a
# network.
#
# The assertions pin the contract, not git's wording: non-zero, the script's own
# "not found on origin" claim absent, *something* on stderr, and no branch
# created. Absence alone would sign off on a script that failed in silence and
# an actionable message is the whole point, so the presence half is keyed on
# git's `error:` / `fatal:` prefix — a convention across every git command
# rather than a wording that a git upgrade may reword.
assert_failed_fetch_is_not_a_missing_ref() {
  local label="$1" root="$2" from="$3" to="$4"

  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from "$from" --to "$to" 2>"$root/stderr")" || rc=$?
  local err; err="$(cat "$root/stderr")"
  if [[ "$rc" -eq 0 ]]; then
    fail "$label" "script exited zero"
  elif grep -q "not found on origin" <<<"$out"$'\n'"$err"; then
    fail "$label" "the fetch failure was reported as a missing ref"
  elif ! grep -qE '^(error|fatal):' <<<"$err"; then
    fail "$label" "it failed without writing an explanation to stderr"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "$label" "it created a backport branch anyway"
  else
    pass "$label"
  fi
}

# The source branch arm. origin has release/v1.0.0 and will happily say so, but
# refs/remotes/origin/release/v1.0.0 cannot be created because
# refs/remotes/origin/release already exists as a ref — the state of a clone
# that once tracked a branch called `release`.
t_failed_fetch_source_branch() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local base; base="$(git -C "$root/clone" rev-parse main)"
  git -C "$root/clone" update-ref refs/remotes/origin/release "$base"

  assert_failed_fetch_is_not_a_missing_ref \
    "a failed fetch of the source branch is not a missing ref" "$root" release/v1.0.0 main
}

# The source tag arm — the same conflict one namespace over, where a ref under
# refs/tags/v1.0.0/ blocks refs/tags/v1.0.0. Reached because origin has the tag
# and no branch of that name, so resolution falls through to the tag arm.
# t_recut_tag pins the `+` on this refspec but not the fetch guard: with the `+`
# in place that fetch succeeds, so the guard never runs there.
t_failed_fetch_source_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local base; base="$(git -C "$root/clone" rev-parse main)"
  git -C "$root/clone" update-ref refs/tags/v1.0.0/superseded "$base"

  assert_failed_fetch_is_not_a_missing_ref \
    "a failed fetch of the source tag is not a missing ref" "$root" v1.0.0 main
}

# The target arm. The source-branch case above never reaches it — its --to is
# `main`, which fetches cleanly — so the collision has to be moved onto the
# target's own destination path: origin grows stable/1.x, the clone holds
# refs/remotes/origin/stable as a ref, and refs/remotes/origin/stable/1.x
# cannot be created.
t_failed_fetch_target_branch() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  git -C "$root/origin" branch stable/1.x main
  local base; base="$(git -C "$root/clone" rev-parse main)"
  git -C "$root/clone" update-ref refs/remotes/origin/stable "$base"

  assert_failed_fetch_is_not_a_missing_ref \
    "a failed fetch of the target branch is not a missing ref" "$root" release/v1.0.0 stable/1.x
}

# --- an unreachable remote is not a missing ref --------------------------------
# Without --exit-code, `git ls-remote` answers 0 for "asked, and the remote has
# no such ref" — the name is just absent from the output — and non-zero only for
# "could not ask": unreachable, or refused. That split is what separates the two,
# and without a case a regression in it is invisible: the suite passes while a
# network failure is reported as a missing ref, sending the operator after a ref
# that is fine.
#
# Same assertion shape as the case above, and for the same reasons: the wording
# of `fatal: Could not read from remote repository.` is git's to change, so what
# is pinned is that the script adds no claim about the ref on top of it — and
# that git's own explanation did reach the operator. Silencing ls-remote's
# stderr would otherwise leave the 128 arm exiting 1 with nothing printed, and
# the absence assertion alone would call that a pass.
t_unreachable_remote() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"
  git -C "$root/clone" remote set-url origin /nonexistent

  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>"$root/stderr")" || rc=$?
  local err; err="$(cat "$root/stderr")"
  if [[ "$rc" -eq 0 ]]; then
    fail "an unreachable remote is not reported as a missing ref" "script exited zero"
  elif grep -q "not found on origin" <<<"$out"$'\n'"$err"; then
    fail "an unreachable remote is not reported as a missing ref" \
         "the network failure was reported as a missing ref"
  elif ! grep -qE '^(error|fatal):' <<<"$err"; then
    fail "an unreachable remote is not reported as a missing ref" \
         "it failed without writing an explanation to stderr"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "an unreachable remote is not reported as a missing ref" "it created a backport branch anyway"
  else
    pass "an unreachable remote is not reported as a missing ref"
  fi
}

# --- a glob as --from is rejected before it reaches the network ----------------
# `ls-remote` matches its argument as a glob and `*` is legal in a fetch refspec,
# so this resolved, fetched wildcard-expanded, and left a FROM_REF that is not a
# commit — `git cherry` fatalled and `|| true` swallowed it into exit 0 with
# "Nothing to backport". A tooling failure reported as a fact about the refs.
t_glob_from() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from 'release/*' --to main 2>&1)"; then
    fail "a glob as --from is rejected" "script exited zero: ${out##*$'\n'}"
  elif grep -q "Nothing to backport" <<<"$out"; then
    fail "a glob as --from is rejected" "reported nothing to backport instead of rejecting the input"
  elif [[ -n "$(git -C "$root/clone" for-each-ref --format='%(refname)' 'refs/remotes/origin/release/*')" ]]; then
    fail "a glob as --from is rejected" "it fetched wildcard-expanded refs before failing"
  else
    pass "a glob as --from is rejected"
  fi
}

# --- a glob as --to is rejected too --------------------------------------------
# Same defect on the other argument: `--to 'mai*'` fetched refs/heads/mai* into
# refs/remotes/origin/mai*, then compared against a ref of that name that does
# not exist, and again ended at "Nothing to backport." with exit 0.
#
# The last assertion pins the ordering, not just the outcome. Both arguments are
# validated up front, before the resolver runs, so a rejected --to must leave the
# repository untouched — including refs/remotes/origin/release/v1.0.0, which a
# validation moved below the fetch would have written on the way to the same
# error.
t_glob_to() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local out
  if out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to 'mai*' 2>&1)"; then
    fail "a glob as --to is rejected" "script exited zero: ${out##*$'\n'}"
  elif grep -q "Nothing to backport" <<<"$out"; then
    fail "a glob as --to is rejected" "reported nothing to backport instead of rejecting the input"
  elif git -C "$root/clone" show-ref --verify --quiet refs/remotes/origin/release/v1.0.0; then
    fail "a glob as --to is rejected" "--from was fetched before --to was validated"
  else
    pass "a glob as --to is rejected"
  fi
}

# --- a valid-but-absent --to writes nothing ------------------------------------
# The half of the description this PR leads with that survived one input class
# over. t_glob_to pins the ordering only for a grammatically invalid --to, which
# require_ref_name catches before resolution runs at all — so it passed against a
# script that fetched --from for every *valid* --to origin does not have.
# `--to mian` is the reachable form: toBranch is a free-text workflow_dispatch
# input exactly as fromBranch is.
#
# Both source shapes, because they write to different namespaces and the branch
# arm alone would leave the tag destination unpinned: a branch --from left
# refs/remotes/origin/release/v1.0.0 behind, a tag --from refs/tags/v1.0.0.
t_bad_to_writes_nothing() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local out shape
  for shape in release/v1.0.0 v1.0.0; do
    if out="$(cd "$root/clone" && "$SCRIPT" --from "$shape" --to no-such-branch 2>&1)"; then
      fail "a bad --to writes nothing" "--from $shape exited zero"
      return
    elif ! grep -q "must be a branch" <<<"$out"; then
      fail "a bad --to writes nothing" "--from $shape: unexpected message: ${out##*$'\n'}"
      return
    elif [[ -n "$(git -C "$root/clone" for-each-ref --format='%(refname)' 'refs/tags/*')" ]]; then
      fail "a bad --to writes nothing" "--from $shape fetched a tag before rejecting --to"
      return
    elif [[ -n "$(git -C "$root/clone" for-each-ref --format='%(refname)' 'refs/remotes/origin/release/*')" ]]; then
      fail "a bad --to writes nothing" "--from $shape fetched the source branch before rejecting --to"
      return
    fi
  done
  pass "a --to that is absent on origin leaves no fetched refs behind"
}

# --- --branch is validated with the other two ----------------------------------
# The third ref-shaped argument, and the one require_ref_name did not guard.
# `git checkout -b` rejects it too, but only at the end of the run: the refs
# assertion is half the point of the case, because an invalid --branch used to
# cost an ls-remote, the fetch and a printed candidate list before anything
# noticed — the round trip the comment above require_ref_name says a rejected
# argument must not cost.
#
# `-x` and `HEAD` are the other half, and they are why `check-ref-format --branch`
# was added: both are names the ref-name grammar accepts and `git checkout -b`
# does not, so the ref-name check paid the whole round trip and then died at
# git's exit 128 anyway — byte for byte the transcript the guard was added to
# remove.
#
# The other direction — `@{-1}`, which `--branch` mode accepts and the ref-name
# grammar rejects — is deliberately *not* in this loop. It needs a previous
# checkout in the reflog to resolve at all, and this fixture has none, so the
# pre-fix script rejects it here for the wrong reason and the assertion would be
# vacuous. It has its own case with the fixture it needs:
# t_branch_override_previous_checkout.
t_branch_override_is_validated() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local name out rc
  for name in 'foo*' '-x' 'HEAD'; do
    rc=0
    out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main --branch "$name" 2>&1)" || rc=$?
    if [[ "$rc" -ne 2 ]]; then
      fail "an invalid --branch is rejected" "--branch '$name' exited $rc, want 2"
      return
    elif ! grep -q -- "--branch" <<<"$out"; then
      fail "an invalid --branch is rejected" \
        "--branch '$name': the message does not name --branch: ${out##*$'\n'}"
      return
    elif git -C "$root/clone" show-ref --verify --quiet refs/remotes/origin/release/v1.0.0; then
      fail "an invalid --branch is rejected" "--branch '$name' fetched before validating it"
      return
    fi
  done
  pass "an invalid --branch is rejected before anything is fetched"
}

# --- --branch '@{-1}' with the previous checkout gone --------------------------
# The quiet half, and the reason the case above is not enough on its own: the
# two failure modes are different events and only one of them is loud.
#
# With the previous branch still present, `checkout -b '@{-1}'` hits "a branch
# named 'scratch' already exists" and exits 128 — bad, but it stops. With that
# branch deleted, `@{-1}` still resolves through the reflog to a name that no
# longer exists, `show-ref --verify` finds nothing to object to, and the run
# creates it, switches to it and cherry-picks onto it at exit 0:
#
#   Creating branch @{-1} off origin/main...
#   Switched to a new branch 'scratch'
#
# An argument the operator typed, silently replaced by a name they did not — the
# same family as `--branch ''`, one input class over, and quieter, because there
# BRANCH_SET at least ended the run.
#
# Seeding the reflog is the whole fixture: without a previous checkout `@{-1}`
# has nothing to resolve to and the case passes for the wrong reason.
t_branch_override_previous_checkout() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # A previous checkout, then deleted — so @{-1} resolves and the name is free.
  git -C "$root/clone" checkout -q -b scratch
  git -C "$root/clone" checkout -q main
  git -C "$root/clone" branch -q -D scratch

  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main --branch '@{-1}' 2>&1)" || rc=$?

  if [[ "$rc" -ne 2 ]]; then
    fail "--branch '@{-1}' is rejected, not resolved" "exited $rc, want 2"
  elif ! grep -q -- "--branch" <<<"$out"; then
    fail "--branch '@{-1}' is rejected, not resolved" \
      "the message does not name --branch: ${out##*$'\n'}"
  elif git -C "$root/clone" show-ref --verify --quiet refs/heads/scratch; then
    fail "--branch '@{-1}' is rejected, not resolved" \
      "the run created 'scratch' — the name @{-1} resolves to, not the one passed"
  elif [[ "$(git -C "$root/clone" branch --show-current)" != "main" ]]; then
    fail "--branch '@{-1}' is rejected, not resolved" \
      "the run switched branches: now on $(git -C "$root/clone" branch --show-current)"
  elif git -C "$root/clone" show-ref --verify --quiet refs/remotes/origin/release/v1.0.0; then
    fail "--branch '@{-1}' is rejected, not resolved" "fetched before validating it"
  else
    pass "--branch '@{-1}' is rejected, not resolved to the previous checkout"
  fi
}

# --- a failed resolve restores a tag it overwrote ------------------------------
# The other half of the rollback, and the one the "did this ref exist" flag it
# replaced could not cover at all. The `+` on the tag refspec exists to overwrite
# a stale local tag, so by the time the `^{commit}` check runs the operator's own
# tag has already been destroyed — skipping the cleanup "because the tag was
# already there" protected a value that no longer existed, and left them with
# their tag pointing at a blob.
#
# Snapshotting values before the fetch is what covers both directions: delete
# what was not there, restore what was — the restore arm outside `refs/remotes/*`
# only, which is the distinction t_rollback_keeps_what_the_fetch_learned pins.
t_failed_resolve_restores_a_clobbered_tag() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # origin's v2.0.0 points at a blob; the clone's points at a commit.
  local blob; blob="$(git -C "$root/origin" rev-parse HEAD:f.txt)"
  git -C "$root/origin" tag v2.0.0 "$blob"
  git -C "$root/clone" tag v2.0.0 main

  local before; before="$(git -C "$root/clone" rev-parse refs/tags/v2.0.0)"
  local rc=0
  (cd "$root/clone" && "$SCRIPT" --from v2.0.0 --to main >/dev/null 2>&1) || rc=$?
  local after; after="$(git -C "$root/clone" rev-parse refs/tags/v2.0.0 2>/dev/null || echo MISSING)"

  if [[ "$rc" -eq 0 ]]; then
    fail "a failed resolve restores a tag it overwrote" "script exited zero"
  elif [[ "$after" != "$before" ]]; then
    fail "a failed resolve restores a tag it overwrote" \
      "v2.0.0 was $before before the run and $after after it"
  else
    pass "a failed resolve restores a tag it overwrote"
  fi
}

# --- the rollback keeps what the fetch learned --------------------------------
# The complement of the case above, and the one neither rule was pinned by: the
# suite passed whether the rollback reverted remote-tracking refs or left them,
# because no fixture had a `--to` the clone already tracks *and* an origin that
# has moved since the clone.
#
# The two namespaces are not the same thing. `refs/tags/<name>` is the operator's
# and the `+` clobbered it, so restoring the prior object is a repair.
# `refs/remotes/origin/<to>` is git's cache of the remote and only ever moves
# toward the truth — reverting it leaves `git status` reporting against a stale
# tip on a branch that tracks it, with the objects already in the store and only
# the ref rolled back. Deleting what was *created* is the half that answers the
# original finding; putting a remote-tracking ref backwards is not.
t_rollback_keeps_what_the_fetch_learned() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # origin's main moves after the clone, so the fetch has something to learn.
  git -C "$root/origin" checkout -q main
  echo moved > "$root/origin/h.txt"
  git -C "$root/origin" add h.txt
  git -C "$root/origin" commit -qm "chore: landed on main after the clone"
  local origin_main; origin_main="$(git -C "$root/origin" rev-parse main)"

  # --from is a tag on a blob, so the resolve fails after the fetch has written.
  local blob; blob="$(git -C "$root/origin" rev-parse HEAD:f.txt)"
  git -C "$root/origin" tag v9.9.9 "$blob"

  local before_tracking; before_tracking="$(git -C "$root/clone" rev-parse refs/remotes/origin/main)"

  local rc=0
  (cd "$root/clone" && "$SCRIPT" --from v9.9.9 --to main >/dev/null 2>&1) || rc=$?

  local after_tracking; after_tracking="$(git -C "$root/clone" rev-parse refs/remotes/origin/main)"

  if [[ "$rc" -eq 0 ]]; then
    fail "the rollback keeps what the fetch learned" "script exited zero"
  elif [[ "$before_tracking" == "$after_tracking" ]]; then
    fail "the rollback keeps what the fetch learned" \
      "origin/main was reverted to its pre-fetch value"
  elif [[ "$after_tracking" != "$origin_main" ]]; then
    fail "the rollback keeps what the fetch learned" \
      "origin/main is neither the pre-fetch value nor origin's: $after_tracking"
  elif git -C "$root/clone" rev-parse --verify --quiet refs/tags/v9.9.9 >/dev/null; then
    fail "the rollback keeps what the fetch learned" \
      "the tag this run created was left behind"
  else
    pass "the rollback keeps what the fetch learned, and drops what it created"
  fi
}

# --- a local branch named origin/<name> does not shadow the fetched ref --------
# `origin/<name>` goes through gitrevisions precedence, which tries
# `refs/heads/<name>` before `refs/remotes/<name>`. A stray local branch named
# `origin/release/v1.0.0` — the `git checkout -b origin/…` typo — therefore won
# over the remote-tracking ref the fetch had just written, and the run backported
# it: exit 0, a `backport/<x>` branch, the release fix never carried, and
# `warning: refname ... is ambiguous` on stderr as the only signal.
#
# The `origin/` guard rejects the prefix in the *argument*; it cannot see a local
# branch of that name in the repo. Fully-qualified FROM_REF/TO_REF can.
t_ambiguous_origin_branch() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # A local branch literally named origin/release/v1.0.0, carrying a commit that
  # is not the release fix.
  git -C "$root/clone" checkout -q -b origin/release/v1.0.0 main
  echo other > "$root/clone/g.txt"
  git -C "$root/clone" add g.txt
  git -C "$root/clone" commit -qm "chore: NOT the release fix"
  git -C "$root/clone" checkout -q main

  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)" || rc=$?

  # Captured, not piped into grep -q: this file runs under `set -o pipefail`, and
  # grep -q exits on its first match, so git takes SIGPIPE and the pipeline
  # reports non-zero on a *successful* match. Same trap as the one noted above
  # fetch_invocations.
  local backport_log=""
  if git -C "$root/clone" rev-parse --verify --quiet refs/heads/backport/v1.0.0 >/dev/null; then
    backport_log="$(git -C "$root/clone" log --oneline refs/heads/backport/v1.0.0)"
  fi

  if [[ "$rc" -ne 0 ]]; then
    fail "a local origin/<name> branch does not shadow the fetched source ref" \
      "script exited $rc: ${out##*$'\n'}"
  elif grep -q "NOT the release fix" <<<"$out"; then
    fail "a local origin/<name> branch does not shadow the fetched source ref" \
      "it listed the local branch's commit as a candidate"
  elif ! grep -q "landed on the release branch" <<<"$backport_log"; then
    fail "a local origin/<name> branch does not shadow the fetched source ref" \
      "the backport branch does not carry the release commit: ${backport_log%%$'\n'*}"
  else
    pass "a local origin/<name> branch does not shadow the fetched source ref"
  fi
}

# --- ...and the same collision on --to ----------------------------------------
# The target arm needs its own case because the two fail differently, which is the
# same reason t_failed_fetch_* splits three ways. The source arm is exit 0 with the
# wrong commits on the branch; this one is a *false candidate list* and then exit
# 128 from `checkout -b`. `git cherry` accepts the ambiguity and answers against
# refs/heads/origin/main, so the operator is told to backport a commit that is
# already on the target — the wrong answer arrives before the fatal, and the fatal
# is not what makes it wrong.
#
# The fixture is the mirror of the case above: a stale local `origin/main`, and the
# release fix already carried onto origin's main, so a resolver reading the real
# remote-tracking ref has nothing to do.
t_ambiguous_origin_target_branch() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # The release fix is already on origin's main — cherry-picked, so it is a
  # distinct commit with the same patch id, which is what `git cherry` matches on.
  git -C "$root/origin" checkout -q main
  git -C "$root/origin" cherry-pick release/v1.0.0 >/dev/null

  # A stale local branch literally named origin/main, from before that landed.
  git -C "$root/clone" branch origin/main main

  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)" || rc=$?

  if [[ "$rc" -ne 0 ]]; then
    fail "a local origin/<name> branch does not shadow the fetched target ref" \
      "script exited $rc: ${out##*$'\n'}"
  elif ! grep -q "Nothing to backport" <<<"$out"; then
    fail "a local origin/<name> branch does not shadow the fetched target ref" \
      "it did not resolve --to against the fetched ref: ${out##*$'\n'}"
  elif git -C "$root/clone" rev-parse --verify --quiet refs/heads/backport/v1.0.0 >/dev/null; then
    fail "a local origin/<name> branch does not shadow the fetched target ref" \
      "it created a backport branch for a commit already on the target"
  else
    pass "a local origin/<name> branch does not shadow the fetched target ref"
  fi
}

# --- an empty --from names the right reason ------------------------------------
# All three value-taking flags reject an empty value loudly; --from was the one
# that named the wrong reason for it, reporting "--from is required" for an
# argument the operator did in fact provide. Same distinction --branch needed:
# "not passed" and "passed empty" are the same empty string until something
# records that the flag was seen.
t_empty_from_names_the_reason() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local out rc label
  for label in '--from=' "--from ''"; do
    rc=0
    if [[ "$label" == '--from=' ]]; then
      out="$(cd "$root/clone" && "$SCRIPT" --from= --to main 2>&1)" || rc=$?
    else
      out="$(cd "$root/clone" && "$SCRIPT" --from '' --to main 2>&1)" || rc=$?
    fi
    if [[ "$rc" -ne 2 ]]; then
      fail "an empty --from names the right reason" "$label exited $rc, want 2"
      return
    elif ! grep -q -- "--from cannot be empty" <<<"$out"; then
      fail "an empty --from names the right reason" \
        "$label: unexpected message: ${out%%$'\n'*}"
      return
    fi
  done

  # And the genuinely absent case still says "required".
  rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --to main 2>&1)" || rc=$?
  if ! grep -q -- "--from is required" <<<"$out"; then
    fail "an empty --from names the right reason" \
      "an absent --from no longer says required: ${out%%$'\n'*}"
  else
    pass "an empty --from names the right reason, an absent one still says required"
  fi
}

# --- an empty --branch is a usage error, not the derived name -------------------
# The fourth member of the family the round-two commit took three of: an argument
# the operator typed, discarded without a word, exit 0. The value check does not
# see it — `--branch ''` is two words, so `$# -lt 2` is false — and
# `[[ -n "$BRANCH_OVERRIDE" ]]` then reads "passed empty" as "not passed", so the
# run fell through to the derived name and cherry-picked onto a branch nobody
# asked for. --to catches its own empty form only because it defaults to a
# non-empty value. Both spellings, since `--branch=` parses through a different
# arm than the flag followed by an empty word.
t_empty_branch_override() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local out rc label
  for label in '--branch=' "--branch ''"; do
    rc=0
    if [[ "$label" == '--branch=' ]]; then
      out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main --branch= 2>&1)" || rc=$?
    else
      out="$(cd "$root/clone" && "$SCRIPT" --from release/v1.0.0 --to main --branch '' 2>&1)" || rc=$?
    fi
    if [[ "$rc" -ne 2 ]]; then
      fail "an empty --branch is a usage error" "$label exited $rc, want 2"
      return
    elif ! grep -q -- "--branch cannot be empty" <<<"$out"; then
      fail "an empty --branch is a usage error" "$label: unexpected message: ${out##*$'\n'}"
      return
    elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
      fail "an empty --branch is a usage error" "$label fell back to the derived name"
      return
    fi
  done
  pass "an empty --branch is a usage error, not a fallback to the derived name"
}

# --- a backport imports no tags it was not asked for ---------------------------
# `--help` promises "those two refs — not the whole remote", and tag
# auto-following broke that on every successful run: a fetch also takes every
# remote tag pointing at an object the run has downloaded, so a backport left
# release candidates and nightlies behind in the operator's repo.
#
# Both shapes live in one case because the three fetches feed one invariant and
# the last of them sees everything the earlier ones downloaded: dropping
# --no-tags from the target fetch shows up in both shapes, from the source
# branch or the source tag arm in one each. Split into two cases, the target
# fetch would redden both of them.
t_no_unrequested_tags() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN

  # Shape 1, branch source. origin's main has moved on and carries a tag of its
  # own, so the target fetch downloads an object and has a tag to auto-follow
  # too. Nothing here is named on the command line: the clone must end with no
  # tags at all.
  make_fixture "$root/branch-source"
  git -C "$root/branch-source/origin" tag v1.0.0-rc1 release/v1.0.0
  echo moved > "$root/branch-source/origin/g.txt"
  git -C "$root/branch-source/origin" add -A
  git -C "$root/branch-source/origin" commit -qm "chore: main moved on"
  git -C "$root/branch-source/origin" tag nightly-1

  local out rc=0
  out="$(cd "$root/branch-source/clone" && "$SCRIPT" --from release/v1.0.0 --to main 2>&1)" || rc=$?
  local tags; tags="$(git -C "$root/branch-source/clone" tag | tr '\n' ' ')"
  if [[ "$rc" -ne 0 ]]; then
    fail "a backport imports no tags it was not asked for" \
      "branch source exited non-zero: ${out##*$'\n'}"
    return
  elif [[ -n "$tags" ]]; then
    fail "a backport imports no tags it was not asked for" \
      "a branch source dragged in tags: ${tags% }"
    return
  fi

  # Shape 2, tag source. --from v1.0.0 asks for exactly one tag by refspec and
  # --no-tags does not suppress an explicit refspec, so that tag must arrive —
  # this half is what stops the flag from being "fixed" onto the tag arm, where
  # it would break the path the release guide tells maintainers to use.
  # v1.0.0-rc1 sits on the same commit and was not asked for.
  make_fixture "$root/tag-source"
  git -C "$root/tag-source/origin" tag v1.0.0-rc1 release/v1.0.0

  rc=0
  out="$(cd "$root/tag-source/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)" || rc=$?
  tags="$(git -C "$root/tag-source/clone" tag | tr '\n' ' ')"
  if [[ "$rc" -ne 0 ]]; then
    fail "a backport imports no tags it was not asked for" \
      "tag source exited non-zero: ${out##*$'\n'}"
  elif [[ "$tags" != "v1.0.0 " ]]; then
    fail "a backport imports no tags it was not asked for" \
      "expected only the requested tag, got: ${tags% }"
  else
    pass "a backport imports no tags it was not asked for"
  fi
}

# --- a --from that resolves to a non-commit says so ----------------------------
# A tag can point at any object, and `v9.9.9` naming a blob is a ref name git's
# own grammar accepts — so check-ref-format cannot see it, ls-remote reports it
# like any other ref, and it arrives at the comparison fully resolved. `git
# cherry` is loud about it (that is the `|| true` removal working), but it
# blames the comparison for an input problem, which is the same mislabelling one
# step along: the run says git cherry failed when what failed is --from.
t_from_must_name_a_commit() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local blob; blob="$(git -C "$root/origin" rev-parse HEAD:f.txt)"
  git -C "$root/origin" tag v9.9.9 "$blob"

  # A --to the clone does not already track, so the target refspec's destination
  # is genuinely new. With `--to main` the clone already holds
  # refs/remotes/origin/main, so that half of the fetch wrote nothing and the
  # assertion below passed without ever exercising it.
  git -C "$root/origin" branch stable/1.x main

  # Pins the refs too, not just the branch, and by *value*: this is the one path
  # that reaches its error having already written. A lightweight tag on a blob is
  # indistinguishable from one on a commit in ls-remote output — no `^{}` peel
  # line either way — so the type is not knowable before the fetch and the
  # `^{commit}` check necessarily runs after it. The invariant above the resolver
  # is stated without qualification, so the check has to undo the write rather
  # than the comment having to admit an exception.
  #
  # `%(refname)` alone compared names, so a ref whose value changed under the
  # `+` was invisible to it. make_fixture clones before the tag exists, which is
  # what makes the tag genuinely new here.
  local refs_before; refs_before="$(git -C "$root/clone" for-each-ref --format='%(refname) %(objectname)')"

  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from v9.9.9 --to stable/1.x 2>&1)" || rc=$?
  local refs_after; refs_after="$(git -C "$root/clone" for-each-ref --format='%(refname) %(objectname)')"
  if [[ "$rc" -eq 0 ]]; then
    fail "a --from that is not a commit is named as such" "script exited zero"
  elif ! grep -q "does not name a commit" <<<"$out"; then
    fail "a --from that is not a commit is named as such" \
      "it did not name the cause: ${out##*$'\n'}"
  elif grep -q "git cherry" <<<"$out"; then
    fail "a --from that is not a commit is named as such" \
      "it still blames the comparison for an input problem"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "a --from that is not a commit is named as such" "it created a backport branch anyway"
  elif [[ "$refs_before" != "$refs_after" ]]; then
    fail "a --from that is not a commit is named as such" \
      "it left refs behind: $(comm -13 <(echo "$refs_before") <(echo "$refs_after") | tr '\n' ' ')"
  else
    pass "a --from that is not a commit is named as such, and writes nothing"
  fi
}

# --- a flag with no value is a usage error -------------------------------------
# `shift 2` with one argument left fails, and `set -e` took that as the whole
# outcome: exit 1, nothing on either stream. The fourth member of this PR's
# family — a failure the operator cannot act on because nothing says what
# happened. backport-fixes.yml cannot reach it, since `--from "${{ inputs.
# fromBranch }}"` always passes a word, so this is the local CLI only.
#
# The message is asserted, not just the exit code: without it, `--from` alone
# still exits 2 through "error: --from is required" — the value-less flag would
# read as a pass while saying something else.
t_flag_without_value() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local flag out rc
  for flag in --from --to --branch; do
    rc=0
    out="$(cd "$root/clone" && "$SCRIPT" "$flag" 2>&1)" || rc=$?
    if [[ "$rc" -ne 2 ]]; then
      fail "a flag with no value is a usage error" "$flag exited $rc, want 2"
      return
    elif ! grep -q -- "$flag requires a value" <<<"$out"; then
      fail "a flag with no value is a usage error" "$flag said nothing about the missing value"
      return
    fi
  done
  pass "a flag with no value is a usage error"
}

# --- a git cherry failure is named as one --------------------------------------
# The `|| true` removal had no case: every input-level path that reached it is
# now intercepted earlier — a glob by require_ref_name, a tag on a blob by the
# `^{commit}` check (t_from_must_name_a_commit asserts `git cherry` is *absent*
# from that run, which is the same fact from the other side) — so restoring
# `|| true` left the whole suite green.
#
# What is left is object-level, and it has to survive the dirty-tree check to
# reach the comparison: an object the revision walk needs, missing from the local
# store, in a part of the history no working-tree check reads. The fetch does not
# resupply it — refs/remotes/origin/main already names the tip, so origin sends
# nothing for it — and `git cherry` fails on the walk rather than on either
# endpoint, both of which resolve.
#
# With `|| true` back the same run reports "Nothing to backport." at exit 0: a
# tooling failure told to the operator as a fact about the refs, which is the
# collapse this PR exists to remove.
t_cherry_failure_is_named() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  # Two commits on origin's main after the clone's HEAD, so the walk has to read
  # a commit object that is neither endpoint nor anything the working tree or the
  # index is compared against.
  echo m1 > "$root/origin/g.txt"
  git -C "$root/origin" add -A
  git -C "$root/origin" commit -qm "chore: m1"
  echo m2 > "$root/origin/g.txt"
  git -C "$root/origin" commit -qam "chore: m2"
  git -C "$root/clone" fetch -q origin '+refs/heads/main:refs/remotes/origin/main'

  # A local clone hardlinks loose objects, so removing the clone's directory
  # entry leaves origin's copy — and origin's answers — untouched.
  local victim path
  victim="$(git -C "$root/clone" rev-parse 'refs/remotes/origin/main~1')"
  path="$root/clone/.git/objects/${victim:0:2}/${victim:2}"
  if [[ ! -f "$path" ]]; then
    fail "a git cherry failure is named as one" "the fixture object is not loose at $path"
    return
  fi
  rm -f "$path"

  local out rc=0
  out="$(cd "$root/clone" && "$SCRIPT" --from v1.0.0 --to main 2>&1)" || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    fail "a git cherry failure is named as one" "script exited zero"
  elif grep -q "Nothing to backport" <<<"$out"; then
    fail "a git cherry failure is named as one" \
      "it reported nothing to backport instead of the failed comparison"
  elif ! grep -q "git cherry could not compare" <<<"$out"; then
    fail "a git cherry failure is named as one" "it did not name the cause: ${out##*$'\n'}"
  elif [[ -n "$(git -C "$root/clone" branch --list 'backport/*')" ]]; then
    fail "a git cherry failure is named as one" "it created a backport branch anyway"
  else
    pass "a git cherry failure is named as one, not as an empty candidate list"
  fi
}

# --- both spellings of a value-taking flag -------------------------------------
# `--from=release/v1.0.0` took the unknown-argument arm and exited 2. Loud, so
# never a silent wrong answer, but it is not a defensible response to the flag
# --help leads with and it is drift from the sibling scripts, which accept both.
t_flag_equals_form() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN
  make_fixture "$root"

  local out subjects
  if out="$(cd "$root/clone" && "$SCRIPT" --from=release/v1.0.0 --to=main 2>&1)"; then
    subjects="$(git -C "$root/clone" log --format=%s main..HEAD)"
    if grep -q "landed on the release branch" <<<"$subjects"; then
      pass "--flag=value is accepted for --from and --to"
    else
      fail "--flag=value is accepted" "branch created but the commit is missing"
    fi
  else
    fail "--flag=value is accepted" "script exited non-zero: ${out##*$'\n'}"
  fi
}

# --- outside a repo, the missing repo is the error -----------------------------
# check-ref-format needs no repository, so with the ref-name guards running first
# someone outside a repo was told their ref name was wrong — fixing which only
# earned them the real blocker on the next run. The argument here is a glob, so
# it would fail the ref-name check too; the case is what pins which of the two
# answers comes back. `check-ref-format --branch` also resolves the `@{-N}`
# forms, which need a repository, so the --branch guard depends on this order.
t_outside_a_repo() {
  local root; root="$(mktemp -d)"; trap 'rm -rf "$root"' RETURN

  local out rc=0
  out="$(cd "$root" && "$SCRIPT" --from 'release/*' --to main 2>&1)" || rc=$?
  if [[ "$rc" -ne 1 ]]; then
    fail "outside a repo, the missing repo is the error" "exit $rc, want 1"
  elif ! grep -q "not inside a git repository" <<<"$out"; then
    fail "outside a repo, the missing repo is the error" "unexpected message: ${out##*$'\n'}"
  else
    pass "outside a repo, the missing repo is reported before the ref name"
  fi
}

echo "backport-fixes.sh — argument handling and ref resolution"
t_branch
t_tag
t_unknown
t_to_rejects_a_tag
t_force_pushed_source
t_branch_beats_tag
t_recut_tag
t_force_pushed_target
t_fetches_stay_verbose
t_failed_fetch_source_branch
t_failed_fetch_source_tag
t_failed_fetch_target_branch
t_unreachable_remote
t_glob_from
t_glob_to
t_bad_to_writes_nothing
t_branch_override_is_validated
t_branch_override_previous_checkout
t_failed_resolve_restores_a_clobbered_tag
t_ambiguous_origin_branch
t_ambiguous_origin_target_branch
t_rollback_keeps_what_the_fetch_learned
t_empty_from_names_the_reason
t_empty_branch_override
t_no_unrequested_tags
t_from_must_name_a_commit
t_cherry_failure_is_named
t_flag_without_value
t_flag_equals_form
t_outside_a_repo

if [[ "$failures" -gt 0 ]]; then
  echo "$failures failing"
  exit 1
fi
echo "all passing"

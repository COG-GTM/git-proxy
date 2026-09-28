#!/usr/bin/env bash
#
# Copyright 2026 GitProxy Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Example GitProxy pre-receive hook for GitLab-fronted repositories.
#
# GitProxy runs ./hooks/pre-receive.sh (relative to the directory GitProxy is started from) after
# the push has been written into its temporary clone of the upstream repository. The hook runs
# with that clone as its working directory and receives one line on stdin:
#
#   <old-commit> <new-commit> <ref>
#
# Exit codes understood by GitProxy:
#   0  auto-approve  (the push still gets a GitProxy link; pushing again forwards it to GitLab)
#   1  auto-reject
#   2  manual review (a reviewer must approve the push in the GitProxy UI)
#   *  anything else is treated as an error and the push is blocked
#
# Policies, evaluated in order:
#   1. reject if any added/modified blob is larger than GITPROXY_HOOK_MAX_FILE_BYTES (default 5 MiB)
#   2. reject if any added/modified file has a blocked binary/keystore extension
#   3. restrictSensitivePaths: reject changes to .gitlab-ci.yml, CODEOWNERS or .gitlab/** unless the
#      pusher (the last commit's committer email, which is how GitProxy identifies the pusher) is
#      in GITPROXY_SENSITIVE_PATH_ALLOWLIST; allowlisted changes always go to manual review
#   4. approve if every changed file is documentation (*.md or docs/**)
#   5. otherwise require manual review
#
# Configuration (environment variables inherited from the GitProxy process):
#   GITPROXY_HOOK_MAX_FILE_BYTES        default 5242880
#   GITPROXY_HOOK_BLOCKED_EXTENSIONS    space/comma separated, case-insensitive
#   GITPROXY_SENSITIVE_PATH_PATTERN     extended regex matched against each changed path
#   GITPROXY_SENSITIVE_PATH_ALLOWLIST   space/comma separated committer emails
#   GITPROXY_DOCS_PATH_PATTERN          extended regex for documentation-only changes
#   GITPROXY_HOOK_LOG                   optional file to append one audit line per decision to
#
# GitProxy records only the exit status of this hook (not its output) for exit codes 0, 1 and 2,
# so set GITPROXY_HOOK_LOG to keep the reason behind each decision.

set -uo pipefail

MAX_FILE_BYTES="${GITPROXY_HOOK_MAX_FILE_BYTES:-5242880}"
BLOCKED_EXTENSIONS="${GITPROXY_HOOK_BLOCKED_EXTENSIONS:-exe dll so dylib bin msi dmg iso jar war ear class pyc zip tar gz tgz bz2 xz 7z rar p12 pfx jks keystore}"
SENSITIVE_PATH_PATTERN="${GITPROXY_SENSITIVE_PATH_PATTERN:-(^|/)\.gitlab-ci\.ya?ml$|(^|/)CODEOWNERS$|^\.gitlab/}"
SENSITIVE_PATH_ALLOWLIST="${GITPROXY_SENSITIVE_PATH_ALLOWLIST:-}"
DOCS_PATH_PATTERN="${GITPROXY_DOCS_PATH_PATTERN:-\.md$|^docs/}"

ZERO_COMMIT_PATTERN='^0+$'

log() {
  echo "pre-receive: $*"
  if [[ -n "${GITPROXY_HOOK_LOG:-}" ]]; then
    printf '%s %s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(basename "$(pwd)")" "${ref:-?}@${new:-?}" "$*" >>"$GITPROXY_HOOK_LOG" || true
  fi
}

# Fail safe: anything unexpected sends the push to a human reviewer.
review() {
  log "manual review required: $*"
  exit 2
}

reject() {
  log "REJECTED: $*"
  exit 1
}

approve() {
  log "auto-approved: $*"
  exit 0
}

for pattern_var in SENSITIVE_PATH_PATTERN DOCS_PATH_PATTERN; do
  grep -Eq -- "${!pattern_var}" <<<"" 2>/dev/null
  (($? <= 1)) || review "invalid regular expression in GITPROXY_${pattern_var}"
done

read -r old new ref || review "no ref update received on stdin"
[[ -n "${new:-}" && ! "$new" =~ $ZERO_COMMIT_PATTERN ]] || review "branch deletion or empty update for ${ref:-unknown ref}"
git cat-file -e "${new}^{commit}" 2>/dev/null || review "commit $new not found in $(pwd)"

if [[ -n "${old:-}" && ! "$old" =~ $ZERO_COMMIT_PATTERN ]] && git cat-file -e "${old}^{commit}" 2>/dev/null; then
  commits="$(git rev-list "${old}..${new}")" || review "unable to list commits ${old}..${new}"
else
  # New branch or unknown base: everything not already on the upstream's remote-tracking refs.
  commits="$(git rev-list "$new" --not --remotes)" || review "unable to list commits for $new"
fi
[[ -n "$commits" ]] || review "no new commits between ${old:-<none>} and $new"

# Raw diff-tree lines: ":<old mode> <new mode> <old sha> <new sha> <status>\t<path>".
# -c adds merge commits as combined diffs ("::<modes...> <shas...> <status>\t<path>"), so edits
# made while resolving a merge are inspected too.
changes="$(
  for commit in $commits; do
    git -c core.quotePath=false diff-tree -r -c --root --no-commit-id --no-renames "$commit" || exit 1
  done
)" || review "unable to compute changed files"
[[ -n "$changes" ]] || review "push contains no file changes"

extension_pattern="\.($(echo "$BLOCKED_EXTENSIONS" | tr ', ' '\n\n' | sed '/^$/d' | paste -sd '|' -))$"
changed_paths=()
while IFS=$'\t' read -r meta path; do
  [[ -n "$path" ]] || continue
  changed_paths+=("$path")
  colons="${meta%%[!:]*}"
  parents=${#colons}
  read -r -a fields <<<"${meta#"$colons"}"
  new_mode="${fields[parents]}"
  new_sha="${fields[2 * parents + 1]}"
  if [[ "$new_sha" =~ ^0+$ || "$new_mode" == "160000" ]]; then
    continue # deletions and submodule pointers carry no blob
  fi
  size="$(git cat-file -s "$new_sha" 2>/dev/null)" || review "unable to read blob for $path"
  if ((size > MAX_FILE_BYTES)); then
    reject "$path is ${size} bytes (limit ${MAX_FILE_BYTES}); use Git LFS or an artifact repository"
  fi
  if [[ "$(echo "$path" | tr '[:upper:]' '[:lower:]')" =~ $extension_pattern ]]; then
    reject "$path has a blocked file extension"
  fi
done <<<"$changes"

pusher="$(git log -1 --format=%ce "$new" | tr '[:upper:]' '[:lower:]')"
sensitive="$(printf '%s\n' "${changed_paths[@]}" | grep -E "$SENSITIVE_PATH_PATTERN" | sort -u | paste -sd ' ' -)"
if [[ -n "$sensitive" ]]; then
  allowlist=" $(echo "$SENSITIVE_PATH_ALLOWLIST" | tr '[:upper:],' '[:lower:] ') "
  if [[ "$allowlist" != *" $pusher "* ]]; then
    reject "$pusher may not modify protected paths: $sensitive"
  fi
  review "$pusher (allowlisted) modified protected paths: $sensitive"
fi

non_docs="$(printf '%s\n' "${changed_paths[@]}" | grep -Ev "$DOCS_PATH_PATTERN" | head -n 1)"
if [[ -z "$non_docs" ]]; then
  approve "documentation-only change (${#changed_paths[@]} path(s))"
fi

review "change touches non-documentation files (e.g. $non_docs)"

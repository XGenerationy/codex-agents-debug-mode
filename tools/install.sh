#!/usr/bin/env bash
set -euo pipefail

target="both"
force="false"
# Use parameter expansion with default so an unset HOME (common in stripped
# containers, service accounts, and some CI contexts) does not abort the
# script under `set -u` before --home can be parsed. Validate after parsing.
home_path="${HOME:-}"

while (($#)); do
  case "$1" in
    --target)
      if [[ $# -lt 2 ]]; then echo "--target requires a value" >&2; exit 2; fi
      target="$2"
      shift 2
      ;;
    --force)
      force="true"
      shift
      ;;
    --home)
      if [[ $# -lt 2 ]]; then echo "--home requires a value" >&2; exit 2; fi
      home_path="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$home_path" ]]; then
  echo "HOME is not set; pass --home <path>" >&2
  exit 2
fi

# Reject relative home paths so the installer cannot silently write into the
# current working directory. Mirrors the absolute-path check in
# tools/install.ps1 (System.IO.Path.IsPathRooted).
if [[ "$home_path" != /* ]]; then
  echo "--home / HOME must be an absolute path: $home_path" >&2
  exit 2
fi

case "$target" in
  codex) destinations=("$home_path/.codex/skills/debug") ;;
  agents) destinations=("$home_path/.agents/skills/debug") ;;
  both) destinations=("$home_path/.codex/skills/debug" "$home_path/.agents/skills/debug") ;;
  *)
    echo "--target must be codex, agents, or both" >&2
    exit 2
    ;;
esac

script_dir="${BASH_SOURCE[0]%/*}"
[[ "$script_dir" == "${BASH_SOURCE[0]}" ]] && script_dir="."
source_dir="$(cd "$script_dir/.." && pwd)"
payload=(SKILL.md agents assets references scripts)

# Emit a machine-readable install result as valid JSON. Prefer node's
# JSON.stringify (the skill requires Node anyway) so every control character
# is escaped correctly; fall back to a manual escaper that covers backslash,
# quote, and the common JSON control characters for minimal environments.
emit_result() {
  local target="$1" backup="$2"
  if command -v node >/dev/null 2>&1; then
    # With `node -e`, user arguments land at process.argv[1]/[2] on every
    # supported Node version (verified on Node 20/22/24). The `--` separator
    # keeps values beginning with `-` from being parsed as Node CLI options.
    node -e 'console.log(JSON.stringify({status:"installed",target:process.argv[1],backup:process.argv[2]}))' -- "$target" "$backup"
    return
  fi
  local t b
  t="${target//\\/\\\\}"; t="${t//\"/\\\"}"; t="${t//$'\n'/\\n}"; t="${t//$'\r'/\\r}"; t="${t//$'\t'/\\t}"
  b="${backup//\\/\\\\}"; b="${b//\"/\\\"}"; b="${b//$'\n'/\\n}"; b="${b//$'\r'/\\r}"; b="${b//$'\t'/\\t}"
  printf '{"status":"installed","target":"%s","backup":"%s"}\n' "$t" "$b"
}

for entry in "${payload[@]}"; do
  # Reject symlinks and special files (FIFOs, sockets, devices): -e follows a
  # symlink to an outside path and would pass, then cp -R would stage the link
  # (or its target) into the installed skill, letting a reviewed payload point
  # outside the tree. Require a regular file or directory.
  [[ (-f "$source_dir/$entry" || -d "$source_dir/$entry") && ! -L "$source_dir/$entry" ]] || {
    echo "Skill payload entry must be a regular file/directory, not a symlink, special file, or missing: $entry" >&2
    exit 1
  }
  # The check above only guards the entry itself; a directory entry can still
  # contain a nested symlink or special file one or more levels down, and the
  # top-level preflight passing would let cp -R stage that nested link (or
  # FIFO) into the installed skill instead of failing closed. find's default
  # -P mode never follows a symlink while traversing, so walking the subtree
  # cannot be redirected outside the tree by the very link being checked for.
  if [[ -d "$source_dir/$entry" ]]; then
    nested="$(find "$source_dir/$entry" -not -type f -not -type d -print -quit)"
    if [[ -n "$nested" ]]; then
      echo "Skill payload contains a symlink or special file, not a regular file/directory: $nested" >&2
      exit 1
    fi
  fi
done

# Preflight all destinations before mutating any of them so multi-target
# installs cannot leave one path updated and another absent/partial. -e alone
# is false for a dangling symlink (it follows the link and tests the missing
# target), which would let a non-forced install silently proceed over one
# instead of refusing like it does for every other existing entry; -L catches
# the symlink itself regardless of whether its target resolves.
for destination in "${destinations[@]}"; do
  if [[ ( -e "$destination" || -L "$destination" ) && "$force" != "true" ]]; then
    echo "Target exists: $destination. Rerun with --force to preserve it as a backup and replace it." >&2
    exit 1
  fi
done

unique_backup() {
  local destination="$1"
  local base_ts backup
  base_ts="$(date -u +%Y%m%d%H%M%S)"
  backup="$destination.backup.$base_ts.$$"
  # -L alongside -e: a dangling symlink at the candidate backup path is
  # invisible to bare -e, so the loop would accept it and mv would write
  # through the link instead of choosing a free name.
  while [[ -e "$backup" || -L "$backup" ]]; do
    backup="$destination.backup.$base_ts.$$.$RANDOM"
  done
  printf '%s\n' "$backup"
}

# Stage each destination under its destination parent so the final mv is an
# atomic rename on the same filesystem. Staging under ${TMPDIR:-/tmp} can land
# on a different device than $HOME (NFS home, container bind mounts); then
# `mv` copies and an interruption can leave a partial install after backup.
declare -a stage_paths=()
declare -a acquired_locks=()
lock_host="${HOSTNAME:-}"
if [[ -z "$lock_host" ]]; then
  lock_host="$(hostname)"
fi
lock_owner="pid=$$"$'\n'"host=$lock_host"$'\n'"token=$$.$RANDOM.$RANDOM"
cleanup_stages() {
  # Best-effort stage removal on EXIT under `set -e`. Capture rm failures
  # into rm_status rather than OR-listing a forced success so this helper
  # is not treated as validation silencing (Codex #4781637950 follow-up).
  local s rm_status=0
  for s in "${stage_paths[@]:-}"; do
    if [[ -n "$s" && ( -e "$s" || -L "$s" ) ]]; then
      rm -rf -- "$s" 2>/dev/null || rm_status=$?
      if [[ $rm_status -ne 0 ]]; then
        echo "Cleanup warning: could not remove staging directory $s (rm exit $rm_status)" >&2
        rm_status=0
      fi
    fi
  done
  # Trap cleanup must not rewrite the installer's exit status.
  return 0
}
release_destination_locks() {
  local i lock_path owner
  for ((i = ${#acquired_locks[@]} - 1; i >= 0; i--)); do
    lock_path="${acquired_locks[$i]}"
    # Never unlink a lock that no longer identifies this process. A live
    # owner cannot be replaced while its lock name exists, and the equality
    # check also keeps cleanup from deleting an unrelated file after a manual
    # repair of a stale lock.
    if [[ -f "$lock_path" && ! -L "$lock_path" ]]; then
      owner="$(<"$lock_path")"
      if [[ "$owner" == "$lock_owner" ]]; then
        if ! rm -- "$lock_path" 2>/dev/null; then
          echo "Cleanup warning: could not release install lock $lock_path" >&2
        fi
      fi
    fi
  done
  acquired_locks=()
}
cleanup_on_exit() {
  local status=$?
  cleanup_stages
  release_destination_locks
  return "$status"
}
# Single-quoted trap body so the handler is not expanded at registration time
# (shellcheck SC2064). Do not add a disable directive; the quote form is the fix.
trap 'cleanup_on_exit' EXIT
trap 'exit 128' HUP INT TERM

for destination in "${destinations[@]}"; do
  parent="$(dirname -- "$destination")"
  mkdir -p -- "$parent"
  stage="$(mktemp -d -- "$parent/.debug-install-stage.XXXXXX" 2>/dev/null     || mktemp -d "$parent/.debug-install-stage.XXXXXX")"
  # Register before populating so a failed cp still leaves the stage path for
  # the EXIT trap / cleanup_stages to remove.
  stage_paths+=("$stage")
  for entry in "${payload[@]}"; do
    cp -R -- "$source_dir/$entry" "$stage/"
  done
done

declare -a committed_dests=()
declare -a committed_backups=()

# Restore a destination from its backup if present (committed or in-flight).
# Best-effort: a rollback step failure is surfaced on stderr but does not abort
# the remaining rollback steps, since the original install error must remain the
# primary failure. rm/mv return non-zero are caught explicitly so set -e does
# not exit the script mid-rollback.
#
# require_backup (3rd arg, default false): when true and $backup is empty, an
# existing non-empty $dest is left untouched instead of being removed. An
# empty backup means $destination did not exist at this destination's
# preflight check, so on this destination's own commit-failure path a
# concurrent process may have created $destination in the same race window
# this script already guards against (mv nesting the stage inside it, or the
# commit mv failing outright) -- with no backup, that content was never ours
# to begin with, and removing it would destroy data we neither created nor
# can restore (Codex/qodo finding: "Race cleanup deletes new target"). A bare
# empty directory is still removed even under require_backup: it holds no
# data (any nested stage this script itself moved into it is always cleared
# by the caller first), so removing it cannot destroy anything, and the
# nested-stage recovery path relies on that to fully roll back the
# concurrently created directory rather than leaving an empty husk behind.
# rollback()'s callers pass the default false: those destinations were
# committed by this same run, so an empty backup there means WE created that
# destination fresh, and it is always ours to remove.
restore_from_backup() {
  local dest="$1" backup="$2" require_backup="${3:-false}"
  if [[ "$require_backup" == "true" && -z "$backup" && -e "$dest" ]]; then
    if [[ ! -d "$dest" || -n "$(ls -A -- "$dest" 2>/dev/null)" ]]; then
      return 0
    fi
  fi
  if ! rm -rf -- "$dest" 2>/dev/null; then
    echo "Rollback warning: could not remove $dest" >&2
  fi
  # -L alongside -e: if the original destination was itself a dangling
  # symlink, unique_backup's mv carried that dangling symlink to $backup
  # verbatim, and -e alone would miss it here too, silently skipping the
  # restore of an otherwise-valid backup.
  if [[ -n "$backup" && ( -e "$backup" || -L "$backup" ) ]]; then
    if ! mv -- "$backup" "$dest" 2>/dev/null; then
      echo "Rollback warning: could not restore $dest from backup" >&2
    fi
  fi
}

rollback() {
  local i
  for ((i = ${#committed_dests[@]} - 1; i >= 0; i--)); do
    restore_from_backup "${committed_dests[$i]}" "${committed_backups[$i]:-}"
  done
}

# Per-destination mutex: link(2) is atomic, so linking a fully written owner
# record creates a lock with no empty-directory initialization window. That
# lets a later installer prove that a local owner PID has exited before it
# reclaims a stale lock. Lock files are held for the entire multi-target
# transaction, including rollback, so a later installer cannot be reverted by
# an earlier transaction that fails on a different destination.
lock_owner_is_dead() {
  local lock_path="$1" contents after_pid owner_pid owner_host owner_token ps_status
  [[ -f "$lock_path" && ! -L "$lock_path" ]] || return 1
  contents="$(<"$lock_path")"
  [[ "$contents" == pid=* ]] || return 1
  after_pid="${contents#pid=}"
  owner_pid="${after_pid%%$'\n'*}"
  after_pid="${after_pid#*$'\n'}"
  [[ "$after_pid" == host=* ]] || return 1
  owner_host="${after_pid#host=}"
  owner_host="${owner_host%%$'\n'*}"
  owner_token="${after_pid#*$'\n'}"
  owner_token="${owner_token#token=}"
  [[ "$contents" == "pid=$owner_pid"$'\n'"host=$owner_host"$'\n'"token=$owner_token" ]] || return 1
  [[ "$owner_pid" =~ ^[1-9][0-9]*$ && -n "$owner_host" && -n "$owner_token" ]] || return 1
  # A lock on another host may be on a shared volume; this installer cannot
  # prove that owner dead, so it leaves the lock intact.
  [[ "$owner_host" == "$lock_host" ]] || return 1
  if kill -0 "$owner_pid" 2>/dev/null; then
    return 1
  fi
  command -v ps >/dev/null 2>&1 || return 1
  ps -p "$owner_pid" -o pid= >/dev/null 2>&1
  ps_status=$?
  # ps returns one only when no matching process exists. Other failures are
  # not proof that reclaiming is safe.
  [[ $ps_status -eq 1 ]]
}
reclaim_stale_lock() {
  local lock_path="$1" original guard current
  [[ -f "$lock_path" && ! -L "$lock_path" ]] || return 1
  original="$(<"$lock_path")"
  lock_owner_is_dead "$lock_path" || return 1
  guard="${lock_path}.reclaim"
  # Only one reclaimer may remove a stale lock. It rechecks the exact owner
  # record after taking this guard so it never unlinks a replacement lock.
  if ! mkdir "$guard" 2>/dev/null; then
    # A guard left behind by a reclaimer that crashed or was killed before its
    # own rmdir would otherwise block reclamation forever, even though the
    # original lock owner is confirmed dead above. Only steal a guard old
    # enough (5+ minutes) that a live reclaimer could not still be inside the
    # short critical section below, then retry exactly once.
    if [[ -n "$(find "$guard" -maxdepth 0 -mmin +5 2>/dev/null)" ]]; then
      rmdir "$guard" 2>/dev/null
      mkdir "$guard" 2>/dev/null || return 1
    else
      return 1
    fi
  fi
  current=""
  if [[ -f "$lock_path" && ! -L "$lock_path" ]]; then
    current="$(<"$lock_path")"
  fi
  if [[ "$current" == "$original" ]] && lock_owner_is_dead "$lock_path"; then
    if rm -- "$lock_path" 2>/dev/null; then
      if ! rmdir "$guard" 2>/dev/null; then
        echo "Cleanup warning: could not release stale-lock reclaim guard $guard" >&2
      fi
      return 0
    fi
  fi
  if ! rmdir "$guard" 2>/dev/null; then
    echo "Cleanup warning: could not release stale-lock reclaim guard $guard" >&2
  fi
  return 1
}
lock_destination() {
  local dest="$1" lock_path owner_path tries=0 link_status
  lock_path="${dest}.install-lock"
  while :; do
    owner_path="$(mktemp "$(dirname -- "$lock_path")/.debug-install-lock-owner.XXXXXX")" || return 2
    printf '%s\n' "$lock_owner" > "$owner_path"
    if ln "$owner_path" "$lock_path" 2>/dev/null; then
      # POSIX ln treats an existing directory as a destination directory. A
      # pre-upgrade directory lock must remain contention; never mistake the
      # link it creates inside that directory for ownership of the lock path.
      if [[ -f "$lock_path" && ! -L "$lock_path" ]]; then
        if ! rm -- "$owner_path" 2>/dev/null; then
          echo "Cleanup warning: could not remove temporary lock owner file $owner_path" >&2
        fi
        acquired_locks+=("$lock_path")
        return 0
      fi
      if [[ -d "$lock_path" ]]; then
        rm -f -- "$lock_path/$(basename -- "$owner_path")"
      fi
      link_status=1
    else
      link_status=$?
    fi
    rm -f -- "$owner_path"
    # A failed link with no existing lock is a real filesystem error (for
    # example, a missing parent), not evidence of another installer.
    if [[ ! -e "$lock_path" && ! -L "$lock_path" ]]; then
      echo "Could not create install lock $lock_path (ln exit $link_status)" >&2
      return 2
    fi
    if reclaim_stale_lock "$lock_path"; then
      continue
    fi
    tries=$((tries + 1))
    if [[ $tries -gt 120 ]]; then
      return 1
    fi
    sleep 0.5
  done
}

# Acquire every lock in a stable order before a destination is backed up or
# committed. Sorting prevents a codex-only installer and a both-target
# installer from deadlocking each other, while the original destination order
# remains intact for result emission and rollback.
while IFS= read -r destination; do
  if ! lock_destination "$destination"; then
    echo "Could not acquire install lock for $destination (another installer is active or lock creation failed)" >&2
    exit 1
  fi
done < <(printf '%s\n' "${destinations[@]}" | LC_ALL=C sort)

idx=0
for destination in "${destinations[@]}"; do
  stage="${stage_paths[$idx]}"
  backup=""
  # Same dangling-symlink gap as the preflight check above: without -L, a
  # dangling symlink at $destination would skip the backup step entirely, so
  # the later mv over it and any subsequent rollback via restore_from_backup
  # (which unconditionally removes $destination) would destroy it with
  # nothing to put back, even though a real backup was never made.
  #
  # Recheck --force at commit time: two concurrent non-force installers can
  # both pass the earlier preflight while the target is absent; after the
  # first commits, the second must refuse rather than back up and replace.
  if [[ -e "$destination" || -L "$destination" ]]; then
    if [[ "$force" != "true" ]]; then
      rollback
      echo "Target exists: $destination. Rerun with --force to preserve it as a backup and replace it." >&2
      exit 1
    fi
    backup="$(unique_backup "$destination")"
    # Guard the backup move: under set -e a bare mv failure in the then-body
    # would exit the script before rollback() runs, leaving previously
    # committed destinations without their backups restored. Handle it
    # explicitly like the staged-tree move below.
    if ! mv -- "$destination" "$backup"; then
      rollback
      echo "Failed to back up $destination" >&2
      exit 1
    fi
  fi
  # Commit: move staged tree into place (atomic rename when same filesystem).
  # If this fails after we already renamed an existing destination to backup,
  # restore that in-flight backup before rolling back prior commits — otherwise
  # the target is left missing while a backup still exists on disk.
  if ! mv -- "$stage" "$destination"; then
    restore_from_backup "$destination" "$backup" true
    rollback
    echo "Failed to install to $destination" >&2
    exit 1
  fi
  # If something recreated $destination as a directory between the backup
  # check above and this mv, POSIX mv nests $stage inside it instead of
  # replacing it or failing, and the commit would silently "succeed" with the
  # payload one level too deep. Detect that nested layout and treat it the
  # same as a failed move.
  if [[ -d "$destination/$(basename -- "$stage")" ]]; then
    if ! rm -rf -- "$destination/$(basename -- "$stage")"; then
      echo "Cleanup warning: could not remove mis-nested stage under $destination" >&2
    fi
    restore_from_backup "$destination" "$backup" true
    rollback
    echo "Failed to install to $destination (destination became a directory during commit)" >&2
    exit 1
  fi
  committed_dests+=("$destination")
  committed_backups+=("$backup")
  idx=$((idx + 1))
done

# Emit results only after every destination has committed. Printing inside
# the loop above would put a target's success record on stdout before later
# targets are known to succeed; if a later commit then failed and rolled
# every committed_dests entry back, that earlier line would already be
# unrecoverably on stdout, letting a consumer that processes result lines
# persist false state for an installation that no longer exists.
for i in "${!committed_dests[@]}"; do
  emit_result "${committed_dests[$i]}" "${committed_backups[$i]}"
done

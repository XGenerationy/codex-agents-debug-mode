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
  [[ -e "$source_dir/$entry" ]] || {
    echo "Missing skill payload entry: $entry" >&2
    exit 1
  }
done

# Preflight all destinations before mutating any of them so multi-target
# installs cannot leave one path updated and another absent/partial.
for destination in "${destinations[@]}"; do
  if [[ -e "$destination" && "$force" != "true" ]]; then
    echo "Target exists: $destination. Rerun with --force to preserve it as a backup and replace it." >&2
    exit 1
  fi
done

unique_backup() {
  local destination="$1"
  local base_ts backup
  base_ts="$(date -u +%Y%m%d%H%M%S)"
  backup="$destination.backup.$base_ts.$$"
  while [[ -e "$backup" ]]; do
    backup="$destination.backup.$base_ts.$$.$RANDOM"
  done
  printf '%s\n' "$backup"
}

# Stage each destination under a sibling temp dir first. Only after every
# staged tree is complete do we commit (backup + replace). On any commit
# failure, restore previously committed destinations from their backups.
stage_root="$(mktemp -d "${TMPDIR:-/tmp}/debug-install-stages.XXXXXX")"
# shellcheck disable=SC2064
trap 'rm -rf -- "$stage_root"' EXIT

declare -a stage_paths=()
for destination in "${destinations[@]}"; do
  parent="$(dirname -- "$destination")"
  mkdir -p -- "$parent"
  stage="$stage_root/$(printf '%s' "$destination" | sed 's/[^A-Za-z0-9._-]/_/g')"
  mkdir -p -- "$stage"
  for entry in "${payload[@]}"; do
    cp -R -- "$source_dir/$entry" "$stage/"
  done
  stage_paths+=("$stage")
done

declare -a committed_dests=()
declare -a committed_backups=()

# Restore a destination from its backup if present (committed or in-flight).
# Best-effort: a rollback step failure is surfaced on stderr but does not abort
# the remaining rollback steps, since the original install error must remain the
# primary failure. rm/mv return non-zero are caught explicitly so set -e does
# not exit the script mid-rollback.
restore_from_backup() {
  local dest="$1" backup="$2"
  if ! rm -rf -- "$dest" 2>/dev/null; then
    echo "Rollback warning: could not remove $dest" >&2
  fi
  if [[ -n "$backup" && -e "$backup" ]]; then
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

idx=0
for destination in "${destinations[@]}"; do
  stage="${stage_paths[$idx]}"
  backup=""
  if [[ -e "$destination" ]]; then
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
    restore_from_backup "$destination" "$backup"
    rollback
    echo "Failed to install to $destination" >&2
    exit 1
  fi
  committed_dests+=("$destination")
  committed_backups+=("$backup")
  emit_result "$destination" "$backup"
  idx=$((idx + 1))
done

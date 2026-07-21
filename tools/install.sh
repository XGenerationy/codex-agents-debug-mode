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

# Stage each destination's payload under a sibling temp dir, then commit only
# after every staged tree is complete. On commit failure, restore backups.
declare -a stage_paths=()
declare -a commit_dests=()
declare -a commit_backups=()
declare -a committed_flags=()

cleanup_stages() {
  local path
  for path in "${stage_paths[@]+"${stage_paths[@]}"}"; do
    [[ -n "$path" && -e "$path" ]] && rm -rf -- "$path"
  done
}

rollback_commits() {
  local i dest backup
  for ((i = ${#commit_dests[@]} - 1; i >= 0; i--)); do
    [[ "${committed_flags[$i]:-}" == "1" ]] || continue
    dest="${commit_dests[$i]}"
    backup="${commit_backups[$i]}"
    rm -rf -- "$dest" 2>/dev/null || true
    if [[ -n "$backup" && -e "$backup" ]]; then
      mv -- "$backup" "$dest" 2>/dev/null || true
    fi
  done
}

trap 'rollback_commits; cleanup_stages' ERR
trap 'cleanup_stages' EXIT

for destination in "${destinations[@]}"; do
  parent="$(dirname -- "$destination")"
  mkdir -p -- "$parent"
  stage="$parent/.debug-install-stage.$(date -u +%Y%m%d%H%M%S).$$.${#stage_paths[@]}"
  rm -rf -- "$stage"
  mkdir -p -- "$stage"
  for entry in "${payload[@]}"; do
    cp -R -- "$source_dir/$entry" "$stage/"
  done
  stage_paths+=("$stage")
  commit_dests+=("$destination")
  commit_backups+=("")
  committed_flags+=("0")
done

for i in "${!commit_dests[@]}"; do
  destination="${commit_dests[$i]}"
  stage="${stage_paths[$i]}"
  backup=""
  if [[ -e "$destination" ]]; then
    backup="$(unique_backup "$destination")"
    mv -- "$destination" "$backup"
  fi
  mv -- "$stage" "$destination"
  stage_paths[$i]=""
  commit_backups[$i]="$backup"
  committed_flags[$i]="1"
  emit_result "$destination" "$backup"
done

# Successful path: clear ERR rollback; EXIT still cleans any leftover stages.
trap - ERR

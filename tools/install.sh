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

for entry in "${payload[@]}"; do
  [[ -e "$source_dir/$entry" ]] || {
    echo "Missing skill payload entry: $entry" >&2
    exit 1
  }
done

for destination in "${destinations[@]}"; do
  backup=""
  if [[ -e "$destination" ]]; then
    if [[ "$force" != "true" ]]; then
      echo "Target exists: $destination. Rerun with --force to preserve it as a backup and replace it." >&2
      exit 1
    fi
    backup="$destination.backup.$(date -u +%Y%m%d%H%M%S)"
    mv -- "$destination" "$backup"
  fi

  mkdir -p -- "$destination"
  for entry in "${payload[@]}"; do
    cp -R -- "$source_dir/$entry" "$destination/"
  done
  dest_json="${destination//\\/\\\\}"
  dest_json="${dest_json//\"/\\\"}"
  backup_json="${backup//\\/\\\\}"
  backup_json="${backup_json//\"/\\\"}"
  printf '{"status":"installed","target":"%s","backup":"%s"}\n' "$dest_json" "$backup_json"
done

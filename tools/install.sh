#!/usr/bin/env bash
set -euo pipefail

target="both"
force="false"
home_path="${HOME}"

while (($#)); do
  case "$1" in
    --target)
      target="${2:-}"
      shift 2
      ;;
    --force)
      force="true"
      shift
      ;;
    --home)
      home_path="${2:-}"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

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
  printf '{"status":"installed","target":"%s","backup":"%s"}\n' "$destination" "$backup"
done

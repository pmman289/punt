#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
version_file=${VERSION_FILE:-"$root_dir/VERSION"}

if [[ ! -f "$version_file" ]]; then
  printf 'VERSION file not found: %s\n' "$version_file" >&2
  exit 1
fi

version=$(tr -d '[:space:]' < "$version_file")
if [[ ! "$version" =~ ^([0-9]+)\.([0-9])\.([0-9])a$ ]]; then
  printf 'invalid version %q; expected MAJOR.MINOR.PATCHa with single-digit MINOR/PATCH\n' "$version" >&2
  exit 1
fi

major=${BASH_REMATCH[1]}
minor=${BASH_REMATCH[2]}
patch=${BASH_REMATCH[3]}

if ((patch < 9)); then
  ((patch += 1))
else
  patch=0
  if ((minor < 9)); then
    ((minor += 1))
  else
    minor=0
    ((major += 1))
  fi
fi

next_version="${major}.${minor}.${patch}a"
printf '%s\n' "$next_version" > "$version_file"
printf 'VERSION: %s -> %s\n' "$version" "$next_version"

#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
version_file="$root_dir/VERSION"
output_root="$root_dir/dist"
cd "$root_dir"

if [[ ! -f "$version_file" ]]; then
  printf 'VERSION file not found: %s\n' "$version_file" >&2
  exit 1
fi

version=$(tr -d '[:space:]' < "$version_file")
if [[ ! "$version" =~ ^[0-9]+\.[0-9]\.[0-9]a$ ]]; then
  printf 'invalid version %q; expected MAJOR.MINOR.PATCHa with single-digit MINOR/PATCH\n' "$version" >&2
  exit 1
fi

if ! command -v go >/dev/null; then
  printf 'go is required to build a release\n' >&2
  exit 1
fi
if ! command -v git >/dev/null || ! command -v sha256sum >/dev/null || ! command -v tar >/dev/null; then
  printf 'git, sha256sum and tar are required to build a release\n' >&2
  exit 1
fi

if ! git -C "$root_dir" rev-parse --verify HEAD >/dev/null 2>&1; then
  printf 'release builds require a Git repository with at least one commit\n' >&2
  exit 1
fi
if [[ -n $(git -C "$root_dir" status --porcelain --untracked-files=all) ]]; then
  printf 'release builds require a clean Git worktree; commit or remove pending files first\n' >&2
  exit 1
fi

output_dir="$output_root/v$version"
if [[ -e "$output_dir" ]]; then
  printf 'release output already exists: %s\n' "$output_dir" >&2
  exit 1
fi

commit=$(git -C "$root_dir" rev-parse HEAD)

staging_dir=$(mktemp -d)
trap 'rm -rf "$staging_dir"' EXIT
package_root="$staging_dir/packages"
work_output="$staging_dir/release"
mkdir -p "$package_root" "$work_output"

build_target() {
  local goarch=$1
  local artifact_arch=$2
  local goarm=${3:-}
  local package_dir="$package_root/punt_${version}_linux_${artifact_arch}"
  local binary="$package_dir/punt"
  local archive="$work_output/punt_${version}_linux_${artifact_arch}.tar.gz"

  mkdir -p "$package_dir"
  if [[ -n "$goarm" ]]; then
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM="$goarm" \
      go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=$version" \
      -o "$binary" ./cmd/punt
  else
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
      go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=$version" \
      -o "$binary" ./cmd/punt
  fi
  cp "$root_dir/LICENSE" "$package_dir/LICENSE"
  cp "$root_dir/README.md" "$package_dir/README.md"
  printf 'Punt %s\nTarget: linux/%s\nCommit: %s\n' "$version" "$artifact_arch" "$commit" > "$package_dir/RELEASE.txt"
  tar -C "$package_root" -czf "$archive" "punt_${version}_linux_${artifact_arch}"
}

build_target amd64 amd64
build_target arm64 arm64
build_target arm armv7 7

git -C "$root_dir" archive --format=tar.gz --prefix="punt_${version}/" HEAD > "$work_output/punt_${version}_source.tar.gz"

(
  cd "$work_output"
  sha256sum ./*.tar.gz > SHA256SUMS
)

mkdir -p "$output_root"
mv "$work_output" "$output_dir"
printf 'release artifacts written to %s\n' "$output_dir"
find "$output_dir" -maxdepth 1 -type f -printf '%f\n' | sort

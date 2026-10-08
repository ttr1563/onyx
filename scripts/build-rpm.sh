#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: scripts/build-rpm.sh VERSION [OUTPUT_ROOT]}"
output_root="${2:-dist/rpm/al2023}"
repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
output_root="$(realpath -m "$output_root")"
case "$output_root" in
  "$repository_root/docs/rpm/al2023" | "$repository_root/dist"/*) ;;
  *)
    echo "output root must be docs/rpm/al2023 or a path below dist" >&2
    exit 1
    ;;
esac

manifest_version="$(awk -F '"' '/^version = "/ { print $2; exit }' Cargo.toml)"
if [[ "$version" != "$manifest_version" ]]; then
  echo "version $version does not match Cargo.toml $manifest_version" >&2
  exit 1
fi
if [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  :
else
  echo "version must use MAJOR.MINOR.PATCH format" >&2
  exit 1
fi
for command in cargo realpath rpmbuild rpm; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 1
  }
done

architecture="$(rpm --eval '%{_target_cpu}')"
case "$architecture" in
  x86_64 | aarch64) ;;
  *)
    echo "unsupported RPM architecture: $architecture" >&2
    exit 1
    ;;
esac

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
topdir="$temporary/rpmbuild"
mkdir -p "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

cargo build --release --locked
install -m0755 target/release/onyx "$topdir/SOURCES/onyx"
install -m0644 LICENSE "$topdir/SOURCES/LICENSE"
install -m0644 README.md "$topdir/SOURCES/README.md"
install -m0644 docs/operations.md "$topdir/SOURCES/operations.md"
install -m0644 ops/logrotate/onyx "$topdir/SOURCES/onyx.logrotate"
install -m0644 packaging/rpm/onyx.spec "$topdir/SPECS/onyx.spec"

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  rpmbuild \
    --define "_topdir $topdir" \
    --define "onyx_version $version" \
    --define "_build_id_links none" \
    -bb "$topdir/SPECS/onyx.spec"

package_dir="$output_root/$architecture/Packages"
mkdir -p "$package_dir"
find "$topdir/RPMS/$architecture" -maxdepth 1 -type f -name 'onyx-*.rpm' \
  -exec install -m0644 {} "$package_dir/" \;

package="$(find "$package_dir" -maxdepth 1 -type f -name "onyx-${version}-*.${architecture}.rpm" -print -quit)"
if [[ -z "$package" ]]; then
  echo "RPM output was not created" >&2
  exit 1
fi
rpm --checksig "$package"
sha256sum "$package"

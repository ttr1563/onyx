#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: scripts/build-deb.sh VERSION [OUTPUT_ROOT]}"
output_root="${2:-dist/deb}"
repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
output_root="$(realpath -m "$output_root")"
case "$output_root" in
  "$repository_root/docs/apt/pool/main/o/onyx" | "$repository_root/dist"/*) ;;
  *)
    echo "output root must be docs/apt/pool/main/o/onyx or a path below dist" >&2
    exit 1
    ;;
esac

manifest_version="$(awk -F '"' '/^version = "/ { print $2; exit }' Cargo.toml)"
if [[ "$version" != "$manifest_version" ]]; then
  echo "version $version does not match Cargo.toml $manifest_version" >&2
  exit 1
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "version must use MAJOR.MINOR.PATCH format" >&2
  exit 1
fi
for command in ar awk cargo du find gzip install md5sum realpath sort tar uname xargs; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 1
  }
done
if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "the initial Debian package must be built on x86_64" >&2
  exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
package_root="$temporary/package"
mkdir -p \
  "$package_root/etc/logrotate.d" \
  "$package_root/usr/bin" \
  "$package_root/usr/share/doc/onyx"

cargo build --release --locked
install -m0755 target/release/onyx "$package_root/usr/bin/onyx"
install -m0644 ops/logrotate/onyx "$package_root/etc/logrotate.d/onyx"
install -m0644 LICENSE "$package_root/usr/share/doc/onyx/copyright"
gzip -9 -n -c README.md > "$package_root/usr/share/doc/onyx/README.md.gz"
gzip -9 -n -c docs/operations.md > "$package_root/usr/share/doc/onyx/operations.md.gz"

installed_size="$(du -sk --apparent-size "$package_root" | awk '{ print $1 }')"
cat > "$temporary/control" <<EOF
Package: onyx
Version: ${version}-1
Architecture: amd64
Maintainer: Onyx maintainers <ttr1563@users.noreply.github.com>
Installed-Size: ${installed_size}
Depends: libc6 (>= 2.34), libgcc-s1
Section: admin
Priority: optional
Homepage: https://ttr1563.github.io/onyx/
Description: lightweight command guard for Linux servers
 Onyx evaluates commands before execution, blocks selected high-risk patterns,
 requires a one-time TOTP approval, and writes redacted local JSONL audit logs.
EOF
printf '/etc/logrotate.d/onyx\n' > "$temporary/conffiles"
(
  cd "$package_root"
  find . -type f -printf '%P\0' | sort -z | xargs -0 md5sum
) > "$temporary/md5sums"
printf '2.0\n' > "$temporary/debian-binary"

source_date_epoch="${SOURCE_DATE_EPOCH:-0}"
tar \
  --sort=name \
  --owner=0 --group=0 --numeric-owner \
  --mtime="@${source_date_epoch}" \
  -C "$temporary" \
  -czf "$temporary/control.tar.gz" control conffiles md5sums
tar \
  --sort=name \
  --owner=0 --group=0 --numeric-owner \
  --mtime="@${source_date_epoch}" \
  -C "$package_root" \
  -czf "$temporary/data.tar.gz" .

mkdir -p "$output_root"
package="$output_root/onyx_${version}-1_amd64.deb"
rm -f "$package"
(
  cd "$temporary"
  ar rcs "$package" debian-binary control.tar.gz data.tar.gz
)

ar t "$package"
sha256sum "$package"

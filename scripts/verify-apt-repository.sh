#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
repository_path="${1:-docs/apt}"
repository_path="$(realpath -m "$repository_path")"
case "$repository_path" in
  "$repository_root/docs/apt" | "$repository_root/dist"/*) ;;
  *)
    echo "repository path must be docs/apt or a path below dist" >&2
    exit 1
    ;;
esac

for command in ar awk cmp find gpg gzip realpath sha256sum sort stat tail tar; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 1
  }
done
test -s "$repository_path/onyx.asc"
test -s "$repository_path/onyx.sources"
test -s "$repository_path/SHA256SUMS"
test -s "$repository_path/SHA256SUMS.asc"
test -s "$repository_path/dists/stable/InRelease"
test -s "$repository_path/dists/stable/Release"
test -s "$repository_path/dists/stable/Release.gpg"
test -s "$repository_path/dists/stable/main/binary-amd64/Packages"
test -s "$repository_path/dists/stable/main/binary-amd64/Packages.gz"

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
chmod 0700 "$temporary"
GNUPGHOME="$temporary" gpg --batch --import "$repository_path/onyx.asc" >/dev/null 2>&1
GNUPGHOME="$temporary" gpg --batch --verify \
  "$repository_path/dists/stable/InRelease"
GNUPGHOME="$temporary" gpg --batch --verify \
  "$repository_path/dists/stable/Release.gpg" \
  "$repository_path/dists/stable/Release"
GNUPGHOME="$temporary" gpg --batch --verify \
  "$repository_path/SHA256SUMS.asc" \
  "$repository_path/SHA256SUMS"
(
  cd "$repository_path"
  sha256sum --check SHA256SUMS
)
gzip -cd "$repository_path/dists/stable/main/binary-amd64/Packages.gz" \
  | cmp - "$repository_path/dists/stable/main/binary-amd64/Packages"

package="$(find "$repository_path/pool/main/o/onyx" -maxdepth 1 -type f -name 'onyx_*_amd64.deb' -print | sort -V | tail -n 1)"
test -n "$package"
expected_hash="$(awk '/^SHA256: / { print $2; exit }' "$repository_path/dists/stable/main/binary-amd64/Packages")"
expected_size="$(awk '/^Size: / { print $2; exit }' "$repository_path/dists/stable/main/binary-amd64/Packages")"
test "$(sha256sum "$package" | awk '{ print $1 }')" = "$expected_hash"
test "$(stat -c %s "$package")" = "$expected_size"

members="$(ar t "$package")"
test "$members" = $'debian-binary\ncontrol.tar.gz\ndata.tar.gz'
(
  cd "$temporary"
  ar x "$package"
  test "$(cat debian-binary)" = "2.0"
  tar -tzf control.tar.gz | grep -Fx control >/dev/null
  tar -tzf control.tar.gz | grep -Fx md5sums >/dev/null
  tar -tzf data.tar.gz | grep -Fx ./usr/bin/onyx >/dev/null
  tar -xzf data.tar.gz ./usr/bin/onyx
  ./usr/bin/onyx --version
  set +e
  ./usr/bin/onyx check -- rm -rf /example >/dev/null
  status=$?
  set -e
  test "$status" -eq 77
)

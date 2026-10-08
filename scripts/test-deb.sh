#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
version="${1:?usage: scripts/test-deb.sh VERSION [PACKAGE_ROOT]}"
repository_path="${2:-dist/deb}"
repository_path="$(realpath -m "$repository_path")"
case "$repository_path" in
  "$repository_root/dist"/*) ;;
  *)
    echo "package root must be below dist" >&2
    exit 1
    ;;
esac

for command in ar grep tar uname; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 1
  }
done

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "the Debian package must be tested natively on Linux" >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64) deb_architecture="amd64" ;;
  aarch64) deb_architecture="arm64" ;;
  *)
    echo "unsupported Debian package architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

package="$repository_path/osmanthus_${version}-1_${deb_architecture}.deb"
test -s "$package"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
(
  cd "$temporary"
  ar x "$package"
)
test "$(<"$temporary/debian-binary")" = "2.0"
tar -xzf "$temporary/control.tar.gz" -C "$temporary"
tar -xzf "$temporary/data.tar.gz" -C "$temporary"
grep -Fx "Package: osmanthus" "$temporary/control"
grep -Fx "Version: ${version}-1" "$temporary/control"
grep -Fx "Architecture: $deb_architecture" "$temporary/control"
grep -Fx "Conflicts: onyx" "$temporary/control"
grep -Fq "/sys/fs/bpf/osmanthus" "$temporary/prerm"
grep -Fq "/usr/bin/osmanthus-shell" "$temporary/prerm"
test -x "$temporary/usr/bin/osmanthus"
test -x "$temporary/usr/bin/osmanthusd"
test -x "$temporary/usr/bin/osmanthus-shell"
test -s "$temporary/lib/systemd/system/osmanthusd.service"
test -s "$temporary/etc/logrotate.d/osmanthus"
test -s "$temporary/usr/share/doc/osmanthus/ssm.md.gz"
gzip -cd "$temporary/usr/share/doc/osmanthus/README.md.gz" | grep -Fq "caller cgroup"
gzip -cd "$temporary/usr/share/doc/osmanthus/operations.md.gz" | grep -Fq "dedicated transient systemd service"
test -s "$temporary/usr/share/osmanthus/ssm/osmanthus-session.json"
"$temporary/usr/bin/osmanthus" --version | grep -Fx "osmanthus $version"
"$temporary/usr/bin/osmanthus" daemon --help | grep -F decommission
"$temporary/usr/bin/osmanthus" maintenance --help | grep -F grant
"$temporary/usr/bin/osmanthus" maintenance --help | grep -F pause
"$temporary/usr/bin/osmanthus" policy maintenance set --help | grep -F -- --maximum
"$temporary/usr/bin/osmanthus" policy protect add --help | grep -F write
"$temporary/usr/bin/osmanthus" policy auth --help | grep -F rotate
set +e
"$temporary/usr/bin/osmanthus" check -- rm -rf /example >/dev/null 2>&1
status=$?
set -e
if [[ "$status" -ne 77 ]]; then
  echo "blocked command check returned unexpected status: $status" >&2
  exit 1
fi

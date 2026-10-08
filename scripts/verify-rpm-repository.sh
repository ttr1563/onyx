#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

repository_path="${1:-docs/rpm/al2023/$(rpm --eval '%{_target_cpu}')}"
key_file="${2:-docs/rpm/RPM-GPG-KEY-ONYX}"
for command in dnf gpg rpm; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 1
  }
done

test -s "$repository_path/repodata/repomd.xml"
test -s "$repository_path/repodata/repomd.xml.asc"
test -s "$key_file"
repository_root_path="$(dirname "$(dirname "$repository_path")")"
test -s "$repository_root_path/SHA256SUMS"
test -s "$repository_root_path/SHA256SUMS.asc"

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
chmod 0700 "$temporary"
GNUPGHOME="$temporary" gpg --batch --import "$key_file" >/dev/null 2>&1
GNUPGHOME="$temporary" gpg --batch --verify \
  "$repository_path/repodata/repomd.xml.asc" \
  "$repository_path/repodata/repomd.xml"
GNUPGHOME="$temporary" gpg --batch --verify \
  "$repository_root_path/SHA256SUMS.asc" \
  "$repository_root_path/SHA256SUMS"
(
  cd "$repository_root_path"
  sha256sum --check SHA256SUMS
)

absolute_repository="$(realpath "$repository_path")"
absolute_key="$(realpath "$key_file")"
dnf \
  --installroot "$temporary/dnf-root" \
  --releasever 2023 \
  --disablerepo='*' \
  --repofrompath "onyx,file://$absolute_repository" \
  --enablerepo onyx \
  --setopt="onyx.gpgkey=file://$absolute_key" \
  --setopt=onyx.gpgcheck=1 \
  --setopt=onyx.repo_gpgcheck=1 \
  --setopt="cachedir=$temporary/dnf-cache" \
  --setopt=persistdir="$temporary/dnf-persist" \
  --refresh -y makecache

verification_db="$temporary/rpmdb"
mkdir -p "$verification_db"
rpm --dbpath "$verification_db" --initdb
rpm --dbpath "$verification_db" --import "$key_file"

for package in "$repository_path"/Packages/*.rpm; do
  rpm --dbpath "$verification_db" --checksig "$package"
  rpm --dbpath "$verification_db" --query --package "$package" --queryformat '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n'
  rpm --dbpath "$verification_db" --query --package "$package" --list >/dev/null
done

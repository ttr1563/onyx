#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

output_root="${1:-docs/rpm}"
output_root="$(realpath -m "$output_root")"
case "$output_root" in
  "$repository_root/docs/rpm" | "$repository_root/dist"/*) ;;
  *)
    echo "output root must be docs/rpm or a path below dist" >&2
    exit 1
    ;;
esac
key_file="${ONYX_GPG_PUBLIC_KEY:-packaging/rpm/RPM-GPG-KEY-ONYX}"
signing_key="${ONYX_GPG_KEY_ID:-}"
gpg_home="${ONYX_GPG_HOME:-}"
passphrase_file="${ONYX_GPG_PASSPHRASE_FILE:-}"

for command in createrepo_c gpg realpath rpm rpmbuild; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 1
  }
done
if [[ ! -s "$key_file" ]]; then
  echo "public signing key not found: $key_file" >&2
  exit 1
fi
if [[ -z "$signing_key" || -z "$gpg_home" ]]; then
  echo "ONYX_GPG_KEY_ID and ONYX_GPG_HOME are required" >&2
  exit 1
fi

architecture="$(rpm --eval '%{_target_cpu}')"
package_dir="$output_root/al2023/$architecture/Packages"
if ! find "$package_dir" -maxdepth 1 -type f -name 'onyx-[0-9]*.rpm' -print -quit | grep -q .; then
  echo "Onyx package not found under $package_dir" >&2
  exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
topdir="$temporary/rpmbuild"
mkdir -p "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
install -m0644 packaging/rpm/onyx.repo "$topdir/SOURCES/onyx.repo"
install -m0644 "$key_file" "$topdir/SOURCES/RPM-GPG-KEY-ONYX"
install -m0644 packaging/rpm/onyx-release.spec "$topdir/SPECS/onyx-release.spec"
rpmbuild --define "_topdir $topdir" -bb "$topdir/SPECS/onyx-release.spec"
install -m0644 "$topdir"/RPMS/noarch/onyx-release-*.noarch.rpm "$package_dir/"

signing_arguments=(
  --define "_gpg_name $signing_key"
  --define "_gpg_path $gpg_home"
)
gpg_arguments=(--batch --yes --local-user "$signing_key")
verification_db="$temporary/rpmdb"
mkdir -p "$verification_db"
rpm --dbpath "$verification_db" --initdb
rpm --dbpath "$verification_db" --import "$key_file"
if [[ -n "$passphrase_file" ]]; then
  if [[ ! -r "$passphrase_file" ]]; then
    echo "GPG passphrase file is not readable" >&2
    exit 1
  fi
  signing_arguments+=(
    --define "_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback --passphrase-file $passphrase_file"
  )
  gpg_arguments+=(--pinentry-mode loopback --passphrase-file "$passphrase_file")
fi

for package in "$package_dir"/*.rpm; do
  GNUPGHOME="$gpg_home" rpmsign "${signing_arguments[@]}" --addsign "$package"
  rpm --dbpath "$verification_db" --checksig "$package"
done

metadata_root="$temporary/repository"
mkdir -p "$metadata_root/Packages"
cp -p "$package_dir"/*.rpm "$metadata_root/Packages/"
createrepo_c --checksum sha256 --workers 1 "$metadata_root"
GNUPGHOME="$gpg_home" gpg "${gpg_arguments[@]}" \
  --armor --detach-sign "$metadata_root/repodata/repomd.xml"

rm -rf "$output_root/al2023/$architecture/repodata"
cp -a "$metadata_root/repodata" "$output_root/al2023/$architecture/repodata"
install -m0644 "$key_file" "$output_root/RPM-GPG-KEY-ONYX"
install -m0644 "$package_dir"/onyx-release-*.noarch.rpm \
  "$output_root/onyx-release-1-1.noarch.rpm"

(
  cd "$output_root"
  sha256sum \
    RPM-GPG-KEY-ONYX \
    onyx-release-1-1.noarch.rpm \
    "al2023/$architecture/Packages/"*.rpm \
    "al2023/$architecture/repodata/repomd.xml" > SHA256SUMS
)
GNUPGHOME="$gpg_home" gpg "${gpg_arguments[@]}" \
  --armor --detach-sign "$output_root/SHA256SUMS"

sha256sum "$package_dir"/*.rpm "$output_root/onyx-release-1-1.noarch.rpm"

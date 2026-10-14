#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
version="$(cd "$root" && python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
revision=1
package_root="$(mktemp -d)"
output="$root/dist/greylog_${version}-${revision}_all.deb"

cleanup() {
  rm -rf "$package_root"
}
trap cleanup EXIT

mkdir -p "$root/dist"
cp -a "$root/packaging/debian/DEBIAN" "$package_root/"
cp -a "$root/packaging/debian/usr" "$package_root/"
sed -i 's/\r$//' "$package_root/usr/bin/greylog"
sed -i "s/^Version:.*/Version: ${version}-${revision}/" "$package_root/DEBIAN/control"
mkdir -p "$package_root/usr/lib/python3/dist-packages"
cp -a "$root/greylog" "$package_root/usr/lib/python3/dist-packages/"
cp "$root/README.md" "$root/LICENSE" "$root/NOTICE" "$package_root/usr/share/doc/greylog/"
gzip -n -9 "$package_root/usr/share/doc/greylog/changelog"
find "$package_root" -type d -exec chmod 0755 {} +
find "$package_root" -type f -exec chmod 0644 {} +
find "$package_root/usr/lib/python3/dist-packages/greylog" -type d -name __pycache__ -prune -exec rm -rf {} +
chmod 0755 "$package_root/DEBIAN/postinst" "$package_root/usr/bin/greylog"
chmod 0644 "$package_root/DEBIAN/control" "$package_root/usr/share/doc/greylog/"{README.md,LICENSE,NOTICE,copyright,changelog.gz}

dpkg-deb --root-owner-group --build "$package_root" "$output"
dpkg-deb --info "$output"
dpkg-deb --contents "$output"

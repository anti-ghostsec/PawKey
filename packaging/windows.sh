#!/bin/sh
# Makes dist/PawKey-VERSION-windows-x86_64.zip: pawkey.exe with GTK 4 and
# everything it needs from MSYS2 (UCRT64) beside it, so it runs on a Windows
# without anything installed. Run in an MSYS2 UCRT64 shell after
# `cargo build --release`:
#
#   packaging/windows.sh VERSION
#
# GTK finds its pieces relative to the folder pawkey.exe is in: lib/ for
# image loaders and TLS (glib-networking, for sync), share/ for icons and
# settings schemas.

set -eu
version=$1
prefix=${MINGW_PREFIX:-/ucrt64}
out=dist/PawKey
rm -rf dist
mkdir -p "$out/lib/gio/modules" "$out/share/glib-2.0" "$out/share/icons/hicolor/scalable/apps"

cp target/release/pawkey.exe "$out/"
cp README.md LICENSE-MIT LICENSE-APACHE "$out/"
cp -r "$prefix/lib/gdk-pixbuf-2.0" "$out/lib/"
cp "$prefix"/lib/gio/modules/*.dll "$out/lib/gio/modules/"
cp -r "$prefix/share/glib-2.0/schemas" "$out/share/glib-2.0/"
glib-compile-schemas "$out/share/glib-2.0/schemas"
cp -r "$prefix/share/icons/Adwaita" "$out/share/icons/"
cp -r "$prefix/share/icons/hicolor" "$out/share/icons/" 2>/dev/null || true
cp icons/pawkey.svg "$out/share/icons/hicolor/scalable/apps/"
gtk4-update-icon-cache -q -t -f "$out/share/icons/hicolor" 2>/dev/null || true

# The image loaders' list, with paths relative to the folder, not to MSYS2.
cache=$out/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache
sed -i "s|$(cygpath -m "$prefix")/||g; s|$prefix/||g" "$cache"

# Every DLL the program, the loaders and the GIO modules need, from MSYS2.
deps() { ldd "$@" | awk -v p="$prefix/" 'index($3, p) == 1 { print $3 }' | sort -u; }
for dll in $(deps "$out/pawkey.exe" "$out"/lib/gdk-pixbuf-2.0/2.10.0/loaders/*.dll "$out"/lib/gio/modules/*.dll); do
    cp -n "$dll" "$out/"
done

(cd dist && zip -qr "PawKey-$version-windows-x86_64.zip" PawKey)
ls -la "dist/PawKey-$version-windows-x86_64.zip"

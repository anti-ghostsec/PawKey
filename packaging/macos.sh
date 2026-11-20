#!/bin/sh
# Makes dist/PawKey-VERSION-macos-arm64.zip: PawKey.app with GTK 4 and
# everything it needs from Homebrew inside it. Run on a Mac after
# `cargo build --release`, with Homebrew's gtk4, libsoup, glib-networking,
# librsvg, adwaita-icon-theme and dylibbundler installed:
#
#   packaging/macos.sh VERSION
#
# The app isn't signed by a developer ID (it's signed ad hoc, which Apple
# Silicon requires to run at all), so macOS asks before opening it the first
# time: right-click it and choose Open.

set -eu
version=$1
brew=$(brew --prefix)
app=dist/PawKey.app
c=$app/Contents
res=$c/Resources
rm -rf dist
mkdir -p "$c/MacOS" "$res/lib/gdk-pixbuf/loaders" "$res/lib/gio/modules" "$res/share/glib-2.0" "$res/share/icons/hicolor/scalable/apps"

cp target/release/pawkey "$c/MacOS/pawkey-bin"
cp "$brew/bin/gdk-pixbuf-query-loaders" "$c/MacOS/"
find "$brew/lib/gdk-pixbuf-2.0" "$(brew --prefix librsvg)/lib/gdk-pixbuf-2.0" -name '*.so' -path '*loaders*' -exec cp {} "$res/lib/gdk-pixbuf/loaders/" \;
cp "$(brew --prefix glib-networking)"/lib/gio/modules/*.so "$res/lib/gio/modules/"
cp -r "$brew/share/glib-2.0/schemas" "$res/share/glib-2.0/"
glib-compile-schemas "$res/share/glib-2.0/schemas"
cp -r "$(brew --prefix adwaita-icon-theme)/share/icons/Adwaita" "$res/share/icons/"
cp icons/pawkey.svg "$res/share/icons/hicolor/scalable/apps/"
cp README.md LICENSE-MIT LICENSE-APACHE "$res/"

# The launcher: tells GTK where its pieces are inside the app.
cat > "$c/MacOS/PawKey" <<'SH'
#!/bin/sh
here=$(cd "$(dirname "$0")" && pwd)
res="$here/../Resources"
export XDG_DATA_DIRS="$res/share"
export GSETTINGS_SCHEMA_DIR="$res/share/glib-2.0/schemas"
export GIO_MODULE_DIR="$res/lib/gio/modules"
cache="${TMPDIR:-/tmp}/pawkey-loaders.cache"
if "$here/gdk-pixbuf-query-loaders" "$res"/lib/gdk-pixbuf/loaders/*.so >"$cache" 2>/dev/null; then
    export GDK_PIXBUF_MODULE_FILE="$cache"
fi
exec "$here/pawkey-bin" "$@"
SH
chmod +x "$c/MacOS/PawKey"

# Every Homebrew library they need, copied in and pointed at.
set -- -x "$c/MacOS/pawkey-bin" -x "$c/MacOS/gdk-pixbuf-query-loaders"
for f in "$res"/lib/gdk-pixbuf/loaders/*.so "$res"/lib/gio/modules/*.so; do set -- "$@" -x "$f"; done
# Libraries named by @rpath are looked for in Homebrew's folders. If one
# still can't be found, dylibbundler asks for its folder on the terminal;
# answering "quit" makes it fail instead of waiting forever.
set -- "$@" -s "$brew/lib"
for d in "$brew"/opt/*/lib; do set -- "$@" -s "$d"; done
yes quit | dylibbundler -of -b "$@" -d "$res/libs" -p @executable_path/../Resources/libs/

# The icon.
set_dir=$(mktemp -d)/pawkey.iconset
mkdir -p "$set_dir"
for s in 16 32 128 256 512; do
    rsvg-convert -w $s -h $s icons/pawkey.svg >"$set_dir/icon_${s}x${s}.png"
    rsvg-convert -w $((s * 2)) -h $((s * 2)) icons/pawkey.svg >"$set_dir/icon_${s}x${s}@2x.png"
done
iconutil -c icns -o "$res/pawkey.icns" "$set_dir"

cat > "$c/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>PawKey</string>
    <key>CFBundleDisplayName</key><string>PawKey</string>
    <key>CFBundleIdentifier</key><string>io.github.anti_ghostsec.PawKey</string>
    <key>CFBundleExecutable</key><string>PawKey</string>
    <key>CFBundleIconFile</key><string>pawkey</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$version</string>
    <key>CFBundleVersion</key><string>$version</string>
    <key>LSMinimumSystemVersion</key><string>12.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

codesign --force --deep --sign - "$app"
(cd dist && ditto -c -k --keepParent PawKey.app "PawKey-$version-macos-arm64.zip")
ls -la "dist/PawKey-$version-macos-arm64.zip"

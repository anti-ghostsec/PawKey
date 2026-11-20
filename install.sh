#!/bin/sh
# Builds PawKey and adds it for the current user only: the program in
# ~/.local/bin and a Start menu entry. Nothing is installed system-wide.
# ./install.sh --uninstall removes it (but never your vault: see the README).
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$HOME/.local/bin"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
APPS="$DATA/applications"
ICONS="$DATA/icons/hicolor/scalable/apps"

if [ "$1" = "--uninstall" ]; then
    rm -f "$BIN/pawkey" "$APPS/pawkey.desktop" "$ICONS/pawkey.svg"
    update-desktop-database "$APPS" 2>/dev/null || true
    echo "PawKey removed. Your vault is still in $DATA/pawkey."
    exit 0
fi

# A release download has the program ready-made; from the source, it's built.
if [ -x "$DIR/pawkey" ]; then
    PROGRAM="$DIR/pawkey"
else
    command -v cargo >/dev/null || { echo "PawKey needs cargo first, to build it." >&2; exit 1; }
    pkg-config --exists gtk4 libsoup-3.0 2>/dev/null ||
        echo "Note: building needs the development files of GTK 4 and libsoup 3 (libgtk-4-dev libsoup-3.0-dev on Debian)." >&2
    (cd "$DIR" && cargo build --release --locked)
    PROGRAM="$DIR/target/release/pawkey"
fi

mkdir -p "$BIN" "$APPS" "$ICONS"
install -m 0755 "$PROGRAM" "$BIN/pawkey"
cp "$DIR/icons/pawkey.svg" "$ICONS/pawkey.svg"

cat > "$APPS/pawkey.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=PawKey
GenericName=Authenticator
Comment=Two-factor codes, kept in an encrypted vault
Exec=$BIN/pawkey
Icon=pawkey
Terminal=false
Categories=Utility;Security;
Keywords=2FA;TOTP;OTP;authenticator;two-factor;
StartupWMClass=pawkey
DESK

update-desktop-database "$APPS" 2>/dev/null || true
echo "PawKey added: open it from the Start menu."

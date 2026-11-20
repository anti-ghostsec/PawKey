# PawKey

Two-factor codes (the six digits a site asks for after your password),
kept in a vault that's encrypted with your password and any keyfiles, on
Linux, Windows, macOS and Android. Works with any site that offers an
"authenticator app": GitHub, Google, Proton, Discord, your bank, and so
on. Written in Rust: one core everywhere, a GTK 4 window on the desktops
and a Kotlin app on Android, the way Wisp is built.

> **Heads up:** PawKey is new and hasn't had a security audit. The codes
> are checked against the RFC test values, and the vault, sync and the
> Linux window have been tested, but it hasn't been used day to day yet.
> The Windows and macOS builds are made by GitHub Actions and haven't been
> run by anyone yet. See [What it doesn't do yet](#what-it-doesnt-do-yet).

## How it works

```
 ┌───────────────────────────────────────────────┐
 │ pawkey (GTK 4 window)                         │
 │  password + keyfiles ── Argon2id → key        │   ~/.local/share/pawkey/
 │  accounts ── XChaCha20-Poly1305 ──────────────┼──▶ pawkey.vault
 │  codes ── TOTP (RFC 6238), every second       │   (random bytes without
 │  QR codes ── read from a picture, offline     │    the password)
 │  sync (off unless turned on) ── AES-256-GCM ──┼──▶ xBrowserSync service
 └───────────────────────────────────────────────┘   (Wisp's sync)
```

- **Codes are made on this PC**, from each account's secret and the clock,
  as every authenticator app does. Nothing goes over the network unless
  you turn [sync](#sync) on.
- **Setup QR codes** are read from a picture: a screenshot of the site's
  setup page (copied, then *Paste a QR picture*), a saved image, or one
  dropped on the window. Or paste the `otpauth://` link or the secret key.

## Encryption

One file is ever written, `pawkey.vault`: in `~/.local/share/pawkey` on
Linux, `%APPDATA%\PawKey` on Windows, `~/Library/Application Support/PawKey`
on macOS, and the app's private storage on Android (left out of Android's
backups).

| What | How |
|---|---|
| Key | Argon2id of the password (192 MiB, 3 passes, about a second a guess), with the keyfiles as its secret input |
| Accounts | Sealed with XChaCha20-Poly1305 under that key, a fresh random nonce at every save, the salt bound in |
| File | The salt, the nonce, the ciphertext and its tag: no magic number or anything else in the clear, so without the password it's random bytes |
| Size | Padded to 4 KiB steps, so it doesn't tell how many accounts there are |
| Saving | Written to a new file (readable by you only) and renamed over the old one: a crash leaves the old vault or the new one, never half |

The sealing and the safe saving are `vaultkit`'s, from
[deniable](https://github.com/anti-ghostsec/deniable), as in PurrDroid.
Changing a single byte of the file makes it fail to open, the same way a
wrong password does.

While PawKey is unlocked, the key and secrets are in memory; locking (the
lock button, Ctrl+L, 5 minutes without use, or closing the window) wipes
them. A copied code is cleared from the clipboard after 30 seconds, unless
something else has been copied since.

### Keyfiles

Any number of files (or folders: every file directly in one) whose
contents are needed as well as the password: the same scheme as Enclave
and PurrDroid. Each keyfile is hashed with SHA-512 and goes into Argon2id
as its secret input, so neither the password nor the keyfiles open anything
alone. Their order doesn't matter. A keyfile must never change by a byte (a
photo that gets edited or re-saved stops working), so keep copies. Drop
them on the password box, or click *Keyfiles…*.

## Sync

Optional, and off until you turn it on (☰ → **Sync…**): your accounts on
every computer with PawKey, the same way [Wisp](https://github.com/anti-ghostsec/wisp)
syncs its bookmarks and logins, through an [xBrowserSync](https://www.xbrowsersync.org)
service. Everything is encrypted on this computer before it's sent; the
service only stores a blob of random-looking bytes and a date.

- **Make a new sync ID** gets one from the service, with a random
  24-character password. To add another computer, open PawKey there and
  type the same sync ID and password under *use a sync ID you already
  have* (the Sync box shows them, with copy buttons).
- **Or use one you have**, Wisp's included. PawKey's accounts are the
  entries whose title starts with `t_`; it never changes anything else, so
  Wisp's bookmarks (`b_`) and logins (`p_`) stay as they are. Keeping 2FA
  in the same place as your passwords does mean one sync password opens
  both factors, so a sync ID of its own is the safer choice.
- **When:** on unlocking, after adding or deleting an account, when the
  sync button in the toolbar is clicked, and once a minute while unlocked
  (a tiny "has it changed?" request unless something changed here).
- **Two computers at once:** accounts are told apart by a random id each
  has, and merged three ways (what's here, what's on the service, and what
  was there last time), so an account added on one computer and another
  deleted on the other both come through. If another computer saved in
  between, the service says so (409) and PawKey pulls theirs and merges
  again, as Wisp does.

The format is Wisp's, which is xBrowserSync's own (v1.5+):

| | |
|---|---|
| Key | PBKDF2-HMAC-SHA256 of the sync password, salted with the sync ID, 250 000 rounds |
| Data | AES-256-GCM, a random 16-byte IV each save, base64; the bookmark tree as JSON inside |
| An account | A bookmark titled `t_Issuer (name)` whose description holds the account (secret included) as JSON; its link is the `otpauth://` link without the secret |
| Service | HTTPS only (or one on this computer, or a `.onion`) |

The sync ID and password are kept in the vault, sealed with your PawKey
password. The sync password is all that protects the copy on the
service, and anyone with that copy can try passwords at PBKDF2's speed
(much faster than Argon2id), which is why PawKey makes a long random one.
Typing your own instead, make it as long. *Turn off sync…* forgets it on
this computer; the accounts stay here and on the service.

## Using it

1. **The first time:** type a password twice (and add any keyfiles), then
   *Create vault*.
2. **Add an account** (+ or Ctrl+N): on the site, turn on two-factor with
   an authenticator app. Take a screenshot of its QR code and click
   *Paste a QR picture*, or paste its setup key. Then type the code PawKey
   shows into the site, to finish.
3. **Click an account** to copy its code. The seconds left show next to
   it, and it turns red for the last five.

Keep each site's **recovery codes** somewhere safe: they get you in if the
vault is lost or the password forgotten. Back the vault up by copying
`pawkey.vault`: it's useless without the password.

**Forgot the password?** The password box has *Reset PawKey…*: once RESET
is typed it writes random bytes over the vault and removes it. There's no
other way in.

The menu has *Sync…*, a *Dark theme* switch (on by default) and *Change
password or keyfiles…*. `pawkey --vault PATH` opens a vault somewhere else.

## Setting up

The [releases](https://github.com/anti-ghostsec/PawKey/releases) have it
ready-made:

- **Linux** (x86_64): unpack the `.tar.gz` and run `./install.sh`. It goes
  in `~/.local/bin` and the Start menu, for your user only, nothing
  system-wide; `./install.sh --uninstall` removes it again (never the
  vault). Needs GTK 4.12+ and libsoup 3 (Debian 13, Ubuntu 24.04 and newer).
- **Windows** (x86_64): unzip it anywhere and run `PawKey\pawkey.exe`. GTK
  comes with it; nothing is installed.
- **macOS** (Apple Silicon): unzip it and move PawKey to Applications. It
  isn't notarized by Apple, so the first time, right-click it and choose
  **Open**.
- **Android** (8.0 and newer): install the `android-arm64.apk`.

From the source on Linux, `./install.sh` builds it first; that needs Rust
and the development files of GTK 4 and libsoup 3 (`libgtk-4-dev
libsoup-3.0-dev` on Debian).

### On Android

The same vault format, codes and sync as the desktop, in an app of its own:

- **Scan the QR code** with the camera (the camera is used only while
  scanning, and nothing is saved), pick a picture of it, paste the setup
  link or key, or tap an `otpauth://` link in the browser.
- Tap an account to copy its code (Android 13+ keeps it out of the
  clipboard preview); long-press to delete it.
- Locks after 5 minutes without use, or 5 minutes in the background.
  Screenshots and screen recording of PawKey are blocked.
- To have the same accounts as your computer, turn sync on in one of them
  and type its sync ID and password into the other (☰ → *Sync…*).
- No keyfiles on Android yet: a vault there is opened with its password.

## What it doesn't do yet

- Google Authenticator's "export accounts" QR codes
  (`otpauth-migration://`) can't be read yet: add each account from its own
  setup code.
- Counter-based codes (HOTP) aren't supported, only time-based ones (TOTP,
  which is what nearly every site uses). Steam's own code format isn't
  either.
- Accounts can't be renamed or reordered yet (delete and add again).
- On the desktops, QR codes are read from pictures, not the camera. On
  Android the camera scanner hasn't been tried on a real phone yet.
- The Windows and macOS builds haven't been run yet, and the macOS one is
  for Apple Silicon only (not Intel Macs).
- No duress password or hidden vault (PurrDroid has both).
- Sync has been tested against a stand-in xBrowserSync service and with
  Wisp's own sync code, not yet against api.xbrowsersync.org itself.
- An account changed on two computers at once keeps this computer's
  version (accounts can't be edited yet anyway, only added and deleted).
- GTK (and Android) keep their own copies of what's typed into the
  password box, which PawKey can't wipe; nothing keeps secrets out of swap.
- Rolling the whole vault file back to an older copy of itself isn't
  detected.

## Building

```sh
cargo build --release
cargo test               # the window tests need a display; they skip themselves without one
android/build-android.sh arm64-v8a   # phones; x86_64 for the emulator
```

Android needs the SDK with NDK 29, a JDK (17 or newer), cargo-ndk and the
Rust Android targets, as Wisp's does (`ANDROID_HOME`, default
`~/.local/opt/android-sdk`). A `v*` tag (matching the version in
`Cargo.toml`) has GitHub build the release for every platform, with
`packaging/windows.sh` and `packaging/macos.sh` putting GTK in with the
program, and a signed build provenance for each file (`gh attestation
verify FILE --repo anti-ghostsec/PawKey`). The Android APKs are signed with
PawKey's own key (GitHub secrets `ANDROID_KEYSTORE` and
`ANDROID_KEYSTORE_PASSWORD`, checked against `android/release-cert.sha256`);
without the key, the release ships without them.

| Part | What it is |
|---|---|
| `crates/core` | TOTP codes, `otpauth://` links, QR codes, keyfiles, the vault, and sync (format, merging) |
| `crates/pawkey` | The desktop program: the GTK 4 window, its dialogs, and sync over libsoup |
| `android/rust` | `pawkey-ffi`: the core for Android, with Kotlin bindings (UniFFI) |
| `android/app` | The Android app (Kotlin): the screens, the camera scanner, HTTPS for sync |

## License

MIT or Apache-2.0, as you prefer.

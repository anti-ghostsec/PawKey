//! The vault: every account, sealed with the password (and any keyfiles).
//!
//! The file is `salt (32) | nonce (24) | ciphertext | tag (16)` and nothing
//! else: no magic number, no version, nothing in the clear, so without the
//! password it's random bytes. The key is Argon2id of the password (192 MiB,
//! 3 passes, about a second a guess) with the keyfiles' secret as its secret
//! input; the accounts are sealed with XChaCha20-Poly1305 by `vaultkit`,
//! the salt bound in as associated data. The plaintext is padded to a
//! multiple of 4 KiB, so the file's size doesn't tell how many accounts it
//! holds. A new nonce is drawn at every save, and every save replaces the
//! file whole (a crash leaves the old one or the new one).

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, Zeroizing};

use serde::{Deserialize, Serialize};

use crate::keyfile;
use crate::sync::SyncState;
use crate::totp::{self, Account};

const SALT: usize = 32;
const PAD: usize = 4096;
const AAD: &[u8] = b"pawkey vault v1";

#[cfg(not(test))]
const KDF: vaultkit::Kdf = vaultkit::Kdf::DESKTOP;
// Tests run without optimisation; 192 MiB of Argon2id would take minutes.
#[cfg(test)]
const KDF: vaultkit::Kdf = vaultkit::Kdf { memory_kib: 8 * 1024, passes: 1, lanes: 1 };

#[derive(Debug)]
pub enum Error {
    /// The password or keyfiles are wrong, or the file isn't a vault (the
    /// two can't be told apart, by design).
    WrongPassword,
    Io(io::Error),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WrongPassword => f.write_str("Wrong password or keyfiles"),
            Error::Io(e) => write!(f, "{e}"),
            Error::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<vaultkit::Error> for Error {
    fn from(e: vaultkit::Error) -> Self {
        match e {
            vaultkit::Error::Decrypt => Error::WrongPassword,
            vaultkit::Error::Io(e) => Error::Io(e),
            other => Error::Other(other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute())
}

/// Where PawKey keeps its files: `~/.local/share/pawkey` on Linux (or
/// `$XDG_DATA_HOME/pawkey`), `%APPDATA%\PawKey` on Windows, and
/// `~/Library/Application Support/PawKey` on macOS.
/// The shortest new password PawKey takes without keyfiles.
pub const MIN_PASSWORD: usize = 10;

/// Why a new password won't do, if it won't. With keyfiles any password
/// goes (the keyfiles carry the strength); without, at least [`MIN_PASSWORD`].
pub fn password_problem(password: &str, keyfiles: bool) -> Option<String> {
    (!keyfiles && password.chars().count() < MIN_PASSWORD)
        .then(|| format!("Pick a password of at least {MIN_PASSWORD} characters (longer is better: it's all that protects your codes)."))
}

pub fn data_dir() -> PathBuf {
    if cfg!(windows) {
        return env_dir("APPDATA").unwrap_or_else(|| PathBuf::from(".")).join("PawKey");
    }
    let home = env_dir("HOME");
    if cfg!(target_os = "macos") {
        return home.unwrap_or_else(|| PathBuf::from(".")).join("Library/Application Support/PawKey");
    }
    env_dir("XDG_DATA_HOME").or_else(|| home.map(|h| h.join(".local/share"))).unwrap_or_else(|| PathBuf::from(".")).join("pawkey")
}

/// Where small settings go (the light theme switch): `~/.config/pawkey` on
/// Linux, the data folder elsewhere.
pub fn config_dir() -> PathBuf {
    if cfg!(any(windows, target_os = "macos")) {
        return data_dir();
    }
    env_dir("XDG_CONFIG_HOME").or_else(|| env_dir("HOME").map(|h| h.join(".config"))).unwrap_or_else(|| PathBuf::from(".")).join("pawkey")
}

/// `pawkey.vault` in [`data_dir`].
pub fn default_path() -> PathBuf {
    data_dir().join("pawkey.vault")
}

fn aad(salt: &[u8; SALT]) -> Vec<u8> {
    [AAD, &salt[..]].concat()
}

/// Argon2id of the password, with the keyfiles' secret as its secret input.
fn derive(password: &[u8], salt: &[u8; SALT], keyfiles: Option<&keyfile::Secret>) -> Result<Zeroizing<[u8; vaultkit::KEY]>> {
    let secret: &[u8] = keyfiles.map(|s| &s[..]).unwrap_or(&[]);
    let params = Params::new(KDF.memory_kib, KDF.passes, KDF.lanes, Some(vaultkit::KEY)).map_err(|e| Error::Other(e.to_string()))?;
    let argon = Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params).map_err(|e| Error::Other(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; vaultkit::KEY]);
    argon.hash_password_into(password, salt, key.as_mut()).map_err(|e| Error::Other(e.to_string()))?;
    Ok(key)
}

pub struct Vault {
    path: PathBuf,
    salt: [u8; SALT],
    key: Zeroizing<[u8; vaultkit::KEY]>,
    pub accounts: Vec<Account>,
    pub sync: SyncState,
}

/// What's sealed in the file.
#[derive(Serialize)]
struct ContentsRef<'a> {
    accounts: &'a [Account],
    sync: &'a SyncState,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Contents {
    Full {
        accounts: Vec<Account>,
        #[serde(default)]
        sync: SyncState,
    },
    /// The first version: the accounts alone.
    Accounts(Vec<Account>),
}

impl Vault {
    /// A new, empty vault at `path`, which must not exist yet.
    pub fn create(path: &Path, password: &[u8], keyfiles: Option<&keyfile::Secret>) -> Result<Vault> {
        if path.exists() {
            return Err(Error::Other(format!("{} already exists", path.display())));
        }
        let mut salt = [0u8; SALT];
        vaultkit::random_bytes(&mut salt)?;
        let vault =
            Vault { path: path.to_path_buf(), key: derive(password, &salt, keyfiles)?, salt, accounts: Vec::new(), sync: SyncState::default() };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: &Path, password: &[u8], keyfiles: Option<&keyfile::Secret>) -> Result<Vault> {
        let bytes = fs::read(path)?;
        if bytes.len() < SALT + vaultkit::NONCE + vaultkit::TAG {
            return Err(Error::WrongPassword);
        }
        let salt: [u8; SALT] = bytes[..SALT].try_into().unwrap();
        let key = derive(password, &salt, keyfiles)?;
        let plain = vaultkit::open(&key, &aad(&salt), &bytes[SALT..])?;
        let contents = serde_json::from_slice(&plain).map_err(|e| Error::Other(format!("The vault opened but its contents are damaged: {e}")))?;
        let (mut accounts, sync) = match contents {
            Contents::Full { accounts, sync } => (accounts, sync),
            Contents::Accounts(accounts) => (accounts, SyncState::default()),
        };
        for a in accounts.iter_mut().filter(|a| a.uid.is_empty()) {
            a.uid = totp::new_uid();
        }
        Ok(Vault { path: path.to_path_buf(), salt, key, accounts, sync })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self) -> Result<()> {
        let mut plain =
            Zeroizing::new(serde_json::to_vec(&ContentsRef { accounts: &self.accounts, sync: &self.sync }).map_err(|e| Error::Other(e.to_string()))?);
        // JSON allows trailing whitespace, so spaces pad it.
        let padded = plain.len().div_ceil(PAD).max(1) * PAD;
        plain.resize(padded, b' ');
        let sealed = vaultkit::seal(&self.key, &aad(&self.salt), &plain)?;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut bytes = Vec::with_capacity(SALT + sealed.len());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&sealed);
        vaultkit::write_private_atomic(&self.path, &bytes)?;
        Ok(())
    }

    /// Reseals the vault under a new password and keyfiles (and a new salt).
    pub fn change_password(&mut self, password: &[u8], keyfiles: Option<&keyfile::Secret>) -> Result<()> {
        let mut salt = [0u8; SALT];
        vaultkit::random_bytes(&mut salt)?;
        let key = derive(password, &salt, keyfiles)?;
        let (old_salt, old_key) = (self.salt, self.key.clone());
        (self.salt, self.key) = (salt, key);
        if let Err(e) = self.save() {
            (self.salt, self.key) = (old_salt, old_key);
            return Err(e);
        }
        Ok(())
    }
}

/// Wipes the vault: writes random bytes over it, syncs, then removes it. On
/// an SSD the drive may keep an old copy where no program can reach it; it
/// still needs the password and keyfiles.
pub fn destroy(path: &Path) -> io::Result<()> {
    let len = fs::metadata(path)?.len() as usize;
    let mut junk = Zeroizing::new(vec![0u8; len]);
    vaultkit::random_bytes(&mut junk).map_err(io::Error::from)?;
    let mut f = OpenOptions::new().write(true).open(path)?;
    f.write_all(&junk)?;
    f.sync_all()?;
    drop(f);
    fs::remove_file(path)
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.salt.zeroize();
        // Accounts wipe their own secrets when dropped.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pawkey-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("pawkey.vault")
    }

    #[test]
    fn round_trip() {
        let path = temp("rt");
        let mut v = Vault::create(&path, b"hunter2", None).unwrap();
        assert!(Vault::create(&path, b"x", None).is_err(), "never overwrites");
        v.accounts.push(Account::new("Example", "me", "JBSWY3DPEHPK3PXP").unwrap());
        v.save().unwrap();

        let v2 = Vault::open(&path, b"hunter2", None).unwrap();
        assert_eq!(v2.accounts, v.accounts);
        assert!(matches!(Vault::open(&path, b"hunter3", None), Err(Error::WrongPassword)));

        let raw = fs::read(&path).unwrap();
        assert!(!raw.windows(16).any(|w| w == b"JBSWY3DPEHPK3PXP"), "secret on disk in the clear");
        assert!(!raw.windows(7).any(|w| w == b"Example"), "issuer on disk in the clear");
        assert_eq!((raw.len() - SALT - vaultkit::NONCE - vaultkit::TAG) % PAD, 0, "padded");
        fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn keyfiles_and_change_password() {
        let path = temp("kf");
        let kf: keyfile::Secret = Zeroizing::new([7u8; 64]);
        let mut v = Vault::create(&path, b"pw", Some(&kf)).unwrap();
        assert!(Vault::open(&path, b"pw", None).is_err(), "password alone opens nothing");
        assert!(Vault::open(&path, b"", Some(&kf)).is_err(), "keyfile alone opens nothing");
        Vault::open(&path, b"pw", Some(&kf)).unwrap();

        v.change_password(b"new", None).unwrap();
        assert!(Vault::open(&path, b"pw", Some(&kf)).is_err());
        Vault::open(&path, b"new", None).unwrap();

        destroy(&path).unwrap();
        assert!(!path.exists());
        fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn tampering_is_a_wrong_password() {
        let path = temp("tamper");
        Vault::create(&path, b"pw", None).unwrap();
        let mut raw = fs::read(&path).unwrap();
        for i in [0, SALT + 3, raw.len() - 1] {
            raw[i] ^= 1;
            fs::write(&path, &raw).unwrap();
            assert!(matches!(Vault::open(&path, b"pw", None), Err(Error::WrongPassword)), "byte {i}");
            raw[i] ^= 1;
        }
        fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}

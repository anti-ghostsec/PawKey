//! pawkey-core for PawKey on Android, with bindings for Kotlin (UniFFI).
//!
//! The same vault, codes, QR reading and sync as the desktop app: only the
//! window is Kotlin's. Every call blocks (Argon2id takes a second or more on
//! a phone, sync waits for the network), so the app makes them off its UI
//! thread. HTTP is the app's: it hands in an [`HttpClient`] (Android's own
//! HTTPS stack), as Wisp does.

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use pawkey_core::qr;
use pawkey_core::sync::{self, SyncAccount, SyncState, Transport};
use pawkey_core::totp::{self, Account, Algo};
use pawkey_core::vault::{self, Vault};
use serde_json::Value as Json;

uniffi::setup_scaffolding!();

#[derive(Debug, uniffi::Error)]
pub enum PawError {
    /// Wrong password, or not a PawKey vault (they can't be told apart).
    WrongPassword,
    Failed {
        reason: String,
    },
}

impl fmt::Display for PawError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PawError::WrongPassword => f.write_str("Wrong password"),
            PawError::Failed { reason } => f.write_str(reason),
        }
    }
}

impl std::error::Error for PawError {}

fn failed(message: impl Into<String>) -> PawError {
    PawError::Failed { reason: message.into() }
}

impl From<vault::Error> for PawError {
    fn from(e: vault::Error) -> Self {
        match e {
            vault::Error::WrongPassword => PawError::WrongPassword,
            other => failed(other.to_string()),
        }
    }
}

#[derive(uniffi::Record)]
pub struct AccountView {
    pub uid: String,
    pub issuer: String,
    pub name: String,
    /// The issuer, or the name when there's no issuer.
    pub title: String,
    pub digits: u32,
    pub period: u64,
}

impl From<&Account> for AccountView {
    fn from(a: &Account) -> Self {
        AccountView {
            uid: a.uid.clone(),
            issuer: a.issuer.clone(),
            name: a.name.clone(),
            title: a.title().to_string(),
            digits: a.digits,
            period: a.period,
        }
    }
}

#[derive(uniffi::Record)]
pub struct CodeView {
    pub code: String,
    pub remaining: u64,
}

#[derive(uniffi::Record, Clone)]
pub struct SyncLogin {
    pub service: String,
    pub id: String,
    pub password: String,
}

impl From<&SyncAccount> for SyncLogin {
    fn from(a: &SyncAccount) -> Self {
        SyncLogin { service: a.service.clone(), id: a.id.clone(), password: a.password.clone() }
    }
}

/// What the app's HTTP client answered. `status` 0: no answer at all (no
/// network, no such host), with the reason in `body`.
#[derive(uniffi::Record)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Android's HTTPS, from Kotlin. `body` is sent as `application/json`;
/// `proxy` is empty (the system's settings) or a checked `socks5://host:port`.
#[uniffi::export(with_foreign)]
pub trait HttpClient: Send + Sync {
    fn request(&self, method: String, url: String, body: Option<String>, proxy: String) -> HttpResponse;
}

struct Http(Arc<dyn HttpClient>, String);

impl Transport for Http {
    fn request(&self, method: &str, url: &str, body: Option<&Json>) -> Result<Json, String> {
        if !sync::service_is_private(url) {
            return Err("The sync service's address must start with https://.".into());
        }
        let r = self.0.request(method.to_string(), url.to_string(), body.map(|b| b.to_string()), self.1.clone());
        if r.status == 0 {
            return Err(format!("Can't reach the sync service: {}", r.body));
        }
        if !(200..300).contains(&r.status) {
            return Err(sync::http_error(r.status));
        }
        let parsed: Result<Json, _> = serde_json::from_str(&r.body);
        // A web page instead of JSON (a captive portal, maintenance): an error.
        parsed.map_err(|_| sync::NOT_SYNC_DATA.to_string())
    }
}

/// No core dumps, not debuggable by other apps: called when the app starts.
#[uniffi::export]
pub fn harden() {
    pawkey_core::harden_process();
}

/// Why a new password won't do (too short), if it won't.
#[uniffi::export]
pub fn password_problem(password: String) -> Option<String> {
    vault::password_problem(&zeroize::Zeroizing::new(password), false)
}

#[uniffi::export]
pub fn tor_proxy() -> String {
    sync::TOR_PROXY.to_string()
}

#[uniffi::export]
pub fn vault_exists(path: String) -> bool {
    PathBuf::from(path).exists()
}

#[uniffi::export]
pub fn create_vault(path: String, password: String) -> Result<Arc<Session>, PawError> {
    let password = zeroize::Zeroizing::new(password);
    if let Some(e) = vault::password_problem(&password, false) {
        return Err(failed(e));
    }
    Ok(Session::new(Vault::create(&PathBuf::from(path), password.as_bytes(), None)?))
}

#[uniffi::export]
pub fn open_vault(path: String, password: String) -> Result<Arc<Session>, PawError> {
    let password = zeroize::Zeroizing::new(password);
    Ok(Session::new(Vault::open(&PathBuf::from(path), password.as_bytes(), None)?))
}

/// Writes random bytes over the vault, then removes it.
#[uniffi::export]
pub fn destroy_vault(path: String) -> Result<(), PawError> {
    vault::destroy(&PathBuf::from(path)).map_err(|e| failed(format!("Couldn't wipe it: {e}")))
}

/// The text of every QR code in a greyscale picture (a camera frame's Y
/// plane, row by row, `width` bytes each).
#[uniffi::export]
pub fn read_qr(width: u32, height: u32, grey: Vec<u8>) -> Vec<String> {
    qr::decode_grey(width as usize, height as usize, &grey)
}

/// What an `otpauth://` link holds, to fill in the add form.
#[uniffi::export]
pub fn parse_link(uri: String) -> Result<AccountView, PawError> {
    totp::parse_otpauth(&uri).map(|a| AccountView::from(&a)).map_err(failed)
}

#[uniffi::export]
pub fn default_sync_service() -> String {
    sync::DEFAULT_SERVICE.to_string()
}

/// An unlocked vault. Dropping it (the app's `destroy()`) wipes the key and
/// every secret.
#[derive(uniffi::Object)]
pub struct Session {
    vault: Mutex<Vault>,
    sync_key: Mutex<Option<(SyncAccount, sync::Key)>>,
    /// One sync at a time.
    syncing: Mutex<()>,
}

impl Session {
    fn new(v: Vault) -> Arc<Session> {
        Arc::new(Session { vault: Mutex::new(v), sync_key: Mutex::new(None), syncing: Mutex::new(()) })
    }

    fn vault(&self) -> std::sync::MutexGuard<'_, Vault> {
        self.vault.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Changes the vault and saves it, or puts it back as it was.
    fn change<T>(&self, f: impl FnOnce(&mut Vault) -> Result<T, PawError>) -> Result<T, PawError> {
        let mut v = self.vault();
        let before = (v.accounts.clone(), v.sync.clone());
        let out = f(&mut v)?;
        if let Err(e) = v.save() {
            (v.accounts, v.sync) = before;
            return Err(failed(format!("Couldn't save: {e}")));
        }
        Ok(out)
    }

    fn add(&self, mut acc: Account, issuer: &str, name: &str) -> Result<AccountView, PawError> {
        acc.issuer = issuer.trim().to_string();
        acc.name = name.trim().to_string();
        if acc.issuer.is_empty() && acc.name.is_empty() {
            return Err(failed("Give it a name, so you can tell it apart."));
        }
        let view = AccountView::from(&acc);
        self.change(|v| {
            v.accounts.push(acc);
            Ok(())
        })?;
        Ok(view)
    }

    fn key_for(&self, account: &SyncAccount) -> Option<sync::Key> {
        self.sync_key.lock().ok()?.as_ref().filter(|(a, _)| a == account).map(|(_, k)| k.clone())
    }

    fn turn_on(&self, account: SyncAccount, key: sync::Key, proxy: String) -> Result<(), PawError> {
        self.change(|v| {
            v.sync = SyncState { account: Some(account.clone()), proxy, ..Default::default() };
            Ok(())
        })?;
        *self.sync_key.lock().unwrap() = Some((account, key));
        Ok(())
    }
}

#[uniffi::export]
impl Session {
    pub fn accounts(&self) -> Vec<AccountView> {
        self.vault().accounts.iter().map(AccountView::from).collect()
    }

    /// Each account's code now, in the same order as [`Session::accounts`].
    pub fn codes(&self, unix_time: u64) -> Vec<CodeView> {
        self.vault().accounts.iter().map(|a| CodeView { code: a.code_at(unix_time), remaining: a.remaining(unix_time) }).collect()
    }

    pub fn code(&self, uid: String, unix_time: u64) -> Option<String> {
        self.vault().accounts.iter().find(|a| a.uid == uid).map(|a| a.code_at(unix_time))
    }

    /// Adds the account an `otpauth://` link describes; `issuer` and `name`
    /// are as the user left them in the form.
    pub fn add_link(&self, uri: String, issuer: String, name: String) -> Result<AccountView, PawError> {
        self.add(totp::parse_otpauth(&uri).map_err(failed)?, &issuer, &name)
    }

    /// `algorithm`: SHA1, SHA256 or SHA512.
    pub fn add_secret(
        &self,
        secret: String,
        issuer: String,
        name: String,
        digits: u32,
        period: u64,
        algorithm: String,
    ) -> Result<AccountView, PawError> {
        let mut acc = Account::new("", "", &secret).map_err(failed)?;
        if !(6..=8).contains(&digits) || period == 0 {
            return Err(failed("Digits must be 6 to 8, and the period above zero."));
        }
        acc.digits = digits;
        acc.period = period;
        acc.algo = Algo::parse(&algorithm).ok_or_else(|| failed("Unsupported algorithm"))?;
        self.add(acc, &issuer, &name)
    }

    pub fn delete(&self, uid: String) -> Result<(), PawError> {
        self.change(|v| {
            v.accounts.retain(|a| a.uid != uid);
            Ok(())
        })
    }

    pub fn change_password(&self, password: String) -> Result<(), PawError> {
        let password = zeroize::Zeroizing::new(password);
        if let Some(e) = vault::password_problem(&password, false) {
            return Err(failed(e));
        }
        self.vault().change_password(password.as_bytes(), None).map_err(PawError::from)
    }

    pub fn sync_login(&self) -> Option<SyncLogin> {
        self.vault().sync.account.as_ref().map(SyncLogin::from)
    }

    /// The sync proxy: empty, or `socks5://host:port`.
    pub fn sync_proxy(&self) -> String {
        self.vault().sync.proxy.clone()
    }

    /// Checks and keeps a new sync proxy; returns it as kept.
    pub fn set_sync_proxy(&self, proxy: String) -> Result<String, PawError> {
        let proxy = sync::check_proxy(&proxy).map_err(failed)?;
        self.change(|v| {
            v.sync.proxy = proxy.clone();
            Ok(())
        })?;
        Ok(proxy)
    }

    /// A new sync ID on `service`, with a random password; syncs next.
    pub fn sync_create(&self, service: String, proxy: String, http: Arc<dyn HttpClient>) -> Result<SyncLogin, PawError> {
        let proxy = sync::check_proxy(&proxy).map_err(failed)?;
        let account = sync::create_account(&Http(http, proxy.clone()), &service).map_err(failed)?;
        let key = sync::derive_key(&account);
        let login = SyncLogin::from(&account);
        self.turn_on(account, key, proxy)?;
        Ok(login)
    }

    /// Uses an existing sync ID (another PawKey's, or Wisp's).
    pub fn sync_connect(&self, login: SyncLogin, proxy: String, http: Arc<dyn HttpClient>) -> Result<(), PawError> {
        let proxy = sync::check_proxy(&proxy).map_err(failed)?;
        let wanted = SyncAccount { service: login.service, id: login.id, password: login.password };
        let (account, key) = sync::connect(&Http(http, proxy.clone()), &wanted).map_err(failed)?;
        self.turn_on(account, key, proxy)
    }

    /// Takes PawKey's accounts off the service (for a sync login that may
    /// be in other hands); other devices then stop syncing, keeping theirs.
    pub fn sync_wipe(&self, http: Arc<dyn HttpClient>) -> Result<(), PawError> {
        let _one = self.syncing.lock().unwrap_or_else(|e| e.into_inner());
        let state = self.vault().sync.clone();
        let account = state.account.clone().ok_or_else(|| failed("Sync is off."))?;
        let key = self.key_for(&account).unwrap_or_else(|| sync::derive_key(&account));
        sync::wipe(&Http(http, state.proxy.clone()), &state, &key).map_err(failed)
    }

    /// Forgets the sync login here; the accounts stay.
    pub fn sync_off(&self) -> Result<(), PawError> {
        self.change(|v| {
            v.sync = SyncState::default();
            Ok(())
        })?;
        *self.sync_key.lock().unwrap() = None;
        Ok(())
    }

    /// Syncs; true if the accounts here changed. Without `force`, only
    /// asks the service whether anything changed, unless something here did.
    pub fn sync(&self, http: Arc<dyn HttpClient>, force: bool) -> Result<bool, PawError> {
        let _one = self.syncing.lock().unwrap_or_else(|e| e.into_inner());
        let (state, local) = {
            let v = self.vault();
            (v.sync.clone(), v.accounts.clone())
        };
        let Some(account) = state.account.clone() else { return Ok(false) };
        let key = self.key_for(&account).unwrap_or_else(|| sync::derive_key(&account));
        let t = Http(http, state.proxy.clone());
        let dirty =
            local.iter().map(|a| a.uid.as_str()).collect::<std::collections::BTreeSet<_>>() != state.base.iter().map(String::as_str).collect();
        if !force && !dirty && !sync::remote_changed(&t, &state).map_err(failed)? {
            *self.sync_key.lock().unwrap() = Some((account, key));
            return Ok(false);
        }
        let out = sync::sync(&t, &state, &key, &local).map_err(failed)?;
        *self.sync_key.lock().unwrap() = Some((account.clone(), key));
        // Accounts may have been added or deleted here while it ran.
        self.change(|v| {
            if v.sync.account.as_ref() != Some(&account) {
                return Err(failed("Sync was switched while it ran."));
            }
            let merged = sync::merge(&v.accounts, &state.base, &out.accounts);
            let changed = merged != v.accounts;
            v.accounts = merged;
            v.sync.base = out.base;
            v.sync.last_updated = out.last_updated;
            v.sync.seq = out.seq;
            Ok(changed)
        })
    }
}

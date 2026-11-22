//! Sync through xBrowserSync, the way Wisp does it.
//!
//! One end-to-end encrypted bookmark tree per sync ID, on an xBrowserSync
//! service. PawKey's accounts are the entries whose title starts with `t_`;
//! it never touches any other entry, so a sync ID can be shared with Wisp
//! (whose bookmarks are `b_` and logins `p_`) or anything else.
//!
//! Wire format (Wisp's, compatible with the official xBrowserSync apps, v1.5+):
//!   key  = PBKDF2-HMAC-SHA256(password, salt = sync id, 250 000 rounds, 32 bytes)
//!   blob = base64(iv[16] || AES-256-GCM(key, iv, lzutf8(json)))
//!
//! An entry is `{"id", "title": "t_GitHub (you)", "url": "otpauth://totp/...",
//! "description": "{...the account, secret included...}"}`. The url never
//! holds the secret; everything is inside the encrypted blob either way.
//!
//! Merging is three-way, by each account's `uid`: `base` is the set of
//! uids the service had after the last sync. An account here and not in
//! `base` was added here; one in `base` and gone from the service was
//! deleted elsewhere; and so on. A PUT answered 409 (another device saved
//! meanwhile) means pulling again and merging again, as Wisp does.
//!
//! One more entry, [`STATE_TITLE`], holds a counter that every upload
//! raises, a "wiped" mark, and padding. A device refuses data whose counter
//! is lower than one it has seen (an old copy played back by the service or
//! someone between), and the padding rounds the data up to 4 KiB steps so
//! its size doesn't tell how many accounts there are.

use std::collections::{BTreeSet, HashMap};

use aes_gcm::aead::generic_array::typenum::U16;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::totp::{Account, Algo};

pub const DEFAULT_SERVICE: &str = "https://api.xbrowsersync.org";
const API_VERSION: &str = "1.5.4";
const ITERATIONS: u32 = 250_000;
pub const PREFIX: &str = "t_";
/// xBrowserSync's default container for bookmarks that aren't on a toolbar/menu.
const OTHER_CONTAINER: &str = "[xbs] Other";
const ATTEMPTS: usize = 5;
/// The entry with the counter, the wiped mark and the padding.
pub const STATE_TITLE: &str = "t_~pawkey sync state~";
const PAD_TO: usize = 4096;

type Cipher = AesGcm<Aes256, U16>;
pub type Key = Zeroizing<[u8; 32]>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SyncAccount {
    pub service: String,
    pub id: String,
    pub password: String,
}

/// Kept in the vault: the login, and what the service had last time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncState {
    pub account: Option<SyncAccount>,
    /// The uids of PawKey's accounts on the service after the last sync.
    pub base: Vec<String>,
    pub last_updated: String,
    /// The highest counter seen on the service: older data is refused.
    #[serde(default)]
    pub seq: u64,
    /// A SOCKS5 proxy for every sync request (`socks5://127.0.0.1:9050` for
    /// Tor), or empty for the system's own settings. See [`check_proxy`].
    #[serde(default)]
    pub proxy: String,
}

pub const TOR_PROXY: &str = "socks5://127.0.0.1:9050";

/// A proxy address as PawKey keeps it: empty (none), or `socks5://host:port`.
/// SOCKS5 only, so names are looked up by the proxy (by Tor), not here.
pub fn check_proxy(text: &str) -> Result<String, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(String::new());
    }
    let bad = || "A proxy is socks5://host:port (for Tor, socks5://127.0.0.1:9050).".to_string();
    let rest = t.strip_prefix("socks5://").or_else(|| t.strip_prefix("socks5h://")).ok_or_else(bad)?;
    let (host, port) = rest.trim_end_matches('/').rsplit_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    let host_ok = !host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || ".-[]:".contains(c));
    if !host_ok || port == 0 {
        return Err(bad());
    }
    Ok(format!("socks5://{host}:{port}"))
}

/// Talking to the service: a JSON request, the JSON answer. A status other
/// than 2xx is an `Err` starting with the status number ("409 ...").
pub trait Transport {
    fn request(&self, method: &str, url: &str, body: Option<&Json>) -> Result<Json, String>;
}

// ---------------------------------------------------------------- accounts

/// A sync service is talked to over HTTPS only, except one on this
/// computer or a Tor onion service (which Tor encrypts itself).
pub fn service_is_private(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host =
        if let Some(v6) = authority.strip_prefix('[') { v6.split(']').next().unwrap_or("") } else { authority.split(':').next().unwrap_or("") }
            .to_ascii_lowercase();
    match scheme.to_ascii_lowercase().as_str() {
        "https" => !host.is_empty(),
        "http" => {
            host == "localhost"
                || host.ends_with(".localhost")
                || host.ends_with(".onion")
                || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
        }
        _ => false,
    }
}

fn checked(service: &str) -> Result<String, String> {
    let service = service.trim().trim_end_matches('/').to_string();
    if service_is_private(&service) {
        Ok(service)
    } else {
        Err("The sync service's address must start with https:// (plain http:// would show anyone on the network your sync ID and let them change what's stored).".into())
    }
}

fn random_password() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut bytes = Zeroizing::new([0u8; 24]);
    vaultkit::random_bytes(&mut bytes[..]).expect("no OS randomness");
    bytes.iter().map(|b| CHARS[*b as usize % CHARS.len()] as char).collect()
}

/// A new sync ID on `service`, with a random password.
pub fn create_account(t: &dyn Transport, service: &str) -> Result<SyncAccount, String> {
    let service = checked(service)?;
    let info = t.request("GET", &format!("{service}/info"), None)?;
    if info["status"].as_i64() == Some(3) {
        return Err("This sync service isn't taking new sync IDs.".into());
    }
    let created = t.request("POST", &format!("{service}/bookmarks"), Some(&json!({ "version": API_VERSION })))?;
    let id = created["id"].as_str().ok_or("The service didn't give a sync ID.")?.to_string();
    Ok(SyncAccount { service, id, password: random_password() })
}

/// Checks an existing sync ID and password (the password must decrypt
/// what's there) and returns its key.
pub fn connect(t: &dyn Transport, account: &SyncAccount) -> Result<(SyncAccount, Key), String> {
    let account = SyncAccount { service: checked(&account.service)?, id: account.id.trim().to_string(), password: account.password.clone() };
    if account.id.is_empty() {
        return Err("Type the sync ID.".into());
    }
    let key = derive_key(&account);
    let data = t.request("GET", &format!("{}/bookmarks/{}", account.service, account.id), None)?;
    let (blob, _) = sync_data(&data)?;
    if !blob.is_empty() {
        decrypt(&key, blob).map_err(|_| "Wrong password for this sync ID.".to_string())?;
    }
    Ok((account, key))
}

// ---------------------------------------------------------------- crypto

/// 250 000 rounds of PBKDF2: a noticeable moment, so not on the UI thread.
pub fn derive_key(account: &SyncAccount) -> Key {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(account.password.as_bytes(), account.id.as_bytes(), ITERATIONS, &mut key[..]);
    key
}

pub fn encrypt(key: &[u8; 32], text: &str) -> Result<String, String> {
    let cipher = Cipher::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut iv = [0u8; 16];
    vaultkit::random_bytes(&mut iv).map_err(|e| e.to_string())?;
    // Plain UTF-8 is a valid LZUTF8 stream (one with no back-references).
    let sealed = cipher.encrypt(GenericArray::from_slice(&iv), text.as_bytes()).map_err(|_| "Encryption failed.".to_string())?;
    let mut out = iv.to_vec();
    out.extend_from_slice(&sealed);
    Ok(B64.encode(out))
}

pub fn decrypt(key: &[u8; 32], blob: &str) -> Result<Zeroizing<String>, String> {
    let raw = B64.decode(blob.trim()).map_err(|_| "The sync data isn't base64.".to_string())?;
    if raw.len() < 16 + 16 {
        return Err("The sync data is too short.".into());
    }
    let cipher = Cipher::new_from_slice(key).map_err(|e| e.to_string())?;
    let plain = Zeroizing::new(
        cipher.decrypt(GenericArray::from_slice(&raw[..16]), &raw[16..]).map_err(|_| "Can't decrypt the sync data (wrong password?).".to_string())?,
    );
    String::from_utf8(lzutf8_decompress(&plain)).map(Zeroizing::new).map_err(|_| "The sync data isn't UTF-8.".to_string())
}

/// Decoder for LZUTF8, the compression xBrowserSync applies before encrypting.
/// Back-references are 2- or 3-byte sequences whose lead byte looks like a
/// UTF-8 lead (110xxxxx / 111xxxxx) but whose next byte is not a continuation.
fn lzutf8_decompress(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 2);
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        let next_is_continuation = input.get(i + 1).is_some_and(|n| n >> 7 == 1);
        if b >> 6 != 3 || i + 1 >= input.len() || next_is_continuation {
            out.push(b);
            i += 1;
            continue;
        }
        let length = (b & 31) as usize;
        let (distance, used) = if b >> 5 == 6 {
            (input[i + 1] as usize, 2)
        } else if i + 2 < input.len() {
            (((input[i + 1] as usize) << 8) | input[i + 2] as usize, 3)
        } else {
            out.push(b);
            i += 1;
            continue;
        };
        let start = out.len().saturating_sub(distance);
        for k in 0..length {
            let byte = out.get(start + k).copied().unwrap_or(b' ');
            out.push(byte);
        }
        i += used;
    }
    out
}

// ---------------------------------------------------------------- the tree

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn entry_title(a: &Account) -> String {
    if a.issuer.is_empty() || a.name.is_empty() {
        format!("{PREFIX}{}", a.title())
    } else {
        format!("{PREFIX}{} ({})", a.issuer, a.name)
    }
}

/// An otpauth link without the secret: what other xBrowserSync apps show.
fn entry_url(a: &Account) -> String {
    let label = if a.issuer.is_empty() { enc(&a.name) } else { format!("{}:{}", enc(&a.issuer), enc(&a.name)) };
    let algo = match a.algo {
        Algo::Sha1 => "SHA1",
        Algo::Sha256 => "SHA256",
        Algo::Sha512 => "SHA512",
    };
    format!("otpauth://totp/{label}?issuer={}&digits={}&period={}&algorithm={algo}", enc(&a.issuer), a.digits, a.period)
}

fn entry_of(a: &Account) -> Json {
    json!({ "title": entry_title(a), "url": entry_url(a), "description": serde_json::to_string(a).unwrap_or_default() })
}

fn is_ours(node: &Json) -> bool {
    node.get("url").is_some() && node["title"].as_str().is_some_and(|t| t.starts_with(PREFIX))
}

fn account_of(node: &Json) -> Option<Account> {
    let a: Account = serde_json::from_str(node["description"].as_str()?).ok()?;
    (!a.uid.is_empty() && crate::totp::base32_decode(&a.secret).is_some_and(|k| !k.is_empty()) && (6..=8).contains(&a.digits) && a.period > 0)
        .then_some(a)
}

/// PawKey's accounts in a tree, in tree order (each uid once).
pub fn accounts_in(tree: &Json) -> Vec<Account> {
    fn walk(node: &Json, out: &mut Vec<Account>) {
        match node {
            Json::Array(items) => items.iter().for_each(|i| walk(i, out)),
            Json::Object(o) => {
                if is_ours(node) {
                    if let Some(a) = account_of(node) {
                        if !out.iter().any(|x| x.uid == a.uid) {
                            out.push(a);
                        }
                    }
                } else if let Some(c) = o.get("children") {
                    walk(c, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(tree, &mut out);
    out
}

fn max_id(node: &Json) -> i64 {
    match node {
        Json::Array(items) => items.iter().map(max_id).max().unwrap_or(0),
        Json::Object(o) => o.get("id").and_then(Json::as_i64).unwrap_or(0).max(o.get("children").map(max_id).unwrap_or(0)),
        _ => 0,
    }
}

fn other_container(tree: &mut Json) -> &mut Vec<Json> {
    if !tree.is_array() {
        *tree = json!([]);
    }
    let pos = tree.as_array().unwrap().iter().position(|c| c["title"] == OTHER_CONTAINER);
    let pos = match pos {
        Some(p) => p,
        None => {
            let id = max_id(tree) + 1;
            let items = tree.as_array_mut().unwrap();
            items.push(json!({ "id": id, "title": OTHER_CONTAINER, "children": [] }));
            items.len() - 1
        }
    };
    let container = &mut tree.as_array_mut().unwrap()[pos];
    if !container["children"].is_array() {
        container["children"] = json!([]);
    }
    container["children"].as_array_mut().unwrap()
}

/// `tree` with PawKey's entries made to match `accounts`: entries kept
/// where they are (and with their ids), changed ones rewritten, gone ones
/// removed, new ones added to the end of "Other". Nothing else is touched.
pub fn with_accounts(tree: &Json, accounts: &[Account]) -> Json {
    let wanted: HashMap<&str, &Account> = accounts.iter().map(|a| (a.uid.as_str(), a)).collect();
    let mut seen = BTreeSet::new();
    fn walk(node: &mut Json, wanted: &HashMap<&str, &Account>, seen: &mut BTreeSet<String>) {
        match node {
            Json::Array(items) => {
                items.retain_mut(|item| {
                    if !is_ours(item) {
                        walk(item, wanted, seen);
                        return true;
                    }
                    let uid = account_of(item).map(|a| a.uid.clone());
                    match uid.as_deref().and_then(|u| wanted.get(u).map(|a| (u, a))) {
                        Some((u, a)) if seen.insert(u.to_string()) => {
                            let id = item["id"].clone();
                            *item = entry_of(a);
                            item["id"] = id;
                            true
                        }
                        // Gone, a duplicate, or unreadable: removed.
                        _ => false,
                    }
                });
            }
            Json::Object(o) => {
                if let Some(c) = o.get_mut("children") {
                    walk(c, wanted, seen);
                }
            }
            _ => {}
        }
    }
    let mut tree = if tree.is_array() { tree.clone() } else { json!([]) };
    walk(&mut tree, &wanted, &mut seen);
    let new: Vec<&Account> = accounts.iter().filter(|a| !seen.contains(&a.uid)).collect();
    if !new.is_empty() {
        other_container(&mut tree);
        let mut next = max_id(&tree) + 1;
        for a in new {
            let mut e = entry_of(a);
            e["id"] = json!(next);
            next += 1;
            other_container(&mut tree).push(e);
        }
    }
    tree
}

/// Three-way merge by uid. `local` keeps its order and wins for accounts on
/// both sides; accounts new on the service are added after it.
pub fn merge(local: &[Account], base: &[String], remote: &[Account]) -> Vec<Account> {
    let base: BTreeSet<&str> = base.iter().map(String::as_str).collect();
    let remote_uids: BTreeSet<&str> = remote.iter().map(|a| a.uid.as_str()).collect();
    let local_uids: BTreeSet<&str> = local.iter().map(|a| a.uid.as_str()).collect();
    let mut out: Vec<Account> = local
        .iter()
        // Deleted on another device: in base, gone from the service.
        .filter(|a| remote_uids.contains(a.uid.as_str()) || !base.contains(a.uid.as_str()))
        .cloned()
        .collect();
    // New on another device: on the service, never seen here. (In base and
    // gone from here means deleted here.)
    out.extend(remote.iter().filter(|a| !local_uids.contains(a.uid.as_str()) && !base.contains(a.uid.as_str())).cloned());
    out
}

// ---------------------------------------------------------------- the state entry

fn is_state(node: &Json) -> bool {
    node["title"].as_str() == Some(STATE_TITLE)
}

/// The counter and wiped mark in a tree (0 and false without the entry).
fn state_in(tree: &Json) -> (u64, bool) {
    fn find(node: &Json) -> Option<&Json> {
        match node {
            Json::Array(items) => items.iter().find_map(find),
            Json::Object(o) if is_state(node) => Some(node).filter(|_| o.contains_key("description")),
            Json::Object(o) => o.get("children").and_then(find),
            _ => None,
        }
    }
    let Some(d) = find(tree).and_then(|n| n["description"].as_str()).and_then(|d| serde_json::from_str::<Json>(d).ok()) else {
        return (0, false);
    };
    (d["seq"].as_u64().unwrap_or(0), d["wiped"].as_bool().unwrap_or(false))
}

/// `tree` (already through [`with_accounts`], which drops the old state
/// entry) with a new state entry, as text padded to [`PAD_TO`] steps.
fn sealed_text(mut tree: Json, seq: u64, wiped: bool) -> Zeroizing<String> {
    let id = max_id(&tree) + 1;
    let entry = |pad: usize| {
        let d = json!({ "seq": seq, "wiped": wiped, "pad": "0".repeat(pad) });
        json!({ "id": id, "title": STATE_TITLE, "url": "about:blank", "description": d.to_string() })
    };
    other_container(&mut tree).push(entry(0));
    let len = tree.to_string().len();
    let pad = (PAD_TO - len % PAD_TO) % PAD_TO;
    *other_container(&mut tree).last_mut().unwrap() = entry(pad);
    Zeroizing::new(tree.to_string())
}

// ---------------------------------------------------------------- syncing

pub struct Outcome {
    /// The accounts as the service now has them.
    pub accounts: Vec<Account>,
    /// The new `SyncState::base` and `last_updated`.
    pub base: Vec<String>,
    pub last_updated: String,
    /// The new `SyncState::seq`.
    pub seq: u64,
    /// Whether anything was uploaded.
    pub uploaded: bool,
}

pub const ROLLED_BACK: &str = "The sync data on the service is older than what this device has already seen: an old copy may have been put back. Nothing was changed. (A device with a PawKey older than 0.1.2 does this too: update it.)";
pub const WIPED: &str = "PawKey's accounts were removed from the service from another device. Nothing was changed here. Turn sync off on this device, or set it up again.";

/// What a failed request says: the status, in PawKey's own words. The
/// service's own text isn't shown, so it can't put words in PawKey's mouth.
pub fn http_error(status: u16) -> String {
    let what = match status {
        404 => "This sync ID isn't on the service.",
        409 => "Another device saved at the same time.",
        413 => "The service won't take this much data.",
        429 => "The service says too many requests; it'll try again later.",
        400..=499 => "The service refused the request.",
        500..=599 => "The sync service is having trouble; it'll try again later.",
        _ => "The sync service answered strangely.",
    };
    format!("{status} {what}")
}

pub const NOT_SYNC_DATA: &str = "The sync service sent something that isn't sync data (is it down for maintenance?). Nothing was changed.";

/// The encrypted data in a reply from the service (empty when there's none
/// yet) and its date. Anything else (an error page, say) is an error, never
/// "no accounts": that would read as every account deleted elsewhere.
fn sync_data(data: &Json) -> Result<(&str, String), String> {
    let o = data.as_object().ok_or(NOT_SYNC_DATA)?;
    if !o.contains_key("bookmarks") && !o.contains_key("lastUpdated") {
        return Err(NOT_SYNC_DATA.into());
    }
    let text = |k: &str| match o.get(k) {
        None | Some(Json::Null) => Ok(""),
        Some(Json::String(v)) => Ok(v.as_str()),
        Some(_) => Err(NOT_SYNC_DATA.to_string()),
    };
    Ok((text("bookmarks")?, text("lastUpdated")?.to_string()))
}

/// Brings the service and `local` together. Blocking: run it off the UI
/// thread. The caller then merges `outcome.accounts` into what it has now
/// (with the old base), in case accounts changed while this ran.
pub fn sync(t: &dyn Transport, state: &SyncState, key: &[u8; 32], local: &[Account]) -> Result<Outcome, String> {
    let account = state.account.as_ref().ok_or("Sync is off.")?;
    let url = format!("{}/bookmarks/{}", account.service, account.id);
    for _ in 0..ATTEMPTS {
        let data = t.request("GET", &url, None)?;
        let (blob, last_updated) = sync_data(&data)?;
        let tree: Json = if blob.is_empty() {
            json!([])
        } else {
            serde_json::from_str(&decrypt(key, blob)?).map_err(|e| format!("The sync data isn't valid JSON: {e}"))?
        };
        let (remote_seq, wiped) = state_in(&tree);
        let joining = state.base.is_empty() && state.seq == 0;
        if wiped && !joining {
            return Err(WIPED.into());
        }
        if !blob.is_empty() && remote_seq < state.seq {
            return Err(ROLLED_BACK.into());
        }
        let remote = accounts_in(&tree);
        // Nothing on the service at all (new, or emptied there): upload
        // what's here rather than take it as everything deleted.
        let base: &[String] = if blob.is_empty() { &[] } else { &state.base };
        let merged = merge(local, base, &remote);
        let base = merged.iter().map(|a| a.uid.clone()).collect();
        if merged == remote && !wiped && !blob.is_empty() {
            return Ok(Outcome { accounts: merged, base, last_updated, seq: remote_seq, uploaded: false });
        }
        let seq = remote_seq.max(state.seq) + 1;
        let text = sealed_text(with_accounts(&tree, &merged), seq, false);
        let body = json!({ "bookmarks": encrypt(key, &text)?, "lastUpdated": last_updated });
        match t.request("PUT", &url, Some(&body)) {
            Ok(res) => {
                let (_, last_updated) = sync_data(&res)?;
                return Ok(Outcome { accounts: merged, base, last_updated, seq, uploaded: true });
            }
            // Another device saved in between: pull theirs and merge again.
            Err(e) if e.starts_with("409") => continue,
            Err(e) => return Err(e),
        }
    }
    Err("Sync kept clashing with another device; it'll try again.".into())
}

/// Removes PawKey's accounts from the service (anything else there stays),
/// for a sync login that may have fallen into other hands. Other devices
/// then stop syncing with [`WIPED`], keeping their accounts.
pub fn wipe(t: &dyn Transport, state: &SyncState, key: &[u8; 32]) -> Result<(), String> {
    let account = state.account.as_ref().ok_or("Sync is off.")?;
    let url = format!("{}/bookmarks/{}", account.service, account.id);
    for _ in 0..ATTEMPTS {
        let data = t.request("GET", &url, None)?;
        let (blob, last_updated) = sync_data(&data)?;
        let tree: Json = if blob.is_empty() {
            json!([])
        } else {
            serde_json::from_str(&decrypt(key, blob)?).map_err(|e| format!("The sync data isn't valid JSON: {e}"))?
        };
        let seq = state_in(&tree).0.max(state.seq) + 1;
        let text = sealed_text(with_accounts(&tree, &[]), seq, true);
        let body = json!({ "bookmarks": encrypt(key, &text)?, "lastUpdated": last_updated });
        match t.request("PUT", &url, Some(&body)) {
            Ok(_) => return Ok(()),
            Err(e) if e.starts_with("409") => continue,
            Err(e) => return Err(e),
        }
    }
    Err("Sync kept clashing with another device; try again.".into())
}

/// Whether the service changed since `state.last_updated` (a tiny request).
pub fn remote_changed(t: &dyn Transport, state: &SyncState) -> Result<bool, String> {
    let account = state.account.as_ref().ok_or("Sync is off.")?;
    let res = t.request("GET", &format!("{}/bookmarks/{}/lastUpdated", account.service, account.id), None)?;
    Ok(res["lastUpdated"].as_str() != Some(state.last_updated.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// An xBrowserSync service in memory, with its conflict rule.
    #[derive(Default)]
    struct FakeService {
        syncs: RefCell<HashMap<String, (String, u64)>>,
        clock: RefCell<u64>,
        /// Before the next PUT, another device saves this tree first.
        interfere: RefCell<Option<(String, Json)>>,
        /// The next GET of the data gets this instead (a maintenance page, say).
        junk: RefCell<Option<Json>>,
    }

    impl FakeService {
        fn bump(&self) -> String {
            *self.clock.borrow_mut() += 1;
            format!("2026-11-19T00:00:{:02}.000Z", *self.clock.borrow())
        }
        fn put_raw(&self, id: &str, blob: String) {
            let n = {
                self.bump();
                *self.clock.borrow()
            };
            self.syncs.borrow_mut().insert(id.to_string(), (blob, n));
        }
        fn stamp(n: u64) -> String {
            format!("2026-11-19T00:00:{n:02}.000Z")
        }
    }

    impl Transport for FakeService {
        fn request(&self, method: &str, url: &str, body: Option<&Json>) -> Result<Json, String> {
            assert!(url.starts_with("https://sync.test/"), "{url}");
            let path = &url["https://sync.test".len()..];
            let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
            match (method, parts.as_slice()) {
                ("GET", ["info"]) => Ok(json!({ "status": 1 })),
                ("POST", ["bookmarks"]) => {
                    let id = format!("sync{}", self.syncs.borrow().len() + 1);
                    self.put_raw(&id, String::new());
                    Ok(json!({ "id": id }))
                }
                ("GET", ["bookmarks", id]) => {
                    if let Some(j) = self.junk.borrow_mut().take() {
                        return Ok(j);
                    }
                    let s = self.syncs.borrow();
                    let (blob, n) = s.get(*id).ok_or("404 no such sync")?;
                    Ok(json!({ "bookmarks": blob, "lastUpdated": Self::stamp(*n) }))
                }
                ("GET", ["bookmarks", id, "lastUpdated"]) => {
                    let n = self.syncs.borrow().get(*id).ok_or("404 no such sync")?.1;
                    Ok(json!({ "lastUpdated": Self::stamp(n) }))
                }
                ("PUT", ["bookmarks", id]) => {
                    if let Some((key_id, tree)) = self.interfere.borrow_mut().take() {
                        let other = SyncAccount { service: "https://sync.test".into(), id: key_id.clone(), password: "pw".into() };
                        self.put_raw(&key_id, encrypt(&derive_key(&other), &tree.to_string()).unwrap());
                    }
                    let body = body.unwrap();
                    let n = self.syncs.borrow().get(*id).ok_or("404 no such sync")?.1;
                    if body["lastUpdated"].as_str() != Some(Self::stamp(n).as_str()) {
                        return Err("409 sync conflict".into());
                    }
                    self.put_raw(id, body["bookmarks"].as_str().unwrap().to_string());
                    let n = self.syncs.borrow()[*id].1;
                    Ok(json!({ "lastUpdated": Self::stamp(n) }))
                }
                _ => Err(format!("404 {method} {path}")),
            }
        }
    }

    fn acc(issuer: &str) -> Account {
        Account::new(issuer, "me", "JBSWY3DPEHPK3PXP").unwrap()
    }

    /// One device: its accounts and sync state, synced the way the window does.
    fn run(t: &FakeService, state: &mut SyncState, key: &[u8; 32], local: &mut Vec<Account>) {
        let out = sync(t, state, key, local).unwrap();
        *local = merge(local, &state.base, &out.accounts);
        state.base = out.base;
        state.last_updated = out.last_updated;
        state.seq = out.seq;
    }

    fn issuers(v: &[Account]) -> Vec<&str> {
        v.iter().map(|a| a.issuer.as_str()).collect()
    }

    #[test]
    fn two_devices() {
        let t = FakeService::default();
        let mut account = create_account(&t, "https://sync.test/").unwrap();
        assert_eq!(account.service, "https://sync.test");
        account.password = "pw".into();
        let (_, key) = connect(&t, &account).unwrap();
        let mut a_state = SyncState { account: Some(account.clone()), ..Default::default() };
        let mut b_state = a_state.clone();
        let (mut a, mut b) = (vec![acc("GitHub"), acc("Proton")], vec![acc("Bank")]);

        // Both join: nothing lost, both end up with all three.
        run(&t, &mut a_state, &key, &mut a);
        run(&t, &mut b_state, &key, &mut b);
        run(&t, &mut a_state, &key, &mut a);
        assert_eq!(issuers(&a), ["GitHub", "Proton", "Bank"]);
        assert_eq!(issuers(&b), ["Bank", "GitHub", "Proton"]);

        // A deletes Proton, B adds Discord at the same time.
        a.retain(|x| x.issuer != "Proton");
        b.push(acc("Discord"));
        run(&t, &mut a_state, &key, &mut a);
        run(&t, &mut b_state, &key, &mut b);
        run(&t, &mut a_state, &key, &mut a);
        assert_eq!(issuers(&a), ["GitHub", "Bank", "Discord"]);
        assert_eq!(issuers(&b), ["Bank", "GitHub", "Discord"]);
        assert!(!remote_changed(&t, &a_state).unwrap());
        assert!(remote_changed(&t, &SyncState { last_updated: "old".into(), ..a_state.clone() }).unwrap());

        // Nothing to do: nothing uploaded.
        assert!(!sync(&t, &a_state, &key, &a).unwrap().uploaded);

        // A wrong password is refused.
        let mut wrong = account.clone();
        wrong.password = "nope".into();
        assert!(connect(&t, &wrong).unwrap_err().contains("Wrong password"));
    }

    #[test]
    fn junk_from_the_service_deletes_nothing() {
        let t = FakeService::default();
        let mut account = create_account(&t, "https://sync.test").unwrap();
        account.password = "pw".into();
        let key = derive_key(&account);
        let mut state = SyncState { account: Some(account.clone()), ..Default::default() };
        let mut local = vec![acc("GitHub"), acc("Bank")];
        run(&t, &mut state, &key, &mut local);
        assert_eq!(state.base.len(), 2);

        // Not sync data: an error, and nothing here changes.
        for junk in [
            Json::Null,
            json!("<html>Down for maintenance</html>"),
            json!({}),
            json!({ "message": "maintenance" }),
            json!({ "bookmarks": 5 }),
            json!([]),
        ] {
            *t.junk.borrow_mut() = Some(junk.clone());
            let err = sync(&t, &state, &key, &local).err().unwrap_or_else(|| panic!("{junk} was taken as sync data"));
            assert!(err.contains("isn't sync data"), "{err}");
        }
        // Looks like sync data, but there's none: taken as a new, empty
        // service, so what's here goes up again rather than being deleted.
        *t.junk.borrow_mut() = Some(json!({ "bookmarks": "", "lastUpdated": "" }));
        let out = sync(&t, &state, &key, &local).unwrap();
        assert_eq!(issuers(&out.accounts), ["GitHub", "Bank"]);
        t.put_raw(&account.id, String::new());
        run(&t, &mut state, &key, &mut local);
        assert_eq!(issuers(&local), ["GitHub", "Bank"]);
        let mut other = Vec::new();
        run(&t, &mut SyncState { account: Some(account), ..Default::default() }, &key, &mut other);
        assert_eq!(issuers(&other), ["GitHub", "Bank"], "back on the service");
    }

    #[test]
    fn an_old_copy_played_back_is_refused() {
        let t = FakeService::default();
        let mut account = create_account(&t, "https://sync.test").unwrap();
        account.password = "pw".into();
        let key = derive_key(&account);
        let mut state = SyncState { account: Some(account.clone()), ..Default::default() };
        let mut local = vec![acc("GitHub")];
        run(&t, &mut state, &key, &mut local);
        let old = t.syncs.borrow()[&account.id].0.clone();
        local.push(acc("Bank"));
        run(&t, &mut state, &key, &mut local);
        assert_eq!(state.seq, 2);

        // The service (or someone between) hands back the first copy.
        t.put_raw(&account.id, old);
        assert_eq!(sync(&t, &state, &key, &local).err().as_deref(), Some(ROLLED_BACK));
        assert_eq!(issuers(&local), ["GitHub", "Bank"]);
    }

    #[test]
    fn wiping_stops_other_devices_without_deleting_there() {
        let t = FakeService::default();
        let mut account = create_account(&t, "https://sync.test").unwrap();
        account.password = "pw".into();
        let key = derive_key(&account);
        let mut a_state = SyncState { account: Some(account.clone()), ..Default::default() };
        let mut b_state = a_state.clone();
        let (mut a, mut b) = (vec![acc("GitHub")], Vec::new());
        run(&t, &mut a_state, &key, &mut a);
        run(&t, &mut b_state, &key, &mut b);
        assert_eq!(issuers(&b), ["GitHub"]);

        wipe(&t, &a_state, &key).unwrap();
        let tree: Json = serde_json::from_str(&decrypt(&key, &t.syncs.borrow()[&account.id].0).unwrap()).unwrap();
        assert!(accounts_in(&tree).is_empty(), "gone from the service");
        assert_eq!(sync(&t, &b_state, &key, &b).err().as_deref(), Some(WIPED));
        assert_eq!(issuers(&b), ["GitHub"], "still on the other device");

        // Set up again from scratch: it works, and the mark goes.
        let mut c_state = SyncState { account: Some(account), ..Default::default() };
        let mut c = vec![acc("Bank")];
        run(&t, &mut c_state, &key, &mut c);
        assert_eq!(issuers(&c), ["Bank"]);
        assert!(sync(&t, &c_state, &key, &c).is_ok());
    }

    #[test]
    fn data_is_padded_to_4_kib_steps() {
        let t = FakeService::default();
        let mut account = create_account(&t, "https://sync.test").unwrap();
        account.password = "pw".into();
        let key = derive_key(&account);
        let mut state = SyncState { account: Some(account.clone()), ..Default::default() };
        let mut local = Vec::new();
        for n in 0..40 {
            local.push(acc(&format!("Site {n}")));
            run(&t, &mut state, &key, &mut local);
            let text = decrypt(&key, &t.syncs.borrow()[&account.id].0).unwrap();
            assert_eq!(text.len() % PAD_TO, 0, "{} accounts: {} bytes", n + 1, text.len());
            assert_eq!(accounts_in(&serde_json::from_str(&text).unwrap()).len(), n + 1);
        }
    }

    #[test]
    fn conflict_pulls_and_merges_again() {
        let t = FakeService::default();
        let mut account = create_account(&t, "https://sync.test").unwrap();
        account.password = "pw".into();
        let key = derive_key(&account);
        let mut state = SyncState { account: Some(account.clone()), ..Default::default() };
        let mut local = vec![acc("Mine")];
        // Another device saves its own account just before our PUT.
        let theirs = acc("Theirs");
        *t.interfere.borrow_mut() = Some((account.id.clone(), with_accounts(&json!([]), &[theirs])));
        run(&t, &mut state, &key, &mut local);
        assert_eq!(issuers(&local), ["Mine", "Theirs"]);
        let blob = t.request("GET", &format!("https://sync.test/bookmarks/{}", account.id), None).unwrap();
        let tree: Json = serde_json::from_str(&decrypt(&key, blob["bookmarks"].as_str().unwrap()).unwrap()).unwrap();
        // On the service, theirs came first and ours went after it.
        assert_eq!(issuers(&accounts_in(&tree)), ["Theirs", "Mine"]);
    }

    #[test]
    fn leaves_wisps_entries_alone() {
        let tree = json!([{ "id": 1, "title": "[xbs] Other", "children": [
            { "id": 2, "title": "b_Rust", "url": "https://rust-lang.org" },
            { "id": 3, "title": "p_example.com", "url": "https://example.com", "description": "{\"username\":\"u\",\"password\":\"p\"}" }
        ]}, { "id": 4, "title": "[xbs] Toolbar", "children": [] }]);
        let (g, p) = (acc("GitHub"), acc("Proton"));
        let t1 = with_accounts(&tree, &[g.clone(), p.clone()]);
        assert_eq!(issuers(&accounts_in(&t1)), ["GitHub", "Proton"]);
        let other = t1[0]["children"].as_array().unwrap();
        assert_eq!(other[0]["title"], "b_Rust");
        assert_eq!(other[1]["description"], tree[0]["children"][1]["description"]);
        assert_eq!((other[2]["id"].clone(), other[3]["id"].clone()), (json!(5), json!(6)));
        assert!(!other[2]["url"].as_str().unwrap().contains(&g.secret), "no secret in the url");
        // Removing one keeps the other's id and everything that isn't ours.
        let t2 = with_accounts(&t1, &[p.clone()]);
        let other = t2[0]["children"].as_array().unwrap();
        assert_eq!(other.len(), 3);
        assert_eq!(other[2]["id"], 6);
        assert_eq!(t2[1], tree[1]);
        assert_eq!(with_accounts(&t2, &[]), tree);
    }

    #[test]
    fn crypto_matches_wisp() {
        let key = [7u8; 32];
        let blob = encrypt(&key, r#"[{"title":"t_héllo"}]"#).unwrap();
        assert_eq!(*decrypt(&key, &blob).unwrap(), r#"[{"title":"t_héllo"}]"#);
        assert!(decrypt(&[8u8; 32], &blob).is_err());
        // "abcabc": literal "abc" + 2-byte reference (length 3, distance 3).
        assert_eq!(lzutf8_decompress(&[b'a', b'b', b'c', 0b1100_0011, 3]), b"abcabc");
        assert_eq!(lzutf8_decompress(&[b'w', b'x', b'y', b'z', 0b1110_0010, 0, 4]), b"wxyzwx");
    }

    #[test]
    fn proxies() {
        assert_eq!(check_proxy("").unwrap(), "");
        assert_eq!(check_proxy(" socks5h://127.0.0.1:9050/ ").unwrap(), TOR_PROXY);
        assert_eq!(check_proxy("socks5://[::1]:9150").unwrap(), "socks5://[::1]:9150");
        for bad in ["http://proxy:8080", "socks5://host", "socks5://:9050", "socks5://h:0", "socks5://a b:1", "127.0.0.1:9050"] {
            assert!(check_proxy(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn services_are_https_or_on_this_computer() {
        for ok in ["https://api.xbrowsersync.org", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080/x", "http://abcdef.onion"] {
            assert!(service_is_private(ok), "{ok}");
        }
        for bad in ["http://sync.example.org", "http://192.168.1.5:8080", "http://localhost.example.org", "ftp://x.org", "x.org", "", "https://"] {
            assert!(!service_is_private(bad), "{bad}");
        }
    }
}

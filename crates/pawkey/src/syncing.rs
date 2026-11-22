//! Sync, the window's side: the Sync dialog, the toolbar button, and
//! running `pawkey_core::sync` off the UI thread over libsoup (as Wisp does).
//!
//! Sync runs when the vault is unlocked, after an account is added or
//! deleted, when the button is clicked, and every minute or two otherwise (a
//! tiny "has it changed?" request unless something here changed; the
//! interval varies, so the requests don't keep a beat).

use std::collections::BTreeSet;

use glib::translate::IntoGlib;
use pawkey_core::sync::{self, Key, SyncAccount, SyncState, Transport};
use serde_json::Value as Json;
use soup::prelude::*;

use super::*;

/// A random time between checks, 45 s to 2 min.
fn check_every() -> Duration {
    Duration::from_secs(glib::random_int_range(45, 121) as u64)
}

pub struct SyncUi {
    pub button: gtk::Button,
    /// The derived key (250 000 PBKDF2 rounds), kept while unlocked.
    key: RefCell<Option<(SyncAccount, Key)>>,
    running: Cell<bool>,
    /// Another run wanted while one was going; `true` if it must not be skipped.
    again: Cell<Option<bool>>,
    last_run: Cell<Option<Instant>>,
    next_in: Cell<Duration>,
    status: RefCell<String>,
    status_labels: RefCell<Vec<glib::WeakRef<gtk::Label>>>,
}

impl SyncUi {
    pub fn new() -> SyncUi {
        let button = gtk::Button::from_icon_name("emblem-synchronizing-symbolic");
        button.set_visible(false);
        button.set_tooltip_text(Some("Sync now"));
        SyncUi {
            button,
            key: RefCell::new(None),
            running: Cell::new(false),
            again: Cell::new(None),
            last_run: Cell::new(None),
            next_in: Cell::new(check_every()),
            status: RefCell::new(String::new()),
            status_labels: RefCell::new(Vec::new()),
        }
    }

    /// When the vault locks: the key goes with it.
    pub fn forget(&self) {
        *self.key.borrow_mut() = None;
        self.again.set(None);
        self.last_run.set(None);
        self.status.borrow_mut().clear();
    }
}

/// libsoup, blocking: made and used on one worker thread. `proxy` is
/// empty (the system's settings) or a checked `socks5://host:port`.
struct Soup(soup::Session);

impl Soup {
    fn new(proxy: &str) -> Soup {
        let session = soup::Session::new();
        session.set_timeout(30);
        if !proxy.is_empty() {
            session.set_proxy_resolver(Some(&gio::SimpleProxyResolver::new(Some(proxy), &[] as &[&str])));
        }
        Soup(session)
    }
}

impl Transport for Soup {
    fn request(&self, method: &str, url: &str, body: Option<&Json>) -> Result<Json, String> {
        if !sync::service_is_private(url) {
            return Err("The sync service's address must start with https://.".into());
        }
        let msg = soup::Message::new(method, url).map_err(|e| format!("Bad address {url}: {e}"))?;
        // A redirect could lead anywhere, plain HTTP included: not followed.
        msg.add_flags(soup::MessageFlags::NO_REDIRECT);
        if let Some(b) = body {
            let bytes = glib::Bytes::from_owned(b.to_string().into_bytes());
            msg.set_request_body_from_bytes(Some("application/json"), Some(&bytes));
        }
        let bytes = self.0.send_and_read(&msg, gio::Cancellable::NONE).map_err(|e| format!("Can't reach the sync service: {e}"))?;
        let status = msg.status().into_glib();
        if !(200..300).contains(&status) {
            return Err(sync::http_error(status as u16));
        }
        let parsed: Result<Json, _> = serde_json::from_slice(&bytes);
        // A web page instead of JSON (a captive portal, maintenance): an error.
        parsed.map_err(|_| sync::NOT_SYNC_DATA.to_string())
    }
}

fn uid_set(accounts: &[Account]) -> BTreeSet<&str> {
    accounts.iter().map(|a| a.uid.as_str()).collect()
}

fn clock() -> String {
    glib::DateTime::now_local().ok().and_then(|d| d.format("%H:%M").ok()).map(|s| s.to_string()).unwrap_or_default()
}

/// The proxy box: empty for the system's settings, or socks5://host:port.
fn proxy_entry(text: &str) -> gtk::Entry {
    let e = gtk::Entry::builder().text(text).placeholder_text(format!("None, or {} for Tor", sync::TOR_PROXY)).build();
    e.set_input_hints(gtk::InputHints::NO_SPELLCHECK | gtk::InputHints::PRIVATE);
    e
}

impl App {
    fn sync_account(&self) -> Option<SyncAccount> {
        self.vault.borrow().as_ref().and_then(|v| v.sync.account.clone())
    }

    pub(super) fn refresh_sync_button(&self) {
        let on = self.sync_account().is_some();
        self.sync.button.set_visible(on);
        let status = self.sync.status.borrow();
        let tip = if self.sync.running.get() {
            "Syncing…".to_string()
        } else if status.is_empty() {
            "Sync now".to_string()
        } else {
            format!("{status}. Click to sync now.")
        };
        self.sync.button.set_tooltip_text(Some(&tip));
    }

    fn set_sync_status(&self, s: String) {
        *self.sync.status.borrow_mut() = s.clone();
        self.sync.status_labels.borrow_mut().retain(|w| match w.upgrade() {
            Some(l) => {
                l.set_text(&s);
                true
            }
            None => false,
        });
        self.refresh_sync_button();
    }

    pub(super) fn sync_tick(&self) {
        if !self.sync.running.get() && self.sync.last_run.get().is_some_and(|t| t.elapsed() >= self.sync.next_in.get()) {
            self.sync_soon(false);
        }
    }

    /// Syncs now, or right after the run that's going. `force`: talk to the
    /// service even if nothing seems to have changed.
    pub(super) fn sync_soon(&self, force: bool) {
        let Some((state, local)) = self.vault.borrow().as_ref().filter(|v| v.sync.account.is_some()).map(|v| (v.sync.clone(), v.accounts.clone()))
        else {
            return;
        };
        if self.sync.running.get() {
            self.sync.again.set(Some(force || self.sync.again.get() == Some(true)));
            return;
        }
        let account = state.account.clone().unwrap();
        let key = self.sync.key.borrow().as_ref().filter(|(a, _)| *a == account).map(|(_, k)| k.clone());
        self.sync.running.set(true);
        self.sync.last_run.set(Some(Instant::now()));
        self.sync.next_in.set(check_every());
        self.sync.button.set_sensitive(false);
        self.refresh_sync_button();
        let (a, old_base, acct) = (self.clone(), state.base.clone(), account.clone());
        glib::spawn_future_local(async move {
            let res = gio::spawn_blocking(move || -> Result<(Key, Option<sync::Outcome>), String> {
                let t = Soup::new(&state.proxy);
                let key = key.unwrap_or_else(|| sync::derive_key(&account));
                let dirty = uid_set(&local) != state.base.iter().map(String::as_str).collect();
                if !force && !dirty && !sync::remote_changed(&t, &state)? {
                    return Ok((key, None));
                }
                let out = sync::sync(&t, &state, &key, &local)?;
                Ok((key, Some(out)))
            })
            .await
            .unwrap_or_else(|_| Err("Sync stopped unexpectedly.".into()));
            a.sync_done(acct, old_base, res);
        });
    }

    fn sync_done(&self, account: SyncAccount, old_base: Vec<String>, res: Result<(Key, Option<sync::Outcome>), String>) {
        self.sync.running.set(false);
        self.sync.button.set_sensitive(true);
        // Locked meanwhile, or sync turned off or switched: this result is stale.
        if self.sync_account().as_ref() != Some(&account) {
            self.refresh_sync_button();
            return;
        }
        match res {
            Ok((key, outcome)) => {
                *self.sync.key.borrow_mut() = Some((account, key));
                let mut changed = false;
                if let Some(out) = outcome {
                    let mut vault = self.vault.borrow_mut();
                    let v = vault.as_mut().unwrap();
                    // Accounts may have been added or deleted here while it ran.
                    let merged = sync::merge(&v.accounts, &old_base, &out.accounts);
                    let before = (v.accounts.clone(), v.sync.clone());
                    changed = merged != v.accounts;
                    v.accounts = merged;
                    v.sync.base = out.base.clone();
                    v.sync.last_updated = out.last_updated.clone();
                    v.sync.seq = out.seq;
                    if let Err(e) = v.save() {
                        (v.accounts, v.sync) = before;
                        drop(vault);
                        self.set_sync_status(format!("Synced, but couldn't save here: {e}"));
                        return;
                    }
                    if uid_set(&v.accounts) != v.sync.base.iter().map(String::as_str).collect() {
                        self.sync.again.set(Some(self.sync.again.get().unwrap_or(false)));
                    }
                }
                if changed {
                    self.rebuild();
                }
                self.set_sync_status(format!("Synced at {}", clock()));
            }
            Err(e) => self.set_sync_status(format!("Couldn't sync: {e}")),
        }
        if let Some(force) = self.sync.again.take() {
            self.sync_soon(force);
        }
    }

    /// Saves a new sync login and syncs straight away.
    fn turn_sync_on(&self, account: SyncAccount, key: Key, proxy: String) -> Result<(), String> {
        let mut vault = self.vault.borrow_mut();
        let v = vault.as_mut().ok_or("PawKey is locked.")?;
        let before = v.sync.clone();
        v.sync = SyncState { account: Some(account.clone()), proxy, ..Default::default() };
        if let Err(e) = v.save() {
            v.sync = before;
            return Err(format!("Couldn't save: {e}"));
        }
        drop(vault);
        *self.sync.key.borrow_mut() = Some((account, key));
        self.set_sync_status(String::new());
        self.sync_soon(true);
        Ok(())
    }

    fn set_proxy(&self, proxy: String) -> Result<(), String> {
        let mut vault = self.vault.borrow_mut();
        let v = vault.as_mut().ok_or("PawKey is locked.")?;
        let before = std::mem::replace(&mut v.sync.proxy, proxy);
        if let Err(e) = v.save() {
            v.sync.proxy = before;
            return Err(format!("Couldn't save: {e}"));
        }
        Ok(())
    }

    fn turn_sync_off(&self) -> Result<(), String> {
        let mut vault = self.vault.borrow_mut();
        let v = vault.as_mut().ok_or("PawKey is locked.")?;
        let before = std::mem::take(&mut v.sync);
        if let Err(e) = v.save() {
            v.sync = before;
            return Err(format!("Couldn't save: {e}"));
        }
        drop(vault);
        self.sync.forget();
        self.refresh_sync_button();
        Ok(())
    }

    pub(super) fn sync_dialog(&self) {
        let (win, content, done) = dialog(&self.window, "Sync", "Done");
        if let Some(cancel) = done.prev_sibling() {
            cancel.set_visible(false);
        }
        let w = win.clone();
        done.connect_clicked(move |_| w.close());
        match self.sync_account() {
            None => self.sync_off_page(&win, &content),
            Some(account) => self.sync_on_page(&win, &content, &account),
        }
        win.present();
    }

    fn sync_off_page(&self, win: &gtk::Window, content: &gtk::Box) {
        let intro = gtk::Label::builder()
            .label(
                "Sync keeps your accounts the same on every computer with PawKey, through xBrowserSync, the way Wisp syncs. \
                 They're encrypted here before they're sent: the service only ever sees random bytes. It's off until you turn it on.",
            )
            .wrap(true)
            .xalign(0.0)
            .build();
        let service = gtk::Entry::builder().input_hints(PRIVATE_INPUT).text(sync::DEFAULT_SERVICE).build();
        let service_label = gtk::Label::builder().label("Service").xalign(0.0).build();
        service_label.add_css_class("dim");
        let proxy = proxy_entry("");
        let proxy_label = gtk::Label::builder().label("Proxy (optional)").xalign(0.0).build();
        proxy_label.add_css_class("dim");
        let new_btn = gtk::Button::with_label("Make a new sync ID");
        new_btn.add_css_class("suggested-action");
        let or = gtk::Label::builder().label("Or use a sync ID you already have, from another PawKey (or Wisp's):").wrap(true).xalign(0.0).build();
        let id = gtk::Entry::builder().input_hints(PRIVATE_INPUT).placeholder_text("Sync ID").build();
        let pw = gtk::PasswordEntry::builder().show_peek_icon(true).placeholder_text("Sync password").build();
        let connect_btn = gtk::Button::with_label("Connect");
        let spinner = gtk::Spinner::new();
        let err = error_label();
        for w in [
            intro.upcast_ref::<gtk::Widget>(),
            service_label.upcast_ref(),
            service.upcast_ref(),
            proxy_label.upcast_ref(),
            proxy.upcast_ref(),
            new_btn.upcast_ref(),
            gtk::Separator::new(gtk::Orientation::Horizontal).upcast_ref(),
            or.upcast_ref(),
            id.upcast_ref(),
            pw.upcast_ref(),
            connect_btn.upcast_ref(),
            spinner.upcast_ref(),
            err.upcast_ref(),
        ] {
            content.append(w);
        }

        let busy = {
            let (b1, b2, sp) = (new_btn.clone(), connect_btn.clone(), spinner.clone());
            move |on: bool| {
                b1.set_sensitive(!on);
                b2.set_sensitive(!on);
                sp.set_spinning(on);
            }
        };
        let finish = {
            let (a, win, err, busy) = (self.clone(), win.clone(), err.clone(), busy.clone());
            move |res: Result<(SyncAccount, Key, String), String>| {
                busy(false);
                match res.and_then(|(acct, key, proxy)| a.turn_sync_on(acct, key, proxy)) {
                    Ok(()) => {
                        win.close();
                        a.sync_dialog();
                    }
                    Err(e) => show_error(&err, &e),
                }
            }
        };

        let (s2, p2, busy2, finish2, e2) = (service.clone(), proxy.clone(), busy.clone(), finish.clone(), err.clone());
        new_btn.connect_clicked(move |_| {
            let proxy = match sync::check_proxy(&p2.text()) {
                Ok(p) => p,
                Err(e) => return show_error(&e2, &e),
            };
            busy2(true);
            let service = s2.text().to_string();
            let finish = finish2.clone();
            glib::spawn_future_local(async move {
                let res = gio::spawn_blocking(move || {
                    let account = sync::create_account(&Soup::new(&proxy), &service)?;
                    let key = sync::derive_key(&account);
                    Ok((account, key, proxy))
                })
                .await
                .unwrap_or_else(|_| Err("Something went wrong.".into()));
                finish(res);
            });
        });
        let err2 = err.clone();
        connect_btn.connect_clicked(move |_| {
            let account = SyncAccount { service: service.text().to_string(), id: id.text().trim().to_string(), password: pw.text().to_string() };
            if account.id.is_empty() || account.password.is_empty() {
                return show_error(&err2, "Type the sync ID and its password.");
            }
            let proxy = match sync::check_proxy(&proxy.text()) {
                Ok(p) => p,
                Err(e) => return show_error(&err2, &e),
            };
            busy(true);
            let finish = finish.clone();
            glib::spawn_future_local(async move {
                let res = gio::spawn_blocking(move || sync::connect(&Soup::new(&proxy), &account).map(|(a, k)| (a, k, proxy)))
                    .await
                    .unwrap_or_else(|_| Err("Something went wrong.".into()));
                finish(res);
            });
        });
    }

    fn sync_on_page(&self, win: &gtk::Window, content: &gtk::Box, account: &SyncAccount) {
        let intro = gtk::Label::builder()
            .label("Sync is on: every computer with this sync ID has the same accounts. They're encrypted here before they're sent.")
            .wrap(true)
            .xalign(0.0)
            .build();
        let status = gtk::Label::builder().label(self.sync.status.borrow().as_str()).wrap(true).xalign(0.0).build();
        status.add_css_class("dim");
        self.sync.status_labels.borrow_mut().push(status.downgrade());

        let grid = gtk::Grid::builder().row_spacing(6).column_spacing(12).build();
        let row = |r: i32, label: &str, value: &gtk::Widget, copy: Option<(String, &'static str)>| {
            let l = gtk::Label::builder().label(label).xalign(0.0).build();
            l.add_css_class("dim");
            grid.attach(&l, 0, r, 1, 1);
            value.set_hexpand(true);
            grid.attach(value, 1, r, 1, 1);
            if let Some((text, what)) = copy {
                let b = gtk::Button::from_icon_name("edit-copy-symbolic");
                b.add_css_class("flat");
                b.set_tooltip_text(Some(&format!("Copy the {what}")));
                let a = self.clone();
                b.connect_clicked(move |_| a.copy_text(text.clone(), &format!("Copied the {what}.")));
                grid.attach(&b, 2, r, 1, 1);
            }
        };
        let label = |t: &str| gtk::Label::builder().label(t).xalign(0.0).selectable(true).ellipsize(gtk::pango::EllipsizeMode::Middle).build();
        row(0, "Service", label(&account.service).upcast_ref(), None);
        row(1, "Sync ID", label(&account.id).upcast_ref(), Some((account.id.clone(), "sync ID")));
        let pw = gtk::PasswordEntry::builder().text(&account.password).show_peek_icon(true).editable(false).build();
        row(2, "Password", pw.upcast_ref(), Some((account.password.clone(), "sync password")));
        let current = self.vault.borrow().as_ref().map(|v| v.sync.proxy.clone()).unwrap_or_default();
        let proxy = proxy_entry(&current);
        let proxy_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let save_proxy = gtk::Button::with_label("Use");
        proxy.set_hexpand(true);
        proxy_box.append(&proxy);
        proxy_box.append(&save_proxy);
        row(3, "Proxy", proxy_box.upcast_ref(), None);

        let how = gtk::Label::builder()
            .label(
                "To add another computer: open PawKey there, then ☰ → Sync… → use a sync ID you already have, and type these two. \
                 Keep the password to yourself: with the sync ID, it opens your accounts.",
            )
            .wrap(true)
            .xalign(0.0)
            .build();
        how.add_css_class("dim");
        let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let now_btn = gtk::Button::with_label("Sync now");
        let off_btn = gtk::Button::with_label("Turn off sync…");
        off_btn.add_css_class("destructive-action");
        buttons.append(&now_btn);
        buttons.append(&off_btn);
        let err = error_label();
        for w in [intro.upcast_ref::<gtk::Widget>(), status.upcast_ref(), grid.upcast_ref(), how.upcast_ref(), buttons.upcast_ref(), err.upcast_ref()]
        {
            content.append(w);
        }

        let a = self.clone();
        now_btn.connect_clicked(move |_| a.sync_soon(true));
        let (a, e2) = (self.clone(), err.clone());
        save_proxy.connect_clicked(move |_| match sync::check_proxy(&proxy.text()).and_then(|p| a.set_proxy(p.clone()).map(|_| p)) {
            Ok(p) => {
                proxy.set_text(&p);
                show_error(&e2, "");
                a.notify(if p.is_empty() { "Sync uses the system's proxy settings." } else { "Sync goes through the proxy." });
                a.sync_soon(true);
            }
            Err(e) => show_error(&e2, &e),
        });
        let (a, win) = (self.clone(), win.clone());
        off_btn.connect_clicked(move |_| {
            let ask = gtk::AlertDialog::builder()
                .modal(true)
                .message("Turn off sync on this computer?")
                .detail(
                    "Your accounts stay here. On the service they can stay for your other computers, or be removed: then nobody \
                     with the sync password can get them from there, and your other computers stop syncing (keeping their accounts).",
                )
                .buttons(["Cancel", "Turn off", "Turn off and remove them from the service"])
                .cancel_button(0)
                .default_button(0)
                .build();
            let (a, win, err) = (a.clone(), win.clone(), err.clone());
            glib::spawn_future_local(async move {
                let remove = match ask.choose_future(Some(&win)).await {
                    Ok(1) => false,
                    Ok(2) => true,
                    _ => return,
                };
                if remove {
                    let Some((state, key)) = a.vault.borrow().as_ref().map(|v| v.sync.clone()).and_then(|st| {
                        let key = a.sync.key.borrow().as_ref().filter(|(acc, _)| Some(acc) == st.account.as_ref()).map(|(_, k)| k.clone());
                        Some((st, key))
                    }) else {
                        return;
                    };
                    let res = gio::spawn_blocking(move || {
                        let key = match key {
                            Some(k) => k,
                            None => sync::derive_key(state.account.as_ref().ok_or("Sync is off.")?),
                        };
                        sync::wipe(&Soup::new(&state.proxy), &state, &key)
                    })
                    .await
                    .unwrap_or_else(|_| Err("Something went wrong.".into()));
                    if let Err(e) = res {
                        return show_error(&err, &format!("Couldn't remove them from the service, so sync is still on: {e}"));
                    }
                }
                match a.turn_sync_off() {
                    Ok(()) => {
                        win.close();
                        a.notify(if remove { "Sync is off, and PawKey's accounts are off the service." } else { "Sync is off." });
                    }
                    Err(e) => show_error(&err, &e),
                }
            });
        });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// A small xBrowserSync service on 127.0.0.1: create, get, lastUpdated,
    /// and put with the conflict rule. Answers one request per connection.
    fn fake_service() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let syncs: Arc<Mutex<(HashMap<String, (String, u64)>, u64)>> = Arc::default();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let (method, path) = {
                    let mut p = line.split_whitespace();
                    (p.next().unwrap_or("").to_string(), p.next().unwrap_or("").to_string())
                };
                let mut len = 0;
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let body: Json = serde_json::from_slice(&body).unwrap_or(Json::Null);
                let stamp = |n: u64| format!("2026-11-19T00:00:{n:02}.000Z");
                let mut guard = syncs.lock().unwrap();
                let (map, clock) = &mut *guard;
                let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
                let (status, answer) = match (method.as_str(), parts.as_slice()) {
                    ("GET", ["info"]) => (200, serde_json::json!({ "status": 1 })),
                    ("POST", ["bookmarks"]) => {
                        *clock += 1;
                        let id = format!("fake{}", map.len() + 1);
                        map.insert(id.clone(), (String::new(), *clock));
                        (200, serde_json::json!({ "id": id }))
                    }
                    ("GET", ["bookmarks", id]) => match map.get(*id) {
                        Some((blob, n)) => (200, serde_json::json!({ "bookmarks": blob, "lastUpdated": stamp(*n) })),
                        None => (404, serde_json::json!({ "message": "no such sync" })),
                    },
                    ("GET", ["bookmarks", id, "lastUpdated"]) => match map.get(*id) {
                        Some((_, n)) => (200, serde_json::json!({ "lastUpdated": stamp(*n) })),
                        None => (404, serde_json::json!({ "message": "no such sync" })),
                    },
                    ("PUT", ["bookmarks", id]) => match map.get(*id).map(|(_, n)| *n) {
                        Some(n) if body["lastUpdated"].as_str() == Some(stamp(n).as_str()) => {
                            *clock += 1;
                            map.insert(id.to_string(), (body["bookmarks"].as_str().unwrap_or("").to_string(), *clock));
                            (200, serde_json::json!({ "lastUpdated": stamp(*clock) }))
                        }
                        Some(_) => (409, serde_json::json!({ "message": "sync conflict" })),
                        None => (404, serde_json::json!({ "message": "no such sync" })),
                    },
                    _ => (404, serde_json::json!({ "message": "not found" })),
                };
                drop(guard);
                let text = answer.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
            }
        });
        url
    }

    fn spin_until(done: impl Fn() -> bool) -> bool {
        let ctx = glib::MainContext::default();
        let start = Instant::now();
        while !done() && start.elapsed() < Duration::from_secs(30) {
            ctx.iteration(false);
        }
        done()
    }

    fn device(gapp: &gtk::Application, dir: &std::path::Path, name: &str) -> App {
        let app = App::build(gapp, dir.join(name).join("pawkey.vault"));
        app.pw1.set_text("pw-test-123");
        app.pw2.set_text("pw-test-123");
        app.unlock();
        assert!(spin_until(|| app.vault.borrow().is_some()));
        app
    }

    fn add(app: &App, issuer: &str) {
        app.vault.borrow_mut().as_mut().unwrap().accounts.push(Account::new(issuer, "me", "JBSWY3DPEHPK3PXP").unwrap());
        assert!(app.save_or(|_| ()));
        app.rebuild();
        app.sync_soon(false);
    }

    fn issuers(app: &App) -> Vec<String> {
        let mut v: Vec<String> = app.vault.borrow().as_ref().unwrap().accounts.iter().map(|a| a.issuer.clone()).collect();
        v.sort();
        v
    }

    fn settled(app: &App) -> bool {
        !app.sync.running.get() && app.sync.again.get().is_none()
    }

    /// Two windows, two vaults, one sync ID, over HTTP through libsoup.
    /// Run from `tests::window` (GTK allows one thread only).
    pub(crate) fn two_windows_sync() {
        let service = fake_service();
        let dir = std::env::temp_dir().join(format!("pawkey-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let gapp =
            gtk::Application::builder().application_id("io.github.anti_ghostsec.PawKeySyncTest").flags(gio::ApplicationFlags::NON_UNIQUE).build();
        gapp.register(None::<&gio::Cancellable>).unwrap();
        let (a, b) = (device(&gapp, &dir, "a"), device(&gapp, &dir, "b"));
        add(&a, "GitHub");
        add(&b, "Bank");

        // A makes a sync ID; B joins with it.
        let account = sync::create_account(&Soup::new(""), &service).unwrap();
        let key = sync::derive_key(&account);
        a.turn_sync_on(account.clone(), key, String::new()).unwrap();
        assert!(spin_until(|| settled(&a) && a.sync.status.borrow().starts_with("Synced")), "{}", a.sync.status.borrow());
        assert!(a.sync.button.property::<bool>("visible"));
        let (account_b, key_b) = sync::connect(&Soup::new(""), &account).unwrap();
        b.turn_sync_on(account_b, key_b, String::new()).unwrap();
        assert!(spin_until(|| settled(&b) && b.sync.status.borrow().starts_with("Synced")), "{}", b.sync.status.borrow());
        a.sync_soon(true);
        assert!(spin_until(|| settled(&a)));
        assert_eq!(issuers(&a), ["Bank", "GitHub"]);
        assert_eq!(issuers(&b), ["Bank", "GitHub"]);
        assert_eq!(a.rows.borrow().len(), 2, "the list shows what came in");

        // B deletes GitHub; A hears of it.
        let uid = b.vault.borrow().as_ref().unwrap().accounts.iter().find(|x| x.issuer == "GitHub").unwrap().uid.clone();
        b.vault.borrow_mut().as_mut().unwrap().accounts.retain(|x| x.uid != uid);
        assert!(b.save_or(|_| ()));
        b.sync_soon(false);
        assert!(spin_until(|| settled(&b)));
        a.sync_soon(false);
        assert!(spin_until(|| settled(&a) && issuers(&a) == ["Bank"]), "{:?}", issuers(&a));

        // It survives locking: the sync login is in the vault.
        a.lock();
        a.pw1.set_text("pw-test-123");
        a.unlock();
        assert!(spin_until(|| a.vault.borrow().is_some() && settled(&a) && a.sync.status.borrow().starts_with("Synced")));
        assert_eq!(a.sync_account().unwrap().id, account.id);

        // Turned off: forgotten here, the accounts stay.
        a.turn_sync_off().unwrap();
        assert!(a.sync_account().is_none() && !a.sync.button.property::<bool>("visible"));
        assert_eq!(issuers(&a), ["Bank"]);

        a.window.destroy();
        b.window.destroy();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

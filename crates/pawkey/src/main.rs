// No console window behind the app on Windows.
#![cfg_attr(windows, windows_subsystem = "windows")]

//! PawKey's window: the password box, the list of codes, and the dialogs to
//! add, delete and reseal. Everything secret lives in `pawkey-core`.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gtk::prelude::*;
use gtk::{gdk, gio, glib};
use pawkey_core::keyfile;
use pawkey_core::qr;
use pawkey_core::totp::{self, Account, Algo};
use pawkey_core::vault::{self, Vault};
use zeroize::Zeroizing;

mod syncing;

const APP_ID: &str = "io.github.anti_ghostsec.PawKey";
const AUTO_LOCK: Duration = Duration::from_secs(5 * 60);
const CLIPBOARD_CLEAR_SECS: u32 = 30;
const ICON_SVG: &[u8] = include_bytes!("../../../icons/pawkey.svg");

const CSS: &str = "
.code { font-family: monospace; font-size: 20pt; font-weight: bold; }
.code.expiring { color: @error_color; }
.secs { font-family: monospace; min-width: 3em; }
.heading-big { font-size: 18pt; font-weight: bold; }
.dim { opacity: 0.65; }
.error-text { color: @error_color; }
";

/// Dark is the default; this file's being there means light.
fn light_theme_marker() -> PathBuf {
    vault::config_dir().join("light-theme")
}

/// Ctrl, or ⌘ on a Mac: what the shortcuts are called.
const MOD: &str = if cfg!(target_os = "macos") { "⌘" } else { "Ctrl+" };

/// On Windows and macOS, GTK and PawKey's icon travel with the program
/// (`share/` next to it, or in the app bundle's Resources): tell GTK where.
fn bundled_icons() {
    let Some(exe_dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) else { return };
    let Some(display) = gdk::Display::default() else { return };
    let theme = gtk::IconTheme::for_display(&display);
    for dir in [exe_dir.join("share/icons"), exe_dir.join("../Resources/share/icons")] {
        if dir.is_dir() {
            theme.add_search_path(&dir);
        }
    }
}

fn set_dark(dark: bool) {
    if let Some(s) = gtk::Settings::default() {
        s.set_gtk_application_prefer_dark_theme(dark);
    }
}

fn load_css() {
    let css = gtk::CssProvider::new();
    css.load_from_string(CSS);
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(&display, &css, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `123456` → `123 456`, `12345678` → `1234 5678`.
fn pretty(code: &str) -> String {
    let half = code.len() / 2;
    format!("{} {}", &code[..half], &code[half..])
}

fn logo() -> Option<gdk::Texture> {
    gdk::Texture::from_bytes(&glib::Bytes::from_static(ICON_SVG)).ok()
}

/// The text of every QR code in a picture.
async fn qr_from_texture(t: gdk::Texture) -> Vec<String> {
    let (w, h) = (t.width() as usize, t.height() as usize);
    let stride = w * 4;
    let mut buf = vec![0u8; stride * h];
    t.download(&mut buf, stride);
    gio::spawn_blocking(move || qr::decode_grey(w, h, &qr::grey_from_bgra_premultiplied(&buf, w, h, stride))).await.unwrap_or_default()
}

/// What a QR code's text means for us: a setup link, or why not.
fn setup_link(found: Vec<String>) -> Result<String, String> {
    if found.is_empty() {
        return Err("No QR code found in that picture.".into());
    }
    if let Some(uri) = found.iter().find(|s| s.starts_with("otpauth://")) {
        return Ok(uri.clone());
    }
    if found.iter().any(|s| s.starts_with("otpauth-migration://")) {
        return Err("That's a Google Authenticator export code; those can't be read yet. Add each account from its own setup code.".into());
    }
    Err("That QR code isn't a two-factor setup code.".into())
}

/// A modal dialog with Cancel and an action button along its bottom. No
/// title bar of GTK's own: the window manager's frame is the only one.
fn dialog(parent: &gtk::ApplicationWindow, title: &str, ok_label: &str) -> (gtk::Window, gtk::Box, gtk::Button) {
    let win = gtk::Window::builder().title(title).modal(true).transient_for(parent).default_width(440).resizable(false).build();
    let cancel = gtk::Button::with_label("Cancel");
    let ok = gtk::Button::with_label(ok_label);
    ok.add_css_class("suggested-action");
    let buttons = gtk::Box::builder().spacing(6).halign(gtk::Align::End).build();
    buttons.append(&cancel);
    buttons.append(&ok);
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    let outer = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    outer.append(&content);
    outer.append(&buttons);
    win.set_child(Some(&outer));
    let w = win.clone();
    cancel.connect_clicked(move |_| w.close());
    let keys = gtk::EventControllerKey::new();
    let w = win.clone();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Escape {
            w.close();
            glib::Propagation::Stop
        } else {
            glib::Propagation::Proceed
        }
    });
    win.add_controller(keys);
    win.set_default_widget(Some(&ok));
    (win, content, ok)
}

fn error_label() -> gtk::Label {
    let l = gtk::Label::builder().wrap(true).xalign(0.0).visible(false).build();
    l.add_css_class("error-text");
    l
}

fn show_error(label: &gtk::Label, msg: &str) {
    label.set_text(msg);
    label.set_visible(!msg.is_empty());
}

// ---------------------------------------------------------------- keyfiles

/// "Keyfiles…" and "Clear" buttons, a line saying which are chosen, and
/// files dropped on any widget given to `accept_drops`.
#[derive(Clone)]
struct Keyfiles {
    paths: Rc<RefCell<Vec<PathBuf>>>,
    label: gtk::Label,
    widget: gtk::Box,
}

impl Keyfiles {
    fn new() -> Keyfiles {
        let widget = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let label = gtk::Label::builder().xalign(0.0).hexpand(true).ellipsize(gtk::pango::EllipsizeMode::Middle).build();
        label.add_css_class("dim");
        let choose = gtk::Button::with_label("Keyfiles…");
        let clear = gtk::Button::from_icon_name("edit-clear-symbolic");
        clear.set_tooltip_text(Some("Use no keyfiles"));
        widget.append(&label);
        widget.append(&choose);
        widget.append(&clear);
        let kf = Keyfiles { paths: Rc::default(), label, widget };
        kf.refresh();

        let k = kf.clone();
        choose.connect_clicked(move |b| {
            let parent = b.root().and_downcast::<gtk::Window>();
            let dialog = gtk::FileDialog::builder().title("Choose keyfiles").modal(true).build();
            let k = k.clone();
            glib::spawn_future_local(async move {
                if let Ok(files) = dialog.open_multiple_future(parent.as_ref()).await {
                    for i in 0..files.n_items() {
                        if let Some(p) = files.item(i).and_downcast::<gio::File>().and_then(|f| f.path()) {
                            k.add(p);
                        }
                    }
                }
            });
        });
        let k = kf.clone();
        clear.connect_clicked(move |_| k.set(Vec::new()));
        kf
    }

    fn add(&self, p: PathBuf) {
        if !self.paths.borrow().contains(&p) {
            self.paths.borrow_mut().push(p);
        }
        self.refresh();
    }

    fn set(&self, v: Vec<PathBuf>) {
        *self.paths.borrow_mut() = v;
        self.refresh();
    }

    fn get(&self) -> Vec<PathBuf> {
        self.paths.borrow().clone()
    }

    fn refresh(&self) {
        let p = self.paths.borrow();
        let name = |p: &PathBuf| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        self.label.set_text(&match p.len() {
            0 => "No keyfiles".to_string(),
            1 => format!("Keyfile: {}", name(&p[0])),
            n => format!("{n} keyfiles: {}", p.iter().map(name).collect::<Vec<_>>().join(", ")),
        });
    }

    fn accept_drops(&self, w: &impl IsA<gtk::Widget>) {
        let drop = gtk::DropTarget::new(gdk::FileList::static_type(), gdk::DragAction::COPY);
        let k = self.clone();
        drop.connect_drop(move |_, value, _, _| match value.get::<gdk::FileList>() {
            Ok(list) => {
                for p in list.files().iter().filter_map(|f| f.path()) {
                    k.add(p);
                }
                true
            }
            Err(_) => false,
        });
        w.add_controller(drop);
    }
}

// ---------------------------------------------------------------- the app

struct Row {
    code: gtk::Label,
    secs: gtk::Label,
    shown: RefCell<String>,
    haystack: String,
}

struct Inner {
    path: PathBuf,
    window: gtk::ApplicationWindow,
    stack: gtk::Stack,
    chrome: Vec<gtk::Widget>,
    // The password box.
    heading: gtk::Label,
    subheading: gtk::Label,
    pw1: gtk::PasswordEntry,
    pw2: gtk::PasswordEntry,
    keyfiles: Keyfiles,
    unlock_btn: gtk::Button,
    spinner: gtk::Spinner,
    unlock_error: gtk::Label,
    reset_btn: gtk::Button,
    // The codes.
    list: gtk::ListBox,
    list_stack: gtk::Stack,
    search: gtk::SearchEntry,
    toast: gtk::Revealer,
    toast_label: gtk::Label,
    toast_gen: Cell<u32>,
    vault: RefCell<Option<Vault>>,
    rows: RefCell<Vec<Row>>,
    last_active: Cell<Instant>,
    sync: syncing::SyncUi,
}

#[derive(Clone)]
struct App(Rc<Inner>);

impl std::ops::Deref for App {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl App {
    fn build(gapp: &gtk::Application, path: PathBuf) -> App {
        let window = gtk::ApplicationWindow::builder().application(gapp).title("PawKey").default_width(460).default_height(620).build();
        window.set_icon_name(Some("pawkey"));

        // A toolbar inside the window, not a GTK title bar: the window
        // manager draws the frame and its buttons.
        let toolbar_start = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let toolbar_end = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let toolbar = gtk::CenterBox::builder().start_widget(&toolbar_start).end_widget(&toolbar_end).build();
        toolbar.add_css_class("toolbar");
        let add_btn = gtk::Button::from_icon_name("list-add-symbolic");
        add_btn.set_tooltip_text(Some(&format!("Add an account ({MOD}N)")));
        add_btn.set_action_name(Some("win.add"));
        let lock_btn = gtk::Button::from_icon_name("system-lock-screen-symbolic");
        lock_btn.set_tooltip_text(Some(&format!("Lock ({MOD}L)")));
        lock_btn.set_action_name(Some("win.lock"));
        let menu = gio::Menu::new();
        menu.append(Some("Dark theme"), Some("win.dark"));
        menu.append(Some("Sync…"), Some("win.sync"));
        menu.append(Some("Change password or keyfiles…"), Some("win.change-password"));
        menu.append(Some("About PawKey"), Some("win.about"));
        let menu_btn = gtk::MenuButton::builder().icon_name("open-menu-symbolic").menu_model(&menu).build();
        toolbar_start.append(&add_btn);
        // Filled in once `App` exists (it needs the sync state).
        let sync_slot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        toolbar_end.append(&sync_slot);
        toolbar_end.append(&lock_btn);
        toolbar_end.append(&menu_btn);

        // The password box.
        let unlock_page = gtk::Box::new(gtk::Orientation::Vertical, 12);
        unlock_page.set_valign(gtk::Align::Center);
        unlock_page.set_margin_start(36);
        unlock_page.set_margin_end(36);
        if let Some(t) = logo() {
            let img = gtk::Image::from_paintable(Some(&t));
            img.set_pixel_size(96);
            unlock_page.append(&img);
        }
        let heading = gtk::Label::new(None);
        heading.add_css_class("heading-big");
        let subheading = gtk::Label::builder().wrap(true).justify(gtk::Justification::Center).build();
        subheading.add_css_class("dim");
        let pw1 = gtk::PasswordEntry::builder().show_peek_icon(true).placeholder_text("Password").build();
        let pw2 = gtk::PasswordEntry::builder().show_peek_icon(true).placeholder_text("Password again").build();
        let keyfiles = Keyfiles::new();
        let unlock_btn = gtk::Button::new();
        unlock_btn.add_css_class("suggested-action");
        let spinner = gtk::Spinner::new();
        let unlock_error = error_label();
        unlock_error.set_justify(gtk::Justification::Center);
        unlock_error.set_xalign(0.5);
        let reset_btn = gtk::Button::with_label("Forgot it? Reset PawKey…");
        reset_btn.add_css_class("flat");
        for w in [
            heading.upcast_ref::<gtk::Widget>(),
            subheading.upcast_ref(),
            pw1.upcast_ref(),
            pw2.upcast_ref(),
            keyfiles.widget.upcast_ref(),
            unlock_btn.upcast_ref(),
            spinner.upcast_ref(),
            unlock_error.upcast_ref(),
            reset_btn.upcast_ref(),
        ] {
            unlock_page.append(w);
        }
        keyfiles.accept_drops(&unlock_page);

        // The codes.
        let main_page = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let search = gtk::SearchEntry::builder().placeholder_text("Search").margin_top(12).margin_start(12).margin_end(12).build();
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .valign(gtk::Align::Start)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .build();
        list.add_css_class("boxed-list");
        list.add_css_class("frame");
        let scroller = gtk::ScrolledWindow::builder().vexpand(true).hscrollbar_policy(gtk::PolicyType::Never).child(&list).build();
        let empty = gtk::Label::builder()
            .label("No accounts yet.\n\nClick + to add one from its setup QR code\n(a screenshot of it will do) or its secret key,\nor drop a picture of the QR code here.")
            .justify(gtk::Justification::Center)
            .vexpand(true)
            .build();
        empty.add_css_class("dim");
        let list_stack = gtk::Stack::new();
        list_stack.add_named(&scroller, Some("list"));
        list_stack.add_named(&empty, Some("empty"));
        main_page.append(&search);
        main_page.append(&list_stack);

        let toast_label = gtk::Label::new(None);
        let toast = gtk::Revealer::builder()
            .child(&toast_label)
            .halign(gtk::Align::Center)
            .valign(gtk::Align::End)
            .margin_bottom(18)
            .transition_type(gtk::RevealerTransitionType::SlideUp)
            .build();
        toast_label.add_css_class("app-notification");
        let overlay = gtk::Overlay::new();
        overlay.set_child(Some(&main_page));
        overlay.add_overlay(&toast);

        let stack = gtk::Stack::builder().transition_type(gtk::StackTransitionType::Crossfade).build();
        stack.add_named(&unlock_page, Some("unlock"));
        stack.add_named(&overlay, Some("main"));
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.append(&toolbar);
        let toolbar_sep = gtk::Separator::new(gtk::Orientation::Horizontal);
        root.append(&toolbar_sep);
        root.append(&stack);
        stack.set_vexpand(true);
        window.set_child(Some(&root));

        let app = App(Rc::new(Inner {
            path,
            window,
            stack,
            // The toolbar and its separator only show while unlocked.
            chrome: vec![toolbar.upcast(), toolbar_sep.upcast()],
            heading,
            subheading,
            pw1,
            pw2,
            keyfiles,
            unlock_btn,
            spinner,
            unlock_error,
            reset_btn,
            list,
            list_stack,
            search,
            toast,
            toast_label,
            toast_gen: Cell::new(0),
            vault: RefCell::new(None),
            rows: RefCell::new(Vec::new()),
            last_active: Cell::new(Instant::now()),
            sync: syncing::SyncUi::new(),
        }));
        sync_slot.append(&app.sync.button);
        app.connect(gapp, &main_page);
        app.show_locked();
        app
    }

    fn connect(&self, gapp: &gtk::Application, main_page: &gtk::Box) {
        let a = self.clone();
        self.unlock_btn.connect_clicked(move |_| a.unlock());
        let a = self.clone();
        self.pw1.connect_activate(move |_| {
            if a.pw2.is_visible() {
                a.pw2.grab_focus();
            } else {
                a.unlock()
            }
        });
        let a = self.clone();
        self.pw2.connect_activate(move |_| a.unlock());
        let a = self.clone();
        self.reset_btn.connect_clicked(move |_| a.reset_dialog());

        let a = self.clone();
        self.list.set_filter_func(move |row| {
            let q = a.search.text().to_lowercase();
            q.is_empty() || a.rows.try_borrow().ok().and_then(|r| r.get(row.index() as usize).map(|r| r.haystack.contains(&q))).unwrap_or(true)
        });
        let a = self.clone();
        self.search.connect_search_changed(move |_| a.list.invalidate_filter());
        let a = self.clone();
        self.list.connect_row_activated(move |_, row| a.copy(row.index() as usize));

        // Pictures of QR codes dropped on the list.
        let drop = gtk::DropTarget::new(gdk::FileList::static_type(), gdk::DragAction::COPY);
        let a = self.clone();
        drop.connect_drop(move |_, value, _, _| {
            let Some(file) = value.get::<gdk::FileList>().ok().and_then(|l| l.files().into_iter().next()) else { return false };
            let a = a.clone();
            glib::spawn_future_local(async move {
                match gdk::Texture::from_file(&file) {
                    Ok(t) => match setup_link(qr_from_texture(t).await) {
                        Ok(uri) => a.add_dialog(Some(uri)),
                        Err(e) => a.notify(&e),
                    },
                    Err(_) => a.notify("That file isn't a picture PawKey can read."),
                }
            });
            true
        });
        main_page.add_controller(drop);

        // Actions and shortcuts.
        let add_action = |name: &str, f: Box<dyn Fn(&App)>| {
            let action = gio::SimpleAction::new(name, None);
            let a = self.clone();
            action.connect_activate(move |_, _| f(&a));
            self.window.add_action(&action);
        };
        add_action(
            "add",
            Box::new(|a| {
                if a.vault.borrow().is_some() {
                    a.add_dialog(None)
                }
            }),
        );
        add_action("lock", Box::new(|a| a.lock()));
        add_action(
            "change-password",
            Box::new(|a| {
                if a.vault.borrow().is_some() {
                    a.password_dialog()
                }
            }),
        );
        add_action("about", Box::new(|a| a.about()));
        add_action(
            "sync",
            Box::new(|a| {
                if a.vault.borrow().is_some() {
                    a.sync_dialog()
                }
            }),
        );
        let a = self.clone();
        self.sync.button.connect_clicked(move |_| a.sync_soon(true));
        let dark = gio::SimpleAction::new_stateful("dark", None, &(!light_theme_marker().exists()).to_variant());
        dark.connect_change_state(|action, value| {
            let Some(on) = value.and_then(|v| v.get::<bool>()) else { return };
            action.set_state(&on.to_variant());
            set_dark(on);
            let marker = light_theme_marker();
            if on {
                let _ = std::fs::remove_file(&marker);
            } else if let Some(dir) = marker.parent() {
                let _ = std::fs::create_dir_all(dir).and_then(|_| std::fs::write(&marker, b""));
            }
        });
        self.window.add_action(&dark);
        // <Primary> is Ctrl, or ⌘ on a Mac.
        gapp.set_accels_for_action("win.add", &["<Primary>n"]);
        gapp.set_accels_for_action("win.lock", &["<Primary>l"]);

        // Anything the user does counts as activity, for the auto-lock.
        let keys = gtk::EventControllerKey::new();
        keys.set_propagation_phase(gtk::PropagationPhase::Capture);
        let a = self.clone();
        keys.connect_key_pressed(move |_, _, _, _| {
            a.last_active.set(Instant::now());
            glib::Propagation::Proceed
        });
        self.window.add_controller(keys);
        let motion = gtk::EventControllerMotion::new();
        let a = self.clone();
        motion.connect_motion(move |_, _, _| a.last_active.set(Instant::now()));
        self.window.add_controller(motion);

        let a = self.clone();
        glib::timeout_add_local(Duration::from_millis(500), move || {
            a.tick();
            glib::ControlFlow::Continue
        });
    }

    // ------------------------------------------------------------ locking

    fn show_locked(&self) {
        let creating = !self.path.exists();
        self.heading.set_text(if creating { "Set up PawKey" } else { "PawKey is locked" });
        self.subheading.set_text(if creating {
            "Pick a password for your codes. Keyfiles are optional: files whose contents are needed as well as the password (drop them on this window)."
        } else {
            "Type your password, and add your keyfiles if you use them."
        });
        self.pw2.set_visible(creating);
        self.unlock_btn.set_label(if creating { "Create vault" } else { "Unlock" });
        self.reset_btn.set_visible(!creating);
        for b in &self.chrome {
            b.set_visible(false);
        }
        self.stack.set_visible_child_name("unlock");
        self.pw1.grab_focus();
    }

    fn busy(&self, on: bool) {
        self.spinner.set_spinning(on);
        for w in [self.pw1.upcast_ref::<gtk::Widget>(), self.pw2.upcast_ref(), self.unlock_btn.upcast_ref(), self.keyfiles.widget.upcast_ref()] {
            w.set_sensitive(!on);
        }
    }

    fn unlock(&self) {
        let creating = !self.path.exists();
        let pw = Zeroizing::new(self.pw1.text().to_string());
        if creating {
            if pw.is_empty() && self.keyfiles.get().is_empty() {
                return show_error(&self.unlock_error, "Pick a password (a long one).");
            }
            if *pw != self.pw2.text().as_str() {
                return show_error(&self.unlock_error, "The two passwords don't match.");
            }
        }
        show_error(&self.unlock_error, "");
        self.busy(true);
        let (path, keyfiles, a) = (self.path.clone(), self.keyfiles.get(), self.clone());
        glib::spawn_future_local(async move {
            let res = gio::spawn_blocking(move || -> Result<Vault, String> {
                let secret = keyfile::secret(&keyfiles).map_err(|e| e.to_string())?;
                let v =
                    if creating { Vault::create(&path, pw.as_bytes(), secret.as_ref()) } else { Vault::open(&path, pw.as_bytes(), secret.as_ref()) };
                v.map_err(|e| e.to_string())
            })
            .await
            .unwrap_or_else(|_| Err("Something went wrong opening the vault.".into()));
            a.busy(false);
            match res {
                Ok(v) => a.unlocked(v),
                Err(e) => {
                    show_error(&a.unlock_error, &e);
                    a.pw1.grab_focus();
                }
            }
        });
    }

    fn unlocked(&self, v: Vault) {
        *self.vault.borrow_mut() = Some(v);
        self.pw1.set_text("");
        self.pw2.set_text("");
        self.search.set_text("");
        self.last_active.set(Instant::now());
        for b in &self.chrome {
            b.set_visible(true);
        }
        self.rebuild();
        self.stack.set_visible_child_name("main");
        self.refresh_sync_button();
        self.sync_soon(true);
    }

    fn lock(&self) {
        // Dropping the vault wipes its key and every secret.
        *self.vault.borrow_mut() = None;
        self.sync.forget();
        self.rows.borrow_mut().clear();
        self.list.remove_all();
        // Which keyfiles were used is a secret too: chosen again on unlock.
        self.keyfiles.set(Vec::new());
        self.show_locked();
    }

    // ------------------------------------------------------------ the list

    fn rebuild(&self) {
        self.list.remove_all();
        let vault = self.vault.borrow();
        let Some(v) = vault.as_ref() else { return };
        let mut rows = Vec::new();
        let mut widgets = Vec::new();
        for acc in v.accounts.iter() {
            let hbox = gtk::Box::builder().spacing(12).margin_top(10).margin_bottom(10).margin_start(12).margin_end(6).build();
            let text = gtk::Box::new(gtk::Orientation::Vertical, 2);
            text.set_hexpand(true);
            let title = gtk::Label::builder().label(acc.title()).xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End).build();
            title.add_css_class("heading");
            text.append(&title);
            if !acc.issuer.is_empty() && !acc.name.is_empty() {
                let name = gtk::Label::builder().label(&acc.name).xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End).build();
                name.add_css_class("dim");
                text.append(&name);
            }
            let code = gtk::Label::new(None);
            code.add_css_class("code");
            let secs = gtk::Label::new(None);
            secs.add_css_class("secs");
            secs.add_css_class("dim");
            let del = gtk::Button::from_icon_name("user-trash-symbolic");
            del.add_css_class("flat");
            del.set_valign(gtk::Align::Center);
            del.set_tooltip_text(Some("Delete this account"));
            let (a, uid) = (self.clone(), acc.uid.clone());
            del.connect_clicked(move |_| a.delete(uid.clone()));
            hbox.append(&text);
            hbox.append(&code);
            hbox.append(&secs);
            hbox.append(&del);
            let row = gtk::ListBoxRow::builder().child(&hbox).activatable(true).tooltip_text("Click to copy").build();
            widgets.push(row);
            rows.push(Row { code, secs, shown: RefCell::default(), haystack: format!("{} {}", acc.issuer, acc.name).to_lowercase() });
        }
        drop(vault);
        let any = !rows.is_empty();
        *self.rows.borrow_mut() = rows;
        for w in widgets {
            self.list.append(&w);
        }
        self.list_stack.set_visible_child_name(if any { "list" } else { "empty" });
        self.tick();
    }

    fn tick(&self) {
        if self.vault.borrow().is_some() && self.last_active.get().elapsed() >= AUTO_LOCK {
            self.lock();
            return;
        }
        self.sync_tick();
        let vault = self.vault.borrow();
        let Some(v) = vault.as_ref() else { return };
        let t = now();
        for (acc, row) in v.accounts.iter().zip(self.rows.borrow().iter()) {
            let code = Zeroizing::new(pretty(&acc.code_at(t)));
            if *row.shown.borrow() != *code {
                row.code.set_text(&code);
                *row.shown.borrow_mut() = code.to_string();
            }
            let left = acc.remaining(t);
            row.secs.set_text(&format!("{left}s"));
            if left <= 5 {
                row.code.add_css_class("expiring");
            } else {
                row.code.remove_css_class("expiring");
            }
        }
    }

    fn copy(&self, i: usize) {
        let code = match self.vault.borrow().as_ref().and_then(|v| v.accounts.get(i).map(|a| a.code_at(now()))) {
            Some(c) => c,
            None => return,
        };
        self.copy_text(code, "Copied.");
    }

    /// Copies a code or a sync login, and clears it again later.
    fn copy_text(&self, text: String, msg: &str) {
        let cb = self.window.clipboard();
        cb.set_text(&text);
        self.notify(&format!("{msg} The clipboard clears in {CLIPBOARD_CLEAR_SECS} seconds."));
        let text = Zeroizing::new(text);
        glib::spawn_future_local(async move {
            glib::timeout_future_seconds(CLIPBOARD_CLEAR_SECS).await;
            // Only if it's still ours: never wipe something copied since.
            if let Ok(Some(t)) = cb.read_text_future().await {
                if t.as_str() == text.as_str() {
                    cb.set_text("");
                }
            }
        });
    }

    fn notify(&self, msg: &str) {
        self.toast_label.set_text(msg);
        self.toast.set_reveal_child(true);
        let gen = self.toast_gen.get().wrapping_add(1);
        self.toast_gen.set(gen);
        let a = self.clone();
        glib::timeout_add_seconds_local_once(3, move || {
            if a.toast_gen.get() == gen {
                a.toast.set_reveal_child(false);
            }
        });
    }

    /// Saves the vault; on failure, undoes `undo` and says why.
    fn save_or(&self, undo: impl FnOnce(&mut Vault)) -> bool {
        let mut vault = self.vault.borrow_mut();
        let Some(v) = vault.as_mut() else { return false };
        match v.save() {
            Ok(()) => true,
            Err(e) => {
                undo(v);
                drop(vault);
                self.notify(&format!("Couldn't save: {e}"));
                false
            }
        }
    }

    /// By uid, not position: a sync can reorder the list while the question is up.
    fn delete(&self, uid: String) {
        let Some(title) = self.vault.borrow().as_ref().and_then(|v| v.accounts.iter().find(|a| a.uid == uid)).map(|a| {
            if a.issuer.is_empty() || a.name.is_empty() {
                a.title().to_string()
            } else {
                format!("{} ({})", a.issuer, a.name)
            }
        }) else {
            return;
        };
        let ask = gtk::AlertDialog::builder()
            .modal(true)
            .message(format!("Delete {title}?"))
            .detail("Its codes will be gone from PawKey. Turn two-factor off for it first (or set it up again), or you may be locked out of that account.")
            .buttons(["Cancel", "Delete"])
            .cancel_button(0)
            .default_button(0)
            .build();
        let a = self.clone();
        glib::spawn_future_local(async move {
            if ask.choose_future(Some(&a.window)).await != Ok(1) {
                return;
            }
            let (i, removed) = match a.vault.borrow_mut().as_mut().and_then(|v| v.accounts.iter().position(|x| x.uid == uid).map(|i| (i, v))) {
                Some((i, v)) => (i, v.accounts.remove(i)),
                None => return,
            };
            if a.save_or(|v| v.accounts.insert(i, removed.clone())) {
                a.notify(&format!("Deleted {title}."));
                a.sync_soon(false);
            }
            a.rebuild();
        });
    }

    // ------------------------------------------------------------ dialogs

    fn add_dialog(&self, prefill: Option<String>) {
        let (win, content, ok) = dialog(&self.window, "Add account", "Add");
        let intro = gtk::Label::builder()
            .label("Paste the setup link or secret key the site shows, or read its QR code from a picture or screenshot.")
            .wrap(true)
            .xalign(0.0)
            .build();
        intro.add_css_class("dim");
        let link = gtk::Entry::builder().placeholder_text("otpauth:// link, or the secret key").hexpand(true).activates_default(true).build();
        let qr_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let open_qr = gtk::Button::with_label("QR from a picture…");
        let paste_qr = gtk::Button::with_label("Paste a QR picture");
        open_qr.set_hexpand(true);
        paste_qr.set_hexpand(true);
        qr_row.append(&open_qr);
        qr_row.append(&paste_qr);
        let issuer = gtk::Entry::builder().placeholder_text("Service (GitHub, say)").activates_default(true).build();
        let name = gtk::Entry::builder().placeholder_text("Account (you@example.com, say)").activates_default(true).build();

        let grid = gtk::Grid::builder().row_spacing(6).column_spacing(12).margin_top(6).build();
        let digits = gtk::DropDown::from_strings(&["6", "7", "8"]);
        let period = gtk::SpinButton::with_range(10.0, 300.0, 5.0);
        period.set_value(30.0);
        let algo = gtk::DropDown::from_strings(&["SHA-1", "SHA-256", "SHA-512"]);
        for (r, (label, w)) in
            [("Digits", digits.upcast_ref::<gtk::Widget>()), ("Seconds per code", period.upcast_ref()), ("Algorithm", algo.upcast_ref())]
                .into_iter()
                .enumerate()
        {
            grid.attach(&gtk::Label::builder().label(label).xalign(0.0).hexpand(true).build(), 0, r as i32, 1, 1);
            grid.attach(w, 1, r as i32, 1, 1);
        }
        let more = gtk::Expander::builder().label("More options (most sites use the defaults)").child(&grid).build();
        let err = error_label();
        for w in [
            intro.upcast_ref::<gtk::Widget>(),
            link.upcast_ref(),
            qr_row.upcast_ref(),
            issuer.upcast_ref(),
            name.upcast_ref(),
            more.upcast_ref(),
            err.upcast_ref(),
        ] {
            content.append(w);
        }

        // A pasted link fills in the rest.
        let (i2, n2, d2, p2, a2, e2) = (issuer.clone(), name.clone(), digits.clone(), period.clone(), algo.clone(), err.clone());
        link.connect_changed(move |l| {
            let text = l.text();
            if !text.trim_start().starts_with("otpauth") {
                return show_error(&e2, "");
            }
            match totp::parse_otpauth(&text) {
                Ok(acc) => {
                    i2.set_text(&acc.issuer);
                    n2.set_text(&acc.name);
                    d2.set_selected(acc.digits.saturating_sub(6));
                    p2.set_value(acc.period as f64);
                    a2.set_selected(match acc.algo {
                        Algo::Sha1 => 0,
                        Algo::Sha256 => 1,
                        Algo::Sha512 => 2,
                    });
                    show_error(&e2, "");
                }
                Err(e) => show_error(&e2, &e),
            }
        });

        let from_texture = {
            let (link, err) = (link.clone(), err.clone());
            move |t: gdk::Texture| {
                let (link, err) = (link.clone(), err.clone());
                glib::spawn_future_local(async move {
                    match setup_link(qr_from_texture(t).await) {
                        Ok(uri) => link.set_text(&uri),
                        Err(e) => show_error(&err, &e),
                    }
                });
            }
        };
        let (w2, ft, e2) = (win.clone(), from_texture.clone(), err.clone());
        open_qr.connect_clicked(move |_| {
            let filter = gtk::FileFilter::new();
            filter.set_name(Some("Pictures"));
            filter.add_mime_type("image/*");
            let fd = gtk::FileDialog::builder().title("A picture of the QR code").modal(true).default_filter(&filter).build();
            let (w2, ft, e2) = (w2.clone(), ft.clone(), e2.clone());
            glib::spawn_future_local(async move {
                if let Ok(file) = fd.open_future(Some(&w2)).await {
                    match gdk::Texture::from_file(&file) {
                        Ok(t) => ft(t),
                        Err(_) => show_error(&e2, "That file isn't a picture PawKey can read."),
                    }
                }
            });
        });
        let (w2, e2) = (win.clone(), err.clone());
        paste_qr.connect_clicked(move |_| {
            let (cb, ft, e2) = (w2.clipboard(), from_texture.clone(), e2.clone());
            glib::spawn_future_local(async move {
                match cb.read_texture_future().await {
                    Ok(Some(t)) => ft(t),
                    _ => {
                        show_error(&e2, "There's no picture on the clipboard. Take a screenshot of the QR code first (copy it, don't only save it).")
                    }
                }
            });
        });

        if let Some(uri) = prefill {
            link.set_text(&uri);
        }
        let a = self.clone();
        let w2 = win.clone();
        let link2 = link.clone();
        ok.connect_clicked(move |_| {
            let link = &link2;
            let text = link.text();
            let parsed = if text.trim_start().starts_with("otpauth") {
                totp::parse_otpauth(&text)
            } else {
                Account::new("", "", &text).map(|mut acc| {
                    acc.digits = 6 + digits.selected();
                    acc.period = period.value() as u64;
                    acc.algo = [Algo::Sha1, Algo::Sha256, Algo::Sha512][algo.selected().min(2) as usize];
                    acc
                })
            };
            let mut acc = match parsed {
                Ok(acc) => acc,
                Err(e) if text.trim().is_empty() => return show_error(&err, &format!("{e}: paste the setup link or key first.")),
                Err(e) => return show_error(&err, &e),
            };
            acc.issuer = issuer.text().trim().to_string();
            acc.name = name.text().trim().to_string();
            if acc.issuer.is_empty() && acc.name.is_empty() {
                return show_error(&err, "Give it a name, so you can tell it apart.");
            }
            let title = acc.title().to_string();
            match a.vault.borrow_mut().as_mut() {
                Some(v) => v.accounts.push(acc),
                None => return w2.close(),
            }
            if a.save_or(|v| drop(v.accounts.pop())) {
                a.notify(&format!("Added {title}."));
                a.sync_soon(false);
                w2.close();
            }
            a.rebuild();
        });

        win.present();
        link.grab_focus();
    }

    fn password_dialog(&self) {
        let (win, content, ok) = dialog(&self.window, "Change password", "Change");
        let intro = gtk::Label::builder()
            .label("PawKey will be sealed with the new password and these keyfiles. The old ones stop working.")
            .wrap(true)
            .xalign(0.0)
            .build();
        intro.add_css_class("dim");
        let pw1 = gtk::PasswordEntry::builder().show_peek_icon(true).placeholder_text("New password").build();
        let pw2 = gtk::PasswordEntry::builder().show_peek_icon(true).placeholder_text("New password again").build();
        let kf = Keyfiles::new();
        kf.set(self.keyfiles.get());
        kf.accept_drops(&content);
        let spinner = gtk::Spinner::new();
        let err = error_label();
        for w in
            [intro.upcast_ref::<gtk::Widget>(), pw1.upcast_ref(), pw2.upcast_ref(), kf.widget.upcast_ref(), spinner.upcast_ref(), err.upcast_ref()]
        {
            content.append(w);
        }
        let a = self.clone();
        let w2 = win.clone();
        ok.connect_clicked(move |ok| {
            let pw = Zeroizing::new(pw1.text().to_string());
            if pw.is_empty() && kf.get().is_empty() {
                return show_error(&err, "Pick a password.");
            }
            if *pw != pw2.text().as_str() {
                return show_error(&err, "The two passwords don't match.");
            }
            let Some(mut v) = a.vault.borrow_mut().take() else { return };
            ok.set_sensitive(false);
            spinner.set_spinning(true);
            let (a, w2, err, ok, spinner, paths) = (a.clone(), w2.clone(), err.clone(), ok.clone(), spinner.clone(), kf.get());
            glib::spawn_future_local(async move {
                let (v, res) = gio::spawn_blocking(move || {
                    let res = keyfile::secret(&paths)
                        .map_err(|e| e.to_string())
                        .and_then(|s| v.change_password(pw.as_bytes(), s.as_ref()).map_err(|e| e.to_string()));
                    (v, res.map(|_| paths))
                })
                .await
                .expect("the password change doesn't panic");
                *a.vault.borrow_mut() = Some(v);
                ok.set_sensitive(true);
                spinner.set_spinning(false);
                match res {
                    Ok(paths) => {
                        a.keyfiles.set(paths);
                        a.notify("Password changed.");
                        w2.close();
                    }
                    Err(e) => show_error(&err, &e),
                }
            });
        });
        win.present();
    }

    fn reset_dialog(&self) {
        let (win, content, ok) = dialog(&self.window, "Reset PawKey", "Wipe everything");
        ok.remove_css_class("suggested-action");
        ok.add_css_class("destructive-action");
        ok.set_sensitive(false);
        let text = gtk::Label::builder()
            .label("This wipes the vault and every account in it, for good: there's no way back without the password. You'll need to set up two-factor again for each site (with its recovery codes).\n\nType RESET to go ahead.")
            .wrap(true)
            .xalign(0.0)
            .build();
        let entry = gtk::Entry::new();
        let err = error_label();
        content.append(&text);
        content.append(&entry);
        content.append(&err);
        let o2 = ok.clone();
        entry.connect_changed(move |e| o2.set_sensitive(e.text() == "RESET"));
        let a = self.clone();
        let w2 = win.clone();
        ok.connect_clicked(move |_| match vault::destroy(&a.path) {
            Ok(()) => {
                a.keyfiles.set(Vec::new());
                show_error(&a.unlock_error, "");
                a.show_locked();
                w2.close();
            }
            Err(e) => show_error(&err, &format!("Couldn't wipe it: {e}")),
        });
        win.present();
    }

    fn about(&self) {
        let about = gtk::AboutDialog::builder()
            .transient_for(&self.window)
            .modal(true)
            .program_name("PawKey")
            .version(env!("CARGO_PKG_VERSION"))
            .comments("Two-factor codes for Linux, kept in an encrypted vault.")
            .website("https://github.com/anti-ghostsec/PawKey")
            .license_type(gtk::License::MitX11)
            .build();
        if let Some(t) = logo() {
            about.set_logo(Some(&t));
        }
        about.present();
    }
}

fn main() -> glib::ExitCode {
    let mut args = std::env::args();
    let argv0 = args.next().unwrap_or_else(|| "pawkey".into());
    let mut path = vault::default_path();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--vault" => match args.next() {
                Some(p) => path = PathBuf::from(p),
                None => {
                    eprintln!("pawkey: --vault needs a path");
                    return glib::ExitCode::FAILURE;
                }
            },
            "--version" => {
                println!("pawkey {}", env!("CARGO_PKG_VERSION"));
                return glib::ExitCode::SUCCESS;
            }
            "-h" | "--help" => {
                println!("pawkey [--vault PATH]\n\nTwo-factor codes, kept in an encrypted vault (default {}).", vault::default_path().display());
                return glib::ExitCode::SUCCESS;
            }
            other => {
                eprintln!("pawkey: unknown option {other} (see --help)");
                return glib::ExitCode::FAILURE;
            }
        }
    }

    let gapp = gtk::Application::builder().application_id(APP_ID).build();
    gapp.connect_startup(|_| {
        set_dark(!light_theme_marker().exists());
        load_css();
        bundled_icons();
    });
    gapp.connect_activate(move |gapp| {
        if let Some(w) = gapp.active_window() {
            return w.present();
        }
        App::build(gapp, path.clone()).window.present();
    });
    gapp.run_with_args(&[argv0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(w: &impl IsA<gtk::Widget>) -> bool {
        w.property::<bool>("visible")
    }

    /// Runs the main loop until `done` or ten seconds have passed.
    fn spin_until(done: impl Fn() -> bool) -> bool {
        let ctx = glib::MainContext::default();
        let start = Instant::now();
        while !done() && start.elapsed() < Duration::from_secs(10) {
            ctx.iteration(false);
        }
        done()
    }

    /// The window tests, one after the other: GTK may only be used from one
    /// thread, and initialised once. They need a display, and skip without one.
    #[test]
    fn window() {
        if gtk::init().is_err() {
            eprintln!("no display: skipped");
            return;
        }
        create_lock_unlock();
        syncing::tests::two_windows_sync();
    }

    /// The real window, driven from code.
    fn create_lock_unlock() {
        let dir = std::env::temp_dir().join(format!("pawkey-gui-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("pawkey.vault");
        let gapp = gtk::Application::builder().application_id("io.github.anti_ghostsec.PawKeyTest").flags(gio::ApplicationFlags::NON_UNIQUE).build();
        gapp.register(None::<&gio::Cancellable>).unwrap();
        let app = App::build(&gapp, path.clone());

        // First run: two passwords, and they must match.
        assert!(shown(&app.pw2));
        app.pw1.set_text("pw-test-123");
        app.pw2.set_text("something else");
        app.unlock();
        assert!(shown(&app.unlock_error) && !path.exists());
        app.pw2.set_text("pw-test-123");
        app.unlock();
        assert!(spin_until(|| app.vault.borrow().is_some()), "vault created");
        assert_eq!(app.stack.visible_child_name().as_deref(), Some("main"));
        assert_eq!(app.list_stack.visible_child_name().as_deref(), Some("empty"));
        assert!(app.pw1.text().is_empty(), "password box cleared");

        // An account shows the right code.
        let acc = totp::parse_otpauth("otpauth://totp/Example:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example").unwrap();
        let expect = pretty(&acc.code_at(now()));
        app.vault.borrow_mut().as_mut().unwrap().accounts.push(acc);
        assert!(app.save_or(|_| ()));
        app.rebuild();
        assert_eq!(app.list_stack.visible_child_name().as_deref(), Some("list"));
        let on_screen = app.rows.borrow()[0].code.text().to_string();
        assert!(on_screen == expect || now() % 30 == 0, "shows {on_screen}, expected {expect}");

        // Lock: secrets gone from the window; a wrong password is refused.
        app.lock();
        assert!(app.vault.borrow().is_none() && app.rows.borrow().is_empty());
        assert_eq!(app.stack.visible_child_name().as_deref(), Some("unlock"));
        assert!(!shown(&app.pw2), "one password box when unlocking");
        app.pw1.set_text("wrong");
        app.unlock();
        assert!(spin_until(|| shown(&app.unlock_error) && app.unlock_btn.is_sensitive()));
        assert!(app.vault.borrow().is_none());

        // The right one brings the account back.
        app.pw1.set_text("pw-test-123");
        app.unlock();
        assert!(spin_until(|| app.vault.borrow().is_some()));
        assert_eq!(app.vault.borrow().as_ref().unwrap().accounts[0].issuer, "Example");
        assert_eq!(app.rows.borrow().len(), 1);

        // Search filters by issuer or account name.
        app.search.set_text("nothing like it");
        app.list.invalidate_filter();
        assert!(!app.list.row_at_index(0).unwrap().is_child_visible());
        app.search.set_text("exam");
        app.list.invalidate_filter();
        assert!(app.list.row_at_index(0).unwrap().is_child_visible());

        // PAWKEY_TEST_SHOT=DIR saves pictures of the window (dark, with codes) there.
        if let Some(shots) = std::env::var_os("PAWKEY_TEST_SHOT").map(PathBuf::from) {
            set_dark(true);
            load_css();
            app.search.set_text("");
            let more = totp::parse_otpauth("otpauth://totp/GitHub:octo-cat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub").unwrap();
            app.vault.borrow_mut().as_mut().unwrap().accounts.push(more);
            app.rebuild();
            app.window.present();
            let save_window = |w: &gtk::Window, name: &str| {
                let t = Instant::now();
                spin_until(|| t.elapsed() > Duration::from_millis(800));
                let paintable = gtk::WidgetPaintable::new(Some(w));
                let snap = gtk::Snapshot::new();
                paintable.snapshot(&snap, w.width() as f64, w.height() as f64);
                if let (Some(node), Some(native)) = (snap.to_node(), w.native()) {
                    native.renderer().unwrap().render_texture(node, None).save_to_png(shots.join(name)).unwrap();
                }
            };
            let save = |name: &str| save_window(app.window.upcast_ref(), name);
            save("list.png");
            let top = |title: &str| {
                gtk::Window::list_toplevels()
                    .into_iter()
                    .filter_map(|w| w.downcast::<gtk::Window>().ok())
                    .find(|w| w.title().as_deref() == Some(title))
            };
            app.sync_dialog();
            let d = top("Sync").unwrap();
            save_window(&d, "sync-off.png");
            d.close();
            app.vault.borrow_mut().as_mut().unwrap().sync.account = Some(pawkey_core::sync::SyncAccount {
                service: "https://api.xbrowsersync.org".into(),
                id: "1f2e3d4c5b6a79881f2e3d4c5b6a7988".into(),
                password: "example-password".into(),
            });
            app.refresh_sync_button();
            app.sync_dialog();
            let d = top("Sync").unwrap();
            save_window(&d, "sync-on.png");
            d.close();
            save("list-sync.png");
            app.vault.borrow_mut().as_mut().unwrap().sync = Default::default();
            app.lock();
            save("locked.png");
        }
        app.window.destroy();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

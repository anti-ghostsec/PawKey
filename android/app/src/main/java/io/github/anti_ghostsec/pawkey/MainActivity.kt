package io.github.anti_ghostsec.pawkey

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowInsets
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors
import uniffi.pawkey_ffi.AccountView
import uniffi.pawkey_ffi.PawException
import uniffi.pawkey_ffi.Session
import uniffi.pawkey_ffi.SyncLogin
import uniffi.pawkey_ffi.createVault
import uniffi.pawkey_ffi.defaultSyncService
import uniffi.pawkey_ffi.destroyVault
import uniffi.pawkey_ffi.openVault
import uniffi.pawkey_ffi.parseLink
import uniffi.pawkey_ffi.readQr
import uniffi.pawkey_ffi.vaultExists

/** Dark is the default, as on the desktop. */
class Palette(dark: Boolean) {
    val bg = if (dark) 0xFF242424.toInt() else 0xFFFAFAFA.toInt()
    val card = if (dark) 0xFF303030.toInt() else 0xFFFFFFFF.toInt()
    val text = if (dark) 0xFFFFFFFF.toInt() else 0xFF1E1E1E.toInt()
    val dim = if (dark) 0xFFAAAAAA.toInt() else 0xFF666666.toInt()
    val accent = if (dark) 0xFF3584E4.toInt() else 0xFF1C71D8.toInt()
    val red = if (dark) 0xFFFF7B63.toInt() else 0xFFC01C28.toInt()
}

class MainActivity : Activity() {
    companion object {
        const val AUTO_LOCK_MS = 5 * 60 * 1000L
        const val SYNC_EVERY_MS = 60_000L
        const val REQ_CAMERA = 1
        const val REQ_PICTURE = 2

        // Kept across the activity being remade (the theme switch); wiped on lock.
        private var session: Session? = null
    }

    private val work = Executors.newSingleThreadExecutor()
    private val net = Executors.newSingleThreadExecutor()
    private val ui = Handler(Looper.getMainLooper())
    private val http = AndroidHttp()
    private lateinit var prefs: SharedPreferences
    private lateinit var p: Palette
    private val vaultPath get() = File(filesDir, "pawkey.vault").path

    private var lastActive = SystemClock.elapsedRealtime()
    private var stoppedAt = 0L
    private var pendingLink: String? = null
    private var onPicture: ((String) -> Unit)? = null
    private var onCamera: (() -> Unit)? = null

    // The list.
    private var accounts = listOf<AccountView>()
    private val rows = mutableListOf<Triple<Int, TextView, TextView>>()
    private var listBox: LinearLayout? = null
    private var emptyText: TextView? = null
    private var syncBtn: TextView? = null
    private var search = ""

    // Sync.
    private var syncing = false
    private var syncAgain: Boolean? = null
    private var lastSync = 0L
    private var syncStatus = ""
    private var statusLabel: TextView? = null

    private val dp get() = resources.displayMetrics.density
    private fun px(v: Int) = (v * dp).toInt()
    private fun now() = (System.currentTimeMillis() / 1000).toULong()

    override fun onCreate(state: Bundle?) {
        prefs = getSharedPreferences("pawkey", Context.MODE_PRIVATE)
        val dark = prefs.getBoolean("dark", true)
        setTheme(if (dark) android.R.style.Theme_Material_NoActionBar else android.R.style.Theme_Material_Light_NoActionBar)
        super.onCreate(state)
        p = Palette(dark)
        guard(window)
        @Suppress("DEPRECATION")
        window.statusBarColor = p.bg
        @Suppress("DEPRECATION")
        window.navigationBarColor = p.bg
        takeLink(intent)
        if (session != null) showMain() else showLock()
        ui.post(ticker)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeLink(intent)
        if (session != null) pendingLink?.let { pendingLink = null; addDialog(it) }
    }

    private fun takeLink(intent: Intent?) {
        val uri = intent?.data?.toString() ?: return
        if (uri.startsWith("otpauth://")) {
            pendingLink = uri
            if (session == null) toast("Unlock PawKey to add the account.")
        }
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        lastActive = SystemClock.elapsedRealtime()
        return super.dispatchTouchEvent(ev)
    }

    override fun onStop() {
        super.onStop()
        stoppedAt = SystemClock.elapsedRealtime()
    }

    override fun onStart() {
        super.onStart()
        if (session != null && stoppedAt > 0 && SystemClock.elapsedRealtime() - stoppedAt > AUTO_LOCK_MS) lock()
        stoppedAt = 0
    }

    override fun onDestroy() {
        ui.removeCallbacksAndMessages(null)
        if (isFinishing) wipe()
        work.shutdown()
        net.shutdown()
        super.onDestroy()
    }

    private val ticker = object : Runnable {
        override fun run() {
            if (session != null) {
                val t = SystemClock.elapsedRealtime()
                if (t - lastActive > AUTO_LOCK_MS) lock()
                else {
                    updateCodes()
                    if (!syncing && lastSync > 0 && t - lastSync > SYNC_EVERY_MS) syncSoon(false)
                }
            }
            ui.postDelayed(this, 500)
        }
    }

    // ------------------------------------------------------------ widgets

    private fun text(s: String, size: Float = 15f, color: Int = p.text, bold: Boolean = false) = TextView(this).apply {
        text = s
        textSize = size
        setTextColor(color)
        if (bold) setTypeface(typeface, Typeface.BOLD)
    }

    private fun edit(hint: String, password: Boolean = false) = EditText(this).apply {
        this.hint = hint
        setSingleLine(true)
        setTextColor(p.text)
        setHintTextColor(p.dim)
        inputType = if (password) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        // A password field's hint would otherwise be in a monospace font.
        typeface = Typeface.DEFAULT
    }

    private fun button(s: String, primary: Boolean = false, danger: Boolean = false) = Button(this).apply {
        text = s
        isAllCaps = false
        if (primary || danger) {
            backgroundTintList = ColorStateList.valueOf(if (danger) p.red else p.accent)
            setTextColor(Color.WHITE)
        }
    }

    private fun vbox(pad: Int = 0) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(px(pad), px(pad), px(pad), px(pad))
    }

    private fun LinearLayout.add(v: View, top: Int = 8): View {
        addView(v, LinearLayout.LayoutParams(-1, -2).apply { topMargin = px(top) })
        return v
    }

    /** Android 15 draws apps edge to edge: keep clear of the status and navigation bars (and the keyboard). */
    private fun setScreen(v: View) {
        v.setOnApplyWindowInsetsListener { view, insets ->
            val (top, bottom) = if (Build.VERSION.SDK_INT >= 30) {
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                bars.top to bars.bottom
            } else {
                @Suppress("DEPRECATION")
                insets.systemWindowInsetTop to insets.systemWindowInsetBottom
            }
            view.setPadding(0, top, 0, bottom)
            insets
        }
        setContentView(v)
    }

    /**
     * No screenshots or screen recording: each pop-up is a window of its own
     * and needs it too. Not in debug builds, so the emulator can be checked.
     */
    private fun guard(w: Window?) {
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) w?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    private fun AlertDialog.Builder.open(): AlertDialog = create().also { guard(it.window); it.show() }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()

    private fun errorText() = text("", 14f, p.red).apply { visibility = View.GONE }

    private fun TextView.show(msg: String) {
        text = msg
        visibility = if (msg.isEmpty()) View.GONE else View.VISIBLE
    }

    private fun message(e: Throwable) = when (e) {
        is PawException.WrongPassword -> "Wrong password."
        is PawException.Failed -> e.reason
        else -> e.message ?: e.javaClass.simpleName
    }

    /** Runs [job] on the vault's thread, then [done] here with its result. */
    private fun <T> bg(job: () -> T, done: (Result<T>) -> Unit) = work.execute {
        val r = runCatching(job)
        ui.post { if (!isDestroyed) done(r) }
    }

    // ------------------------------------------------------------ locked

    private fun showLock() {
        val creating = !vaultExists(vaultPath)
        val root = vbox(32).apply { gravity = Gravity.CENTER_HORIZONTAL }
        root.add(ImageView(this).apply { setImageResource(R.drawable.icon) }.also {
            it.layoutParams = LinearLayout.LayoutParams(px(96), px(96))
        }, 48)
        (root.getChildAt(0).layoutParams as LinearLayout.LayoutParams).gravity = Gravity.CENTER_HORIZONTAL
        root.add(text(if (creating) "Set up PawKey" else "PawKey is locked", 24f, bold = true).apply { gravity = Gravity.CENTER }, 16)
        root.add(text(
            if (creating) "Pick a password for your codes. It can't be recovered, so make it one you'll remember."
            else "Type your password.", 15f, p.dim,
        ).apply { gravity = Gravity.CENTER })
        val pw1 = edit("Password", password = true)
        val pw2 = edit("Password again", password = true)
        root.add(pw1, 16)
        if (creating) root.add(pw2)
        val err = errorText()
        val spin = ProgressBar(this).apply { visibility = View.GONE }
        val go = button(if (creating) "Create vault" else "Unlock", primary = true)
        root.add(go, 16)
        root.add(spin)
        root.add(err)
        if (!creating) root.add(button("Forgot it? Reset PawKey…").apply {
            background = null
            setTextColor(p.dim)
            setOnClickListener { resetDialog() }
        }, 24)

        go.setOnClickListener {
            val pw = pw1.text.toString()
            if (creating && pw.isEmpty()) return@setOnClickListener err.show("Pick a password (a long one).")
            if (creating && pw != pw2.text.toString()) return@setOnClickListener err.show("The two passwords don't match.")
            err.show("")
            go.isEnabled = false
            spin.visibility = View.VISIBLE
            bg({ if (creating) createVault(vaultPath, pw) else openVault(vaultPath, pw) }) { r ->
                go.isEnabled = true
                spin.visibility = View.GONE
                r.onSuccess { unlocked(it) }.onFailure { err.show(message(it)); pw1.requestFocus() }
            }
        }
        val submit = TextView.OnEditorActionListener { _, id, _ ->
            if (id == EditorInfo.IME_ACTION_DONE || id == EditorInfo.IME_ACTION_GO) { go.performClick(); true } else false
        }
        pw1.imeOptions = if (creating) EditorInfo.IME_ACTION_NEXT else EditorInfo.IME_ACTION_GO
        pw2.imeOptions = EditorInfo.IME_ACTION_GO
        pw1.setOnEditorActionListener(submit)
        pw2.setOnEditorActionListener(submit)
        setScreen(ScrollView(this).apply { setBackgroundColor(p.bg); addView(root) })
        pw1.requestFocus()
    }

    private fun unlocked(s: Session) {
        session = s
        lastActive = SystemClock.elapsedRealtime()
        showMain()
        pendingLink?.let { pendingLink = null; addDialog(it) }
        syncSoon(true)
    }

    private fun wipe() {
        // Destroying the session drops the vault: its key and every secret are wiped.
        session?.destroy()
        session = null
        syncStatus = ""
        lastSync = 0
        syncAgain = null
    }

    private fun lock() {
        wipe()
        rows.clear()
        showLock()
    }

    private fun resetDialog() {
        val v = vbox(20)
        v.add(text("This wipes the vault and every account in it, for good: there's no way back without the password. " +
            "You'll need to set up two-factor again for each site (with its recovery codes).\n\nType RESET to go ahead.", 15f), 0)
        val e = edit("RESET")
        v.add(e)
        val d = AlertDialog.Builder(this).setTitle("Reset PawKey").setView(v)
            .setNegativeButton("Cancel", null).setPositiveButton("Wipe everything", null).create()
        d.setOnShowListener {
            val ok = d.getButton(AlertDialog.BUTTON_POSITIVE)
            ok.isEnabled = false
            ok.setTextColor(p.red)
            e.addTextChangedListener(watcher { ok.isEnabled = it == "RESET" })
            ok.setOnClickListener {
                bg({ destroyVault(vaultPath) }) { r ->
                    r.onSuccess { d.dismiss(); showLock() }.onFailure { toast(message(it)) }
                }
            }
        }
        guard(d.window)
        d.show()
    }

    // ------------------------------------------------------------ the codes

    private fun showMain() {
        val root = vbox().apply { setBackgroundColor(p.bg) }
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(px(16), px(8), px(4), px(4))
        }
        bar.addView(text("PawKey", 20f, bold = true), LinearLayout.LayoutParams(0, -2, 1f))
        fun barButton(label: String, what: String, onClick: (View) -> Unit) = text(label, 24f).apply {
            contentDescription = what
            setPadding(px(14), px(6), px(14), px(6))
            setOnClickListener(onClick)
            bar.addView(this)
        }
        barButton("+", "Add an account") { addDialog(null) }
        syncBtn = barButton("⟳", "Sync now") { syncSoon(true); toast(syncStatus.ifEmpty { "Syncing…" }) }
        barButton("⋮", "Menu") { menu(it) }
        root.addView(bar)

        val searchBox = edit("Search")
        searchBox.setText(search)
        searchBox.addTextChangedListener(watcher { search = it.lowercase(); renderList() })
        root.addView(searchBox, LinearLayout.LayoutParams(-1, -2).apply { setMargins(px(16), 0, px(16), 0) })

        val list = vbox().apply { setPadding(px(12), px(4), px(12), px(24)) }
        listBox = list
        emptyText = text(
            "No accounts yet.\n\nTap + to add one: scan the setup QR code the site shows, or paste its setup key.",
            15f, p.dim,
        ).apply { gravity = Gravity.CENTER; setPadding(px(24), px(48), px(24), 0) }
        list.addView(emptyText)
        root.addView(ScrollView(this).apply { addView(list) }, LinearLayout.LayoutParams(-1, 0, 1f))
        setScreen(root)
        refreshSyncButton()
        renderList()
    }

    private fun renderList() {
        val s = session ?: return
        val list = listBox ?: return
        accounts = s.accounts()
        rows.clear()
        list.removeAllViews()
        emptyText?.let { list.addView(it) }
        emptyText?.visibility = if (accounts.isEmpty()) View.VISIBLE else View.GONE
        accounts.forEachIndexed { i, a ->
            if (search.isNotEmpty() && !"${a.issuer} ${a.name}".lowercase().contains(search)) return@forEachIndexed
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(px(16), px(14), px(16), px(14))
                background = GradientDrawable().apply { setColor(p.card); cornerRadius = 12 * dp }
                isClickable = true
                isLongClickable = true
                setOnClickListener { copyCode(a.uid) }
                setOnLongClickListener { deleteDialog(a); true }
            }
            val left = vbox()
            left.addView(text(a.title, 16f, bold = true).apply { maxLines = 1; ellipsize = android.text.TextUtils.TruncateAt.END })
            if (a.issuer.isNotEmpty() && a.name.isNotEmpty()) {
                left.addView(text(a.name, 14f, p.dim).apply { maxLines = 1; ellipsize = android.text.TextUtils.TruncateAt.END })
            }
            row.addView(left, LinearLayout.LayoutParams(0, -2, 1f))
            val code = text("", 26f, bold = true).apply { typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD) }
            val secs = text("", 13f, p.dim).apply { typeface = Typeface.MONOSPACE; setPadding(px(10), 0, 0, 0); minEms = 2 }
            row.addView(code)
            row.addView(secs)
            list.addView(row, LinearLayout.LayoutParams(-1, -2).apply { topMargin = px(10) })
            rows.add(Triple(i, code, secs))
        }
        updateCodes()
    }

    private fun updateCodes() {
        val s = session ?: return
        if (rows.isEmpty()) return
        val codes = s.codes(now())
        for ((i, code, secs) in rows) {
            val c = codes.getOrNull(i) ?: continue
            val half = c.code.length / 2
            val shown = c.code.substring(0, half) + " " + c.code.substring(half)
            if (code.text != shown) code.text = shown
            secs.text = "${c.remaining}s"
            code.setTextColor(if (c.remaining <= 5u) p.red else p.text)
        }
    }

    private fun copyText(value: String, msg: String) {
        Clipboard.copy(this, value)
        toast("$msg The clipboard clears in 30 seconds.")
    }

    private fun copyCode(uid: String) {
        val code = session?.code(uid, now()) ?: return
        copyText(code, "Copied.")
    }

    private fun deleteDialog(a: AccountView) {
        val title = if (a.issuer.isEmpty() || a.name.isEmpty()) a.title else "${a.issuer} (${a.name})"
        AlertDialog.Builder(this)
            .setTitle("Delete $title?")
            .setMessage("Its codes will be gone from PawKey. Turn two-factor off for it first (or set it up again), or you may be locked out of that account.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Delete") { _, _ ->
                val s = session ?: return@setPositiveButton
                bg({ s.delete(a.uid) }) { r ->
                    r.onSuccess { renderList(); toast("Deleted $title."); syncSoon(false) }.onFailure { toast(message(it)) }
                }
            }
            .open()
    }

    // ------------------------------------------------------------ adding

    /** What a QR code's text means for us: a setup link, or why not. */
    private fun setupLink(found: List<String>): Result<String> {
        found.firstOrNull { it.startsWith("otpauth://") }?.let { return Result.success(it) }
        val why = when {
            found.isEmpty() -> "No QR code found in that picture."
            found.any { it.startsWith("otpauth-migration://") } -> "That's a Google Authenticator export code; those can't be read yet. Add each account from its own setup code."
            else -> "That QR code isn't a two-factor setup code."
        }
        return Result.failure(Exception(why))
    }

    private fun addDialog(prefill: String?) {
        val s = session ?: return
        val v = vbox(20)
        v.add(text("Scan the QR code the site shows, or paste its setup link or key.", 15f, p.dim), 0)
        val scan = button("Scan the QR code", primary = true)
        val picture = button("QR from a picture")
        v.add(scan)
        v.add(picture, 4)
        val link = edit("otpauth:// link, or the secret key")
        val issuer = edit("Service (GitHub, say)")
        val name = edit("Account (you@example.com, say)")
        v.add(link, 12)
        v.add(issuer)
        v.add(name)
        val more = vbox().apply { visibility = View.GONE }
        val digits = Spinner(this).apply { adapter = ArrayAdapter(context, android.R.layout.simple_spinner_dropdown_item, listOf("6 digits", "7 digits", "8 digits")) }
        val period = edit("Seconds per code").apply { setText("30"); inputType = InputType.TYPE_CLASS_NUMBER }
        val algo = Spinner(this).apply { adapter = ArrayAdapter(context, android.R.layout.simple_spinner_dropdown_item, listOf("SHA-1", "SHA-256", "SHA-512")) }
        more.add(digits, 0)
        more.add(period)
        more.add(algo)
        val moreToggle = text("More options (most sites use the defaults) ▸", 14f, p.accent).apply { setPadding(0, px(8), 0, px(8)) }
        moreToggle.setOnClickListener { more.visibility = if (more.visibility == View.GONE) View.VISIBLE else View.GONE }
        v.add(moreToggle)
        v.add(more, 0)
        val err = errorText()
        v.add(err)

        link.addTextChangedListener(watcher { t ->
            if (!t.trim().startsWith("otpauth")) return@watcher err.show("")
            try {
                val a = parseLink(t.trim())
                issuer.setText(a.issuer)
                name.setText(a.name)
                digits.setSelection((a.digits.toInt() - 6).coerceIn(0, 2))
                period.setText(a.period.toString())
                err.show("")
            } catch (e: Exception) {
                err.show(message(e))
            }
        })
        val gotLink = { uri: String -> link.setText(uri) }
        scan.setOnClickListener {
            withCamera {
                QrScanner(this) { found ->
                    setupLink(found).onSuccess(gotLink).isSuccess.also { ok ->
                        if (!ok && found.any { it.startsWith("otpauth-migration://") }) toast(setupLink(found).exceptionOrNull()?.message ?: "")
                    }
                }.show()
            }
        }
        picture.setOnClickListener {
            onPicture = { uri -> gotLink(uri) }
            @Suppress("DEPRECATION")
            startActivityForResult(Intent(Intent.ACTION_GET_CONTENT).setType("image/*").addCategory(Intent.CATEGORY_OPENABLE), REQ_PICTURE)
        }

        val d = AlertDialog.Builder(this).setTitle("Add account").setView(ScrollView(this).apply { addView(v) })
            .setNegativeButton("Cancel", null).setPositiveButton("Add", null).create()
        d.setOnShowListener {
            d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val t = link.text.toString().trim()
                if (t.isEmpty()) return@setOnClickListener err.show("Scan the QR code, or paste the setup link or key, first.")
                val (iss, nm) = issuer.text.toString() to name.text.toString()
                val algorithm = listOf("SHA1", "SHA256", "SHA512")[algo.selectedItemPosition.coerceIn(0, 2)]
                val secs = period.text.toString().toULongOrNull() ?: 30u
                bg({
                    if (t.startsWith("otpauth")) s.addLink(t, iss, nm)
                    else s.addSecret(t, iss, nm, (6 + digits.selectedItemPosition).toUInt(), secs, algorithm)
                }) { r ->
                    r.onSuccess { d.dismiss(); renderList(); toast("Added ${it.title}."); syncSoon(false) }.onFailure { err.show(message(it)) }
                }
            }
        }
        guard(d.window)
        d.show()
        prefill?.let { link.setText(it) }
    }

    private fun withCamera(go: () -> Unit) {
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) return go()
        onCamera = go
        requestPermissions(arrayOf(Manifest.permission.CAMERA), REQ_CAMERA)
    }

    override fun onRequestPermissionsResult(code: Int, perms: Array<out String>, results: IntArray) {
        super.onRequestPermissionsResult(code, perms, results)
        if (code != REQ_CAMERA) return
        val go = onCamera
        onCamera = null
        if (results.firstOrNull() == PackageManager.PERMISSION_GRANTED) go?.invoke()
        else toast("PawKey needs the camera only to scan QR codes. A picture of the code, or its setup key, works too.")
    }

    @Deprecated("startActivityForResult")
    override fun onActivityResult(code: Int, result: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(code, result, data)
        if (code != REQ_PICTURE) return
        val done = onPicture
        onPicture = null
        val uri: Uri = data?.data ?: return
        if (result != RESULT_OK || done == null) return
        bg({ readPicture(uri) }) { r ->
            r.onSuccess { found -> setupLink(found).onSuccess(done).onFailure { toast(it.message ?: "") } }
                .onFailure { toast("That file isn't a picture PawKey can read.") }
        }
    }

    /** The QR codes in a picture, read at up to about 2000 pixels across. */
    private fun readPicture(uri: Uri): List<String> {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        contentResolver.openInputStream(uri)!!.use { BitmapFactory.decodeStream(it, null, bounds) }
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / sample > 2000) sample *= 2
        val bmp = contentResolver.openInputStream(uri)!!.use {
            BitmapFactory.decodeStream(it, null, BitmapFactory.Options().apply { inSampleSize = sample })
        } ?: throw Exception("not a picture")
        val (w, h) = bmp.width to bmp.height
        val px = IntArray(w * h)
        bmp.getPixels(px, 0, w, 0, 0, w, h)
        bmp.recycle()
        val grey = ByteArray(w * h) { i ->
            val c = px[i]
            val a = c ushr 24
            val l = (299 * ((c shr 16) and 255) + 587 * ((c shr 8) and 255) + 114 * (c and 255)) / 1000
            // Transparent counts as white.
            ((l * a + 255 * (255 - a)) / 255).toByte()
        }
        return readQr(w.toUInt(), h.toUInt(), grey)
    }

    // ------------------------------------------------------------ menu

    private fun menu(anchor: View) {
        val m = PopupMenu(this, anchor)
        m.menu.add(0, 1, 0, "Sync…")
        m.menu.add(0, 2, 1, "Dark theme").apply { isCheckable = true; isChecked = prefs.getBoolean("dark", true) }
        m.menu.add(0, 3, 2, "Change password…")
        m.menu.add(0, 4, 3, "Lock")
        m.menu.add(0, 5, 4, "About PawKey")
        m.setOnMenuItemClickListener {
            when (it.itemId) {
                1 -> syncDialog()
                2 -> { prefs.edit().putBoolean("dark", !prefs.getBoolean("dark", true)).apply(); recreate() }
                3 -> passwordDialog()
                4 -> lock()
                5 -> AlertDialog.Builder(this).setTitle("PawKey ${packageManager.getPackageInfo(packageName, 0).versionName}")
                    .setMessage("Two-factor codes, kept in an encrypted vault.\n\nMIT or Apache-2.0, as you prefer.\nhttps://github.com/anti-ghostsec/PawKey")
                    .setPositiveButton("OK", null).open()
            }
            true
        }
        m.show()
    }

    private fun passwordDialog() {
        val s = session ?: return
        val v = vbox(20)
        v.add(text("PawKey will be sealed with the new password. The old one stops working.", 15f, p.dim), 0)
        val pw1 = edit("New password", password = true)
        val pw2 = edit("New password again", password = true)
        v.add(pw1)
        v.add(pw2)
        val err = errorText()
        v.add(err)
        val d = AlertDialog.Builder(this).setTitle("Change password").setView(v)
            .setNegativeButton("Cancel", null).setPositiveButton("Change", null).create()
        d.setOnShowListener {
            val ok = d.getButton(AlertDialog.BUTTON_POSITIVE)
            ok.setOnClickListener {
                val pw = pw1.text.toString()
                if (pw.isEmpty()) return@setOnClickListener err.show("Pick a password.")
                if (pw != pw2.text.toString()) return@setOnClickListener err.show("The two passwords don't match.")
                ok.isEnabled = false
                bg({ s.changePassword(pw) }) { r ->
                    ok.isEnabled = true
                    r.onSuccess { d.dismiss(); toast("Password changed.") }.onFailure { err.show(message(it)) }
                }
            }
        }
        guard(d.window)
        d.show()
    }

    // ------------------------------------------------------------ sync

    private fun refreshSyncButton() {
        syncBtn?.visibility = if (session?.syncLogin() != null) View.VISIBLE else View.GONE
        syncBtn?.alpha = if (syncing) 0.4f else 1f
    }

    private fun setSyncStatus(s: String) {
        syncStatus = s
        statusLabel?.text = s
        refreshSyncButton()
    }

    private fun syncSoon(force: Boolean) {
        val s = session ?: return
        if (s.syncLogin() == null) return
        if (syncing) { syncAgain = force || syncAgain == true; return }
        syncing = true
        lastSync = SystemClock.elapsedRealtime()
        refreshSyncButton()
        net.execute {
            val r = runCatching { s.sync(http, force) }
            ui.post {
                syncing = false
                if (session !== s || isDestroyed) return@post
                r.onSuccess { changed ->
                    setSyncStatus("Synced at " + SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date()))
                    if (changed) renderList()
                }.onFailure { setSyncStatus("Couldn't sync: ${message(it)}") }
                syncAgain?.let { syncAgain = null; syncSoon(it) }
            }
        }
    }

    private fun syncDialog() {
        val s = session ?: return
        val v = vbox(20)
        val d = AlertDialog.Builder(this).setTitle("Sync").setView(ScrollView(this).apply { addView(v) })
            .setPositiveButton("Done", null).create()
        val login = s.syncLogin()
        if (login == null) syncOffPage(v, d, s) else syncOnPage(v, d, s, login)
        guard(d.window)
        d.show()
    }

    private fun syncOffPage(v: LinearLayout, d: AlertDialog, s: Session) {
        v.add(text("Sync keeps your accounts the same on every device with PawKey, through xBrowserSync, the way Wisp syncs. " +
            "They're encrypted here before they're sent: the service only ever sees random bytes. It's off until you turn it on.", 15f), 0)
        v.add(text("Service", 13f, p.dim), 12)
        val service = edit("https://…").apply { setText(defaultSyncService()) }
        v.add(service, 0)
        val create = button("Make a new sync ID", primary = true)
        v.add(create)
        v.add(text("Or use a sync ID you already have, from another PawKey (or Wisp's):", 15f), 20)
        val id = edit("Sync ID")
        val pw = edit("Sync password", password = true)
        v.add(id)
        v.add(pw)
        val connect = button("Connect")
        v.add(connect)
        val spin = ProgressBar(this).apply { visibility = View.GONE }
        val err = errorText()
        v.add(spin)
        v.add(err)
        fun busy(on: Boolean) {
            create.isEnabled = !on
            connect.isEnabled = !on
            spin.visibility = if (on) View.VISIBLE else View.GONE
        }
        fun run(job: () -> Unit) {
            busy(true)
            net.execute {
                val r = runCatching(job)
                ui.post {
                    if (isDestroyed) return@post
                    busy(false)
                    r.onSuccess { d.dismiss(); syncDialog(); syncSoon(true) }.onFailure { err.show(message(it)) }
                }
            }
        }
        create.setOnClickListener { val svc = service.text.toString(); run { s.syncCreate(svc, http) } }
        connect.setOnClickListener {
            val login = SyncLogin(service.text.toString(), id.text.toString().trim(), pw.text.toString())
            if (login.id.isEmpty() || login.password.isEmpty()) return@setOnClickListener err.show("Type the sync ID and its password.")
            run { s.syncConnect(login, http) }
        }
    }

    private fun syncOnPage(v: LinearLayout, d: AlertDialog, s: Session, login: SyncLogin) {
        v.add(text("Sync is on: every device with this sync ID has the same accounts. They're encrypted here before they're sent.", 15f), 0)
        val status = text(syncStatus, 14f, p.dim)
        statusLabel = status
        // Only this dialog's own label: closing an old one mustn't clear a new one's.
        d.setOnDismissListener { if (statusLabel === status) statusLabel = null }
        v.add(status)
        fun field(label: String, value: String, secret: Boolean) {
            v.add(text(label, 13f, p.dim), 14)
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            val shown = text(if (secret) "•".repeat(16) else value, 15f).apply { setTextIsSelectable(!secret) }
            row.addView(shown, LinearLayout.LayoutParams(0, -2, 1f))
            if (secret) row.addView(text("Show", 14f, p.accent).apply {
                setPadding(px(12), px(8), px(12), px(8))
                setOnClickListener { shown.text = value; visibility = View.GONE }
            })
            row.addView(text("Copy", 14f, p.accent).apply {
                setPadding(px(12), px(8), px(12), px(8))
                setOnClickListener { copyText(value, "Copied the ${label.lowercase()}.") }
            })
            v.add(row, 0)
        }
        field("Service", login.service, false)
        field("Sync ID", login.id, false)
        field("Password", login.password, true)
        v.add(text("To add another device: open PawKey there, then Sync… → use a sync ID you already have, and type these two. " +
            "Keep the password to yourself: with the sync ID, it opens your accounts.", 14f, p.dim), 14)
        val now = button("Sync now")
        val off = button("Turn off sync…", danger = true)
        v.add(now, 14)
        v.add(off, 4)
        now.setOnClickListener { syncSoon(true) }
        off.setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("Turn off sync on this device?")
                .setMessage("Your accounts stay here, and on the service for your other devices. To sync again, use the same sync ID and password: copy them first if you haven't kept them.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Turn off") { _, _ ->
                    bg({ s.syncOff() }) { r ->
                        r.onSuccess { d.dismiss(); setSyncStatus(""); toast("Sync is off.") }.onFailure { toast(message(it)) }
                    }
                }
                .open()
        }
    }

    private fun watcher(f: (String) -> Unit) = object : TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        override fun afterTextChanged(s: Editable?) = f(s?.toString() ?: "")
    }
}

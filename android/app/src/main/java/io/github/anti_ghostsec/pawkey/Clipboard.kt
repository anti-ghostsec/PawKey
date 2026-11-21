package io.github.anti_ghostsec.pawkey

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock

/**
 * Copies a code or secret and clears it from the clipboard [CLEAR_MS] later,
 * even when PawKey has been closed or frozen in the background since: a
 * timer in the app for when it's still running, and an alarm (which wakes
 * it) for when it isn't. Whichever comes first clears; the other is called
 * off.
 *
 * Android 10+ doesn't let an app in the background read the clipboard, so
 * there PawKey can't always tell whether what's on it is still its own. It
 * clears it unless it saw something else copied over it: rather wipe a
 * copy made in another app in those 30 seconds than leave a code there.
 */
object Clipboard {
    const val CLEAR_MS = 30_000L
    private const val LABEL = "PawKey"
    private const val EXTRA_TOKEN = "token"

    private val main = Handler(Looper.getMainLooper())
    // What's pending, and whether something else has been copied over it since.
    private var token: Long = 0
    private var value: String? = null
    private var replaced = false
    private var listening = false

    fun copy(context: Context, text: String) {
        val app = context.applicationContext
        val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(LABEL, text)
        // Android 13+: the clipboard preview doesn't show it.
        if (Build.VERSION.SDK_INT >= 33) clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        if (!listening) {
            listening = true
            // Only told while PawKey is in front (Android 10+), and then it can read.
            cm.addPrimaryClipChangedListener {
                if (value != null && read(cm)?.let { it != value } == true) replaced = true
            }
        }
        main.removeCallbacksAndMessages(null)
        token = SystemClock.elapsedRealtimeNanos()
        value = text
        cm.setPrimaryClip(clip)
        replaced = false
        val t = token
        main.postDelayed({ fire(app, t) }, CLEAR_MS)
        val am = app.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + CLEAR_MS, alarm(app, t))
    }

    /** From the timer or the alarm. A token of 0 is an alarm from before PawKey was restarted. */
    internal fun fire(app: Context, t: Long) {
        if (t != token && token != 0L) return // a newer copy has its own
        val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val current = read(cm)
        val ours = when {
            current != null -> current == value || (value == null && label(cm) == LABEL)
            else -> !replaced // can't read it from the background: clear unless it was replaced
        }
        if (ours) clear(cm)
        main.removeCallbacksAndMessages(null)
        (app.getSystemService(Context.ALARM_SERVICE) as AlarmManager).cancel(alarm(app, t))
        token = 0
        value = null
        replaced = false
    }

    private fun alarm(app: Context, t: Long): PendingIntent = PendingIntent.getBroadcast(
        app, 0,
        Intent(app, ClipboardClearer::class.java).putExtra(EXTRA_TOKEN, t),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )

    private fun read(cm: ClipboardManager): String? =
        try { cm.primaryClip?.getItemAt(0)?.text?.toString() } catch (_: Exception) { null }

    private fun label(cm: ClipboardManager): String? =
        try { cm.primaryClipDescription?.label?.toString() } catch (_: Exception) { null }

    private fun clear(cm: ClipboardManager) {
        try {
            if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip()
            else cm.setPrimaryClip(ClipData.newPlainText("", ""))
        } catch (_: Exception) {}
    }

    internal fun tokenOf(intent: Intent) = intent.getLongExtra(EXTRA_TOKEN, 0)
}

/** The alarm's end of [Clipboard]: wakes PawKey to clear the clipboard. */
class ClipboardClearer : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        Clipboard.fire(context.applicationContext, Clipboard.tokenOf(intent))
    }
}

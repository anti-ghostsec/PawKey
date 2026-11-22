package io.github.anti_ghostsec.pawkey

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/**
 * Where a tapped `otpauth://` link lands. Android keeps the Intent that
 * started a task (the link, secret and all) in its recent-tasks files, so
 * the link never starts PawKey's own task: this activity runs in a task of
 * its own that's left out of recents and removed when it finishes, hands
 * the link to [MainActivity] in memory, and is gone.
 */
class LinkActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val uri = intent?.data?.toString()
        intent = Intent()
        if (uri != null && uri.startsWith("otpauth://")) MainActivity.incomingLink = uri
        startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        finishAndRemoveTask()
    }
}

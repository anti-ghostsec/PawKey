package io.github.anti_ghostsec.pawkey

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Dialog
import android.content.Context
import android.graphics.Color
import android.graphics.ImageFormat
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.util.Size
import android.view.Gravity
import android.view.Surface
import android.view.TextureView
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import uniffi.pawkey_ffi.readQr

/**
 * A full-screen camera that looks for QR codes, with camera2 (no libraries).
 * Each frame's brightness (the Y plane) goes to pawkey-core's QR reader;
 * nothing is saved. [onFound] gets every QR code's text and returns true
 * when it's the one wanted, which closes the scanner.
 */
@SuppressLint("MissingPermission") // asked for before this is made
class QrScanner(private val activity: Activity, private val onFound: (List<String>) -> Boolean) {
    private val thread = HandlerThread("pawkey-camera").apply { start() }
    private val handler = Handler(thread.looper)
    private val dialog = Dialog(activity, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
    private val texture = TextureView(activity)
    private val hint = TextView(activity)
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    @Volatile private var busy = false
    @Volatile private var closed = false

    fun show() {
        val dp = activity.resources.displayMetrics.density
        val root = FrameLayout(activity).apply { setBackgroundColor(Color.BLACK) }
        root.addView(texture, FrameLayout.LayoutParams(-1, -1, Gravity.CENTER))
        val bottom = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding((16 * dp).toInt(), (16 * dp).toInt(), (16 * dp).toInt(), (32 * dp).toInt())
            setBackgroundColor(0xAA000000.toInt())
        }
        hint.text = "Point the camera at the setup QR code."
        hint.setTextColor(Color.WHITE)
        hint.textSize = 16f
        hint.gravity = Gravity.CENTER
        bottom.addView(hint)
        bottom.addView(Button(activity).apply { text = "Cancel"; setOnClickListener { close() } })
        root.addView(bottom, FrameLayout.LayoutParams(-1, -2, Gravity.BOTTOM))
        dialog.setContentView(root)
        dialog.setOnDismissListener { release() }
        dialog.show()
        texture.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(st: SurfaceTexture, w: Int, h: Int) = open(st)
            override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, w: Int, h: Int) {}
            override fun onSurfaceTextureDestroyed(st: SurfaceTexture) = true
            override fun onSurfaceTextureUpdated(st: SurfaceTexture) {}
        }
    }

    fun close() {
        if (dialog.isShowing) dialog.dismiss() else release()
    }

    private fun say(text: String) = activity.runOnUiThread { hint.text = text }

    private fun open(st: SurfaceTexture) {
        val manager = activity.getSystemService(Context.CAMERA_SERVICE) as CameraManager
        val id = try {
            manager.cameraIdList.firstOrNull {
                manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK
            } ?: manager.cameraIdList.firstOrNull()
        } catch (e: Exception) {
            null
        } ?: return say("This device has no camera PawKey can use.")
        val map = manager.getCameraCharacteristics(id).get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
        val sizes = map?.getOutputSizes(ImageFormat.YUV_420_888) ?: emptyArray()
        // About 1280x720: enough for a QR code across the room, quick to read.
        val size = sizes.minByOrNull { Math.abs(it.width * it.height - 1280 * 720) } ?: Size(640, 480)
        st.setDefaultBufferSize(size.width, size.height)
        fitPreview(size)
        val r = ImageReader.newInstance(size.width, size.height, ImageFormat.YUV_420_888, 2)
        reader = r
        r.setOnImageAvailableListener({ scan(it) }, handler)
        try {
            manager.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    if (closed) return device.close()
                    camera = device
                    startPreview(device, Surface(st), r.surface)
                }
                override fun onDisconnected(device: CameraDevice) = device.close()
                override fun onError(device: CameraDevice, error: Int) {
                    device.close()
                    say("The camera couldn't be opened (error $error).")
                }
            }, handler)
        } catch (e: Exception) {
            say("The camera couldn't be opened: ${e.message}")
        }
    }

    /** The camera's picture is landscape; shown upright in portrait, keep its shape. */
    private fun fitPreview(size: Size) = activity.runOnUiThread {
        val parent = texture.parent as? FrameLayout ?: return@runOnUiThread
        val w = parent.width
        val portrait = parent.height > parent.width
        val ratio = if (portrait) size.width.toFloat() / size.height else size.height.toFloat() / size.width
        texture.layoutParams = FrameLayout.LayoutParams(w, (w * ratio).toInt(), Gravity.CENTER)
    }

    @Suppress("DEPRECATION") // the list form of createCaptureSession: Android 8 has no other
    private fun startPreview(device: CameraDevice, preview: Surface, frames: Surface) {
        device.createCaptureSession(listOf(preview, frames), object : CameraCaptureSession.StateCallback() {
            override fun onConfigured(s: CameraCaptureSession) {
                if (closed) return s.close()
                session = s
                val req = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                    addTarget(preview)
                    addTarget(frames)
                    set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                }
                s.setRepeatingRequest(req.build(), null, handler)
            }
            override fun onConfigureFailed(s: CameraCaptureSession) = say("The camera couldn't start.")
        }, handler)
    }

    private fun scan(r: ImageReader) {
        val img = r.acquireLatestImage() ?: return
        if (busy || closed) return img.close()
        busy = true
        val (w, h) = img.width to img.height
        val plane = img.planes[0]
        val grey = ByteArray(w * h)
        val buf = plane.buffer
        val (row, px) = plane.rowStride to plane.pixelStride
        for (y in 0 until h) {
            if (px == 1) {
                buf.position(y * row)
                buf.get(grey, y * w, w)
            } else {
                for (x in 0 until w) grey[y * w + x] = buf.get(y * row + x * px)
            }
        }
        img.close()
        val found = try { readQr(w.toUInt(), h.toUInt(), grey) } catch (e: Exception) { emptyList() }
        busy = false
        if (found.isNotEmpty()) activity.runOnUiThread { if (!closed && onFound(found)) close() }
    }

    private fun release() {
        if (closed) return
        closed = true
        handler.post {
            try { session?.close() } catch (_: Exception) {}
            try { camera?.close() } catch (_: Exception) {}
            try { reader?.close() } catch (_: Exception) {}
            thread.quitSafely()
        }
    }
}

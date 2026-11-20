package io.github.anti_ghostsec.pawkey

import java.net.HttpURLConnection
import java.net.URL
import uniffi.pawkey_ffi.HttpClient
import uniffi.pawkey_ffi.HttpResponse

/**
 * Android's own HTTPS, for sync. pawkey-core decides what to send and checks
 * the address (HTTPS only, or this phone itself); this only carries it. Called
 * from a background thread.
 */
class AndroidHttp : HttpClient {
    override fun request(method: String, url: String, body: String?): HttpResponse = try {
        val c = URL(url).openConnection() as HttpURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = 15_000
            c.readTimeout = 30_000
            c.useCaches = false
            c.instanceFollowRedirects = false
            c.setRequestProperty("Accept", "application/json")
            if (body != null) {
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(body.toByteArray()) }
            }
            val status = c.responseCode
            val stream = if (status in 200..299) c.inputStream else c.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
            HttpResponse(status.toUShort(), text)
        } finally {
            c.disconnect()
        }
    } catch (e: Exception) {
        HttpResponse(0u, e.message ?: e.javaClass.simpleName)
    }
}

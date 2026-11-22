package io.github.anti_ghostsec.pawkey

import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import uniffi.pawkey_ffi.HttpClient
import uniffi.pawkey_ffi.HttpResponse

/**
 * Android's own HTTPS, for sync. pawkey-core decides what to send and checks
 * the address (HTTPS only, or this phone itself) and the proxy; this only
 * carries it. Called from a background thread.
 *
 * With a SOCKS proxy (Tor through Orbot), names are looked up by the proxy,
 * not here. The User-Agent says nothing about the phone (Android's own
 * names the model and build).
 */
class AndroidHttp : HttpClient {
    override fun request(method: String, url: String, body: String?, proxy: String): HttpResponse = try {
        val px = toProxy(proxy)
        val c = (if (px == null) URL(url).openConnection() else URL(url).openConnection(px)) as HttpURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = 15_000
            c.readTimeout = 30_000
            c.useCaches = false
            c.instanceFollowRedirects = false
            c.setRequestProperty("Accept", "application/json")
            c.setRequestProperty("User-Agent", "Mozilla/5.0")
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

    /** `socks5://host:port` (already checked by pawkey-core), or null: the system's settings. */
    private fun toProxy(proxy: String): Proxy? {
        if (proxy.isEmpty()) return null
        val hostPort = proxy.removePrefix("socks5://")
        val host = hostPort.substringBeforeLast(':').removePrefix("[").removeSuffix("]")
        val port = hostPort.substringAfterLast(':').toInt()
        return Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(host, port))
    }
}

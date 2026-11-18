package it.ipzs.l2plus

import android.app.Activity
import android.content.Context
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import android.os.Handler
import android.os.Looper
import java.io.IOException
import java.lang.ref.WeakReference
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Exactly one of [onSuccess] and [onError] is called, once, on the main thread. */
interface L2PlusCallback {
    fun onSuccess(result: L2PlusResult)
    fun onError(error: L2PlusException)
    fun onStep(step: L2PlusStep) {}
}

/**
 * Reads the L2+ evidence from a CIE over NFC.
 *
 * ```
 * val sdk = L2PlusSdk(activity, L2PlusTrustConfig(cscaCertificates))
 * sdk.start(L2PlusAccess.Can("123456"), challenge, callback)
 * ```
 *
 * The app collects the CAN or the MRZ data, gets the challenge from its backend and sends the result.
 * The SDK makes no network calls and keeps nothing after the callback.
 */
class L2PlusSdk(activity: Activity, private val trust: L2PlusTrustConfig) {

    private val activityRef = WeakReference(activity)
    private val main = Handler(Looper.getMainLooper())
    private val active = AtomicReference<Session?>(null)

    /**
     * Starts a read. Inputs are checked before NFC is enabled.
     * A call made while another read is running gets ALREADY_RUNNING; the running read is not affected.
     */
    fun start(access: L2PlusAccess, challenge: ByteArray, callback: L2PlusCallback) {
        val request = try {
            if (trust.mrtdTrustAnchors.isEmpty()) {
                throw L2PlusException(L2PlusErrorCode.MISSING_TRUST_ANCHORS, "No trust anchors configured")
            }
            L2PlusRequest.validate(access, challenge)
        } catch (e: L2PlusException) {
            main.post { callback.onError(e) }
            return
        }

        val activity = activityRef.get()
        val adapter = activity?.let { NfcAdapter.getDefaultAdapter(it) }
        if (activity == null || adapter == null) {
            main.post { callback.onError(L2PlusException(L2PlusErrorCode.NFC_NOT_AVAILABLE, "NFC not available")) }
            return
        }
        if (!adapter.isEnabled) {
            main.post { callback.onError(L2PlusException(L2PlusErrorCode.NFC_DISABLED, "NFC disabled")) }
            return
        }

        val session = Session(request, callback, adapter)
        if (!active.compareAndSet(null, session)) {
            main.post { callback.onError(L2PlusException(L2PlusErrorCode.ALREADY_RUNNING, "A read is already running")) }
            return
        }
        session.step(L2PlusStep.WAITING_FOR_CARD)
        val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
        adapter.enableReaderMode(activity, { tag -> session.onTag(tag) }, flags, null)
    }

    /** Stops the running read; the callback gets CANCELLED. */
    fun cancel() {
        active.get()?.finish(error = L2PlusException(L2PlusErrorCode.CANCELLED, "Read cancelled"))
    }

    private inner class Session(
        private val request: L2PlusRequest,
        private val callback: L2PlusCallback,
        private val adapter: NfcAdapter,
    ) {
        private val finished = AtomicBoolean(false)
        private val tagInUse = AtomicBoolean(false)

        fun step(s: L2PlusStep) {
            if (!finished.get()) main.post { if (!finished.get()) callback.onStep(s) }
        }

        fun onTag(tag: Tag) {
            if (finished.get() || !tagInUse.compareAndSet(false, true)) return
            val isoDep = IsoDep.get(tag)
            if (isoDep == null) {
                finish(error = L2PlusException(L2PlusErrorCode.TAG_NOT_SUPPORTED, "Tag does not support ISO-DEP"))
                return
            }
            step(L2PlusStep.CARD_DETECTED)
            try {
                isoDep.timeout = IO_TIMEOUT_MS
                isoDep.connect()
                val result = L2PlusReader(trust).read(
                    IsoDepTransport(isoDep),
                    request,
                    isCancelled = { finished.get() },
                    onStep = ::step,
                )
                finish(result = result)
            } catch (e: L2PlusException) {
                finish(error = e)
            } catch (e: Exception) {
                finish(error = L2PlusException(L2PlusErrorCode.INTERNAL_ERROR, "Unexpected error", cause = e))
            } finally {
                try { isoDep.close() } catch (_: IOException) { }
            }
        }

        fun finish(result: L2PlusResult? = null, error: L2PlusException? = null) {
            if (!finished.compareAndSet(false, true)) return
            active.compareAndSet(this, null)
            main.post {
                activityRef.get()?.let { a -> try { adapter.disableReaderMode(a) } catch (_: Exception) { } }
                if (result != null) callback.onSuccess(result) else callback.onError(error!!)
            }
        }
    }

    companion object {
        private const val IO_TIMEOUT_MS = 10_000

        /**
         * CSCA certificates shipped in the `csca/` assets folder.
         * Handy for testing; a production app should supply up-to-date trust material.
         */
        fun bundledCscaCertificates(context: Context): List<X509Certificate> {
            val factory = CertificateFactory.getInstance("X.509")
            val assets = context.assets
            return assets.list("csca").orEmpty().filter { it.endsWith(".cer") }.sorted().map { name ->
                assets.open("csca/$name").use { factory.generateCertificate(it) as X509Certificate }
            }
        }
    }
}

internal class IsoDepTransport(private val isoDep: IsoDep) : ApduTransport {
    override fun transceive(command: ByteArray): ByteArray =
        try {
            isoDep.transceive(command)
        } catch (e: TagLostException) {
            throw L2PlusException(L2PlusErrorCode.TAG_LOST, "Card removed", cause = e)
        } catch (e: IOException) {
            throw L2PlusException(L2PlusErrorCode.TAG_LOST, "Card communication lost", cause = e)
        }
}

package it.ipzs.l2plus.demo

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import it.ipzs.l2plus.L2PlusAccess
import it.ipzs.l2plus.L2PlusCallback
import it.ipzs.l2plus.L2PlusException
import it.ipzs.l2plus.L2PlusResult
import it.ipzs.l2plus.L2PlusSdk
import it.ipzs.l2plus.L2PlusStep
import it.ipzs.l2plus.L2PlusTrustConfig
import java.security.SecureRandom

/**
 * Minimal integration example. In a real wallet the challenge comes from the PID Provider
 * and the JSON is sent back inside the `mrtd_validation_jwt`.
 */
class MainActivity : Activity() {

    private lateinit var sdk: L2PlusSdk
    private var challenge = ByteArray(0)
    private var lastJson: String? = null

    private lateinit var accessType: RadioGroup
    private lateinit var can: EditText
    private lateinit var mrzFields: View
    private lateinit var documentNumber: EditText
    private lateinit var birthDate: EditText
    private lateinit var expiryDate: EditText
    private lateinit var challengeView: TextView
    private lateinit var read: Button
    private lateinit var cancel: Button
    private lateinit var status: TextView
    private lateinit var result: TextView
    private lateinit var copy: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        accessType = findViewById(R.id.accessType)
        can = findViewById(R.id.can)
        mrzFields = findViewById(R.id.mrzFields)
        documentNumber = findViewById(R.id.documentId)
        birthDate = findViewById(R.id.birthDate)
        expiryDate = findViewById(R.id.expiryDate)
        challengeView = findViewById(R.id.challenge)
        read = findViewById(R.id.read)
        cancel = findViewById(R.id.cancel)
        status = findViewById(R.id.status)
        result = findViewById(R.id.result)
        copy = findViewById(R.id.copy)

        sdk = L2PlusSdk(this, L2PlusTrustConfig(L2PlusSdk.bundledCscaCertificates(this)))

        accessType.setOnCheckedChangeListener { _, id ->
            val mrz = id == R.id.accessMrz
            can.visibility = if (mrz) View.GONE else View.VISIBLE
            mrzFields.visibility = if (mrz) View.VISIBLE else View.GONE
        }
        findViewById<Button>(R.id.newChallenge).setOnClickListener { newChallenge() }
        read.setOnClickListener { startRead() }
        cancel.setOnClickListener { sdk.cancel() }
        copy.setOnClickListener { copyJson() }
        newChallenge()
    }

    override fun onPause() {
        super.onPause()
        sdk.cancel()
    }

    private fun newChallenge() {
        challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        challengeView.text = challenge.joinToString("") { "%02X".format(it) }
    }

    private fun startRead() {
        val access = if (accessType.checkedRadioButtonId == R.id.accessMrz) {
            L2PlusAccess.Mrz(documentNumber.text.toString(), birthDate.text.toString(), expiryDate.text.toString())
        } else {
            L2PlusAccess.Can(can.text.toString())
        }
        setRunning(true)
        showResult(null)
        sdk.start(access, challenge, object : L2PlusCallback {
            override fun onStep(step: L2PlusStep) {
                status.setText(describe(step))
            }

            override fun onSuccess(result: L2PlusResult) {
                setRunning(false)
                status.setText(R.string.status_done)
                showResult(result.toJson())
            }

            override fun onError(error: L2PlusException) {
                setRunning(false)
                status.text = getString(R.string.status_error, error.code.name, error.action.name, error.message)
            }
        })
    }

    private fun setRunning(running: Boolean) {
        read.isEnabled = !running
        cancel.isEnabled = running
    }

    private fun showResult(json: String?) {
        lastJson = json
        result.text = json.orEmpty()
        copy.visibility = if (json == null) View.GONE else View.VISIBLE
    }

    private fun copyJson() {
        val json = lastJson ?: return
        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("L2+", json))
        Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show()
    }

    private fun describe(step: L2PlusStep): Int = when (step) {
        L2PlusStep.WAITING_FOR_CARD -> R.string.step_waiting
        L2PlusStep.CARD_DETECTED, L2PlusStep.PACE -> R.string.step_detected
        L2PlusStep.READING_MRTD -> R.string.step_mrtd
        L2PlusStep.READING_IAS, L2PlusStep.SIGNING_CHALLENGE -> R.string.step_ias
        L2PlusStep.VERIFYING -> R.string.step_verifying
    }
}

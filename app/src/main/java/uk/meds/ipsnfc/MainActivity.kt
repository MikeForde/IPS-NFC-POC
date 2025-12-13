package uk.meds.ipsnfc  // <-- make sure this matches your package name

import android.nfc.NfcAdapter
import android.nfc.Tag
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import android.nfc.tech.Ndef
import android.widget.AdapterView
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.lifecycle.lifecycleScope
import android.widget.ArrayAdapter
import android.widget.ImageButton
import android.widget.Spinner
import android.widget.TabHost



class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private enum class PendingAction { NONE, WRITE, READ, FORMAT, WRITE_DUAL_NDEF, FORMAT_FOR_NDEF, READ_DUAL_NDEF, WRITE_NATO, READ_NATO, FORMAT_NATO }

    private var nfcAdapter: NfcAdapter? = null
    private var pendingAction: PendingAction = PendingAction.NONE

    private val http = OkHttpClient()
    private val httpClient = okhttp3.OkHttpClient()
    private val gson = com.google.gson.GsonBuilder().setPrettyPrinting().create()

    private data class IpsListItem(
        val packageUUID: String,
        val given: String,
        val name: String
    ) {
        fun label(): String = "${name}, ${given}  (${packageUUID.take(8)})"
    }

    private data class SplitResponse(
        val id: String?,
        val cutoff: String?,
        val protect: String?,
        val ro: Any?,
        val rw: Any?
    )

    private var ipsList: List<IpsListItem> = emptyList()
    private var selectedPackageUuid: String? = null

    private val PREFS = "ips_prefs"
    private val KEY_BASE_URL = "ips_base_url"

    private val BASE_LOCAL = "http://localhost:5050"
    private val BASE_AZURE = "https://ipsmern-dep.azurewebsites.net"

    private fun getIpsBase(): String {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        return prefs.getString(KEY_BASE_URL, BASE_AZURE) ?: BASE_AZURE
    }

    private fun setIpsBase(base: String) {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().putString(KEY_BASE_URL, base).apply()
    }

    private fun ipsListUrl(): String = "${getIpsBase()}/ips/list"
    private fun ipsSplitUrlBase(): String = "${getIpsBase()}/ipsunifiedsplit/"



    private lateinit var statusText: TextView
    private lateinit var textHistoric: EditText
    private lateinit var textRw: EditText
    private lateinit var buttonWrite: Button
    private lateinit var buttonRead: Button
    private lateinit var buttonFormatApp: Button
    private lateinit var buttonWriteDualNdef: Button
    private lateinit var buttonFormatForNDEF:Button
    private lateinit var buttonReadDual:Button
    private lateinit var buttonWriteNato:Button
    private lateinit var buttonReadNato:Button
    private lateinit var buttonFormatForNATO:Button


    // For now, dummy payloads. Later these will be gzip’d IPS historic/new data.
    private val dummyHistoricPayload: ByteArray
        get() = """
            {
              "type": "historic",
              "message": "Dummy historic IPS payload 2",
              "entries": [ "Problem A", "Allergy B" ]
            }
        """.trimIndent().toByteArray(Charsets.UTF_8)

    private val dummyRwPayload: ByteArray
        get() = """
            {
              "type": "rw",
              "message": "Dummy read/write IPS payload 2",
              "entries": [ "Recent BP", "New medication" ]
            }
        """.trimIndent().toByteArray(Charsets.UTF_8)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<ImageButton>(R.id.buttonSettings).setOnClickListener {
            showBaseUrlChooser()
        }

        val tabHost = findViewById<TabHost>(android.R.id.tabhost)
        tabHost.setup()

        tabHost.addTab(
            tabHost.newTabSpec("ro")
                .setIndicator("RO (NPS)")
                .setContent(R.id.tab_ro)
        )

        tabHost.addTab(
            tabHost.newTabSpec("rw")
                .setIndicator("RW (Extra)")
                .setContent(R.id.tab_rw)
        )

// Default tab (optional)
        tabHost.currentTab = 0


        statusText = findViewById(R.id.statusText)
        textHistoric = findViewById(R.id.textHistoric)
        textRw = findViewById(R.id.textRw)
        buttonWrite = findViewById(R.id.buttonWrite)
        buttonRead = findViewById(R.id.buttonRead)
        buttonFormatApp = findViewById(R.id.buttonFormatApp)
        buttonWriteDualNdef = findViewById(R.id.buttonWriteDualNdef)
        buttonFormatForNDEF = findViewById(R.id.buttonFormatForNDEF)
        buttonReadDual = findViewById(R.id.buttonReadDual)
        buttonWriteNato = findViewById(R.id.buttonWriteNato)
        buttonReadNato = findViewById(R.id.buttonReadNato)
        buttonFormatForNATO = findViewById(R.id.buttonFormatForNATO)
        val spinner = findViewById<Spinner>(R.id.spinnerIps)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            Toast.makeText(this, "NFC not available on this device", Toast.LENGTH_LONG).show()
            statusText.text = "NFC not available on this device"
        }

        buttonWrite.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.WRITE
            statusText.text = "WRITE mode: Tap DESFire card"
        }

        buttonRead.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.READ
            statusText.text = "READ mode: Tap DESFire card"
        }

        buttonFormatApp.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.FORMAT
            statusText.text = "FORMAT mode: Tap DESFire card – this will erase ALL apps"
        }

        buttonWriteDualNdef.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.WRITE_DUAL_NDEF
            statusText.text = "WRITE NDEF dual mode: tap DESFire card\n(This will FORMAT and recreate the app/files)"
        }

        buttonFormatForNDEF.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.FORMAT_FOR_NDEF
            statusText.text = "FORMAT For NDEF dual mode: tap DESFire card\n(This will FORMAT for NDEF + DES)"
        }

        buttonReadDual.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.READ_DUAL_NDEF
            statusText.text = "READ NDEF dual mode: tap DESFire card\n(This will READ NDEF + DES)"
        }

        buttonWriteNato.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.WRITE_NATO
            statusText.text = "WRITE NATO mode: tap DESFire card\n(This will WRITE NATO NDEF)"
        }

        buttonReadNato.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.READ_NATO
            statusText.text = "READ NATO mode: tap DESFire card\n(This will READ NATO NDEF)"
        }

        buttonFormatForNATO.setOnClickListener {
            if (nfcAdapter == null) return@setOnClickListener
            pendingAction = PendingAction.FORMAT_NATO
            statusText.text = "FORMAT for NATO mode: tap DESFire card\n(This will FORMAT for NATO NDEF)"
        }

        spinner.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: android.widget.AdapterView<*>,
                view: android.view.View,
                position: Int,
                id: Long
            ) {
                val uuid = ipsList.getOrNull(position)?.packageUUID
                selectedPackageUuid = uuid

                uuid?.let {
                    // Optional: update status immediately
                    statusText.text = "Fetching IPS split for: $it"
                    fetchAndShowSplit(it)   // <-- implement / call your existing network fetch here
                }
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>) {
                selectedPackageUuid = null
            }
        }

        findViewById<Button>(R.id.buttonRefreshIps).setOnClickListener {
            refreshIpsList()
        }

// load once at startup
        refreshIpsList()
    }

    override fun onResume() {
        super.onResume()
        enableReaderMode()
    }

    override fun onPause() {
        super.onPause()
        disableReaderMode()
    }

    private fun enableReaderMode() {
        val options = Bundle().apply {
            putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250)
        }

        nfcAdapter?.enableReaderMode(
            this,
            this,
            NfcAdapter.FLAG_READER_NFC_A or
                    NfcAdapter.FLAG_READER_NFC_B or   // harmless, but covers Type 4B too
                    NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
            options
        )
    }


    private fun disableReaderMode() {
        nfcAdapter?.disableReaderMode(this)
    }

    /**
     * Called on a binder thread when a tag is discovered.
     */
    override fun onTagDiscovered(tag: Tag?) {
        if (tag == null) return

        val techs = tag.techList.joinToString()
        runOnUiThread {
            statusText.text = "Tag techs: $techs"
        }

        val currentAction = pendingAction
        if (currentAction == PendingAction.NONE) return

        // 🔹 Special case: WRITE_DUAL_NDEF uses NDEFHelper, so do NOT open DesfireHelper here
        if (currentAction == PendingAction.WRITE_DUAL_NDEF) {
            try {
                handleWriteDualNdef(tag)   // this will call NDEFHelper.connect(...)
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
            return
        }

        // 🔹 Special case: WRITE_DUAL_NDEF uses NDEFHelper, so do NOT open DesfireHelper here
        if (currentAction == PendingAction.FORMAT_FOR_NDEF) {
            try {
                handleFormatForDualNdef(tag)   // this will call NDEFHelper.connect(...)
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
            return
        }

        if (currentAction == PendingAction.READ_DUAL_NDEF) {
            handleReadDualNdef(tag)
            return
        }

        // 🔹 Special case: NATO layout (000001 with two NDEF files) uses NATOHelper
        if (currentAction == PendingAction.WRITE_NATO) {
            try {
                handleWriteNato(tag)   // this should call NATOHelper.connect(...)
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
            return
        }

        if (currentAction == PendingAction.READ_NATO) {
            try {
                handleReadNato(tag)    // this should call NATOHelper.connect(...)
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
            return
        }

        if (currentAction == PendingAction.FORMAT_NATO) {
            try {
                handleFormatForNato(tag)    // this should call NATOHelper.connect(...)
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                }
            }
            return
        }

        // 🔹 All other actions use DesfireHelper as before
        val helper = DesfireHelper.connect(tag, debug = true)
        if (helper == null) {
            runOnUiThread {
                Toast.makeText(
                    this,
                    "Tag is not DESFire / IsoDep connect failed",
                    Toast.LENGTH_SHORT
                ).show()
                statusText.text = "Not a DESFire EVx card or connection error"
            }
            return
        }

        try {
            when (currentAction) {
                PendingAction.WRITE -> handleWrite(helper)
                PendingAction.READ  -> handleRead(helper)
                PendingAction.FORMAT -> handleFormat(helper)
                PendingAction.WRITE_DUAL_NDEF -> Unit
                PendingAction.FORMAT_FOR_NDEF -> Unit
                PendingAction.READ_DUAL_NDEF -> Unit
                PendingAction.WRITE_NATO -> Unit
                PendingAction.READ_NATO -> Unit
                PendingAction.FORMAT_NATO -> Unit
                PendingAction.NONE  -> Unit
                // 🚫 no WRITE_DUAL_NDEF here anymore
            }
        } catch (e: Exception) {
            e.printStackTrace()
            runOnUiThread {
                statusText.text = "Error: ${e.message}"
            }
        } finally {
            helper.close()
        }
    }

    private fun showBaseUrlChooser() {
        val options = arrayOf(
            "Local (http://localhost:5050)",
            "Azure (https://ipsmern-dep.azurewebsites.net)"
        )

        val current = getIpsBase()
        val checked = when (current) {
            BASE_AZURE -> 1
            else -> 0
        }

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("API base URL")
            .setSingleChoiceItems(options, checked) { dialog, which ->
                val chosen = if (which == 1) BASE_AZURE else BASE_LOCAL
                setIpsBase(chosen)

                statusText.text = "API base set to: $chosen"
                dialog.dismiss()

                // Immediately refresh list + auto-fetch first record (your existing flow)
                refreshIpsList()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }


    private fun fetchAndShowSplit(packageUUID: String) {
        runOnUiThread {
            statusText.text = "Fetching IPS split for $packageUUID..."
            pendingAction = PendingAction.NONE
        }

        val url = ipsSplitUrlBase() + packageUUID

        val req = okhttp3.Request.Builder()
            .url(url)
            .get()
            .build()

        httpClient.newCall(req).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: java.io.IOException) {
                runOnUiThread {
                    statusText.text = "Fetch failed: ${e.message}"
                }
            }

            override fun onResponse(call: okhttp3.Call, resp: okhttp3.Response) {
                resp.use {
                    if (!it.isSuccessful) {
                        runOnUiThread {
                            statusText.text = "Fetch failed: HTTP ${it.code}"
                        }
                        return
                    }

                    val body = it.body?.string().orEmpty()
                    try {
                        val split = gson.fromJson(body, SplitResponse::class.java)

                        val roPretty = gson.toJson(split.ro)
                        val rwPretty = gson.toJson(split.rw)

                        runOnUiThread {
                            textHistoric.setText(roPretty)
                            textRw.setText(rwPretty)
                            statusText.text = "Loaded IPS for $packageUUID"
                        }
                    } catch (ex: Exception) {
                        runOnUiThread {
                            statusText.text = "Parse failed: ${ex.message}"
                        }
                    }
                }
            }
        })
    }


    private fun refreshIpsList() {
        statusText.text = "Loading IPS list…"

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    val req = Request.Builder().url(ipsListUrl()).build()
                    http.newCall(req).execute().use { resp ->
                        if (!resp.isSuccessful) {
                            return@withContext Result.failure(Exception("HTTP ${resp.code}"))
                        }
                        val body = resp.body?.string() ?: "[]"
                        val arr = JSONArray(body)

                        val items = mutableListOf<IpsListItem>()
                        for (i in 0 until arr.length()) {
                            val o = arr.getJSONObject(i)
                            items.add(
                                IpsListItem(
                                    packageUUID = o.optString("packageUUID", ""),
                                    given = o.optString("given", ""),
                                    name = o.optString("name", "")
                                )
                            )
                        }
                        Result.success(items.toList())
                    }
                } catch (e: Exception) {
                    Result.failure(e)
                }
            }

            runOnUiThread {
                result.fold(
                    onSuccess = { items ->
                        ipsList = items
                        val spinner = findViewById<Spinner>(R.id.spinnerIps)
                        val labels = items.map { it.label() }.ifEmpty { listOf("(no records)") }

                        spinner.adapter = ArrayAdapter(
                            this@MainActivity,
                            android.R.layout.simple_spinner_dropdown_item,
                            labels
                        )

                        // Default selection
                        selectedPackageUuid = items.firstOrNull()?.packageUUID
                        statusText.text = "IPS list loaded (${items.size})"
                    },
                    onFailure = { e ->
                        statusText.text = "Failed to load IPS list: ${e.message}"
                    }
                )
            }
        }
    }


    private fun handleFormatForNato(tag: Tag) {
        // Use whatever is in the Historic box as the seed NPS payload,
        // or fall back to a sensible default if blank.
        val npsSeed =  """{"type":"nps-seed","msg":"Initial NATO NPS"}"""
            .toByteArray()

        val ok = NATOHelper.formatPiccForNatoNdef(
            tag = tag,
            debug = true,
            seedNpsMimeType = "application/x.nps.v1-0",
            seedNpsPayload = npsSeed,
            npsCapacityBytes = 2048,
            extraCapacityBytes = 2048
        )

        runOnUiThread {
            statusText.text = if (ok) "NATO format OK" else "NATO format FAILED"
            pendingAction = PendingAction.NONE
        }
    }


    private fun handleWriteNato(tag: Tag) {
        val helper = NATOHelper.connect(tag, debug = true) ?: run {
            runOnUiThread { statusText.text = "NATO write: connect failed" }
            return
        }

        try {
            val ok = helper.writeNatoPayloads(
                npsMimeType = "application/x.nps.v1-0",
                npsPayload = textHistoric.text.toString().toByteArray(),
                extraMimeType = "application/x.ext.v1-0",
                extraPayload = textRw.text.toString().toByteArray()
            )
            runOnUiThread {
                statusText.text = if (ok) "NATO write OK" else "NATO write FAILED"
                pendingAction = PendingAction.NONE
            }
        } finally {
            helper.close()
        }
    }

    private fun handleReadNato(tag: Tag) {
        val helper = NATOHelper.connect(tag, debug = true) ?: run {
            runOnUiThread { statusText.text = "NATO read: connect failed" }
            return
        }

        try {
            val payload = helper.readNatoPayloads()
            runOnUiThread {
                if (payload == null) {
                    statusText.text = "NATO read FAILED or not NATO layout"
                } else {
                    textHistoric.setText(payload.npsPayload.toString(Charsets.UTF_8))
                    textRw.setText(payload.extraPayload.toString(Charsets.UTF_8))
                    statusText.text = "NATO read OK"
                }
                pendingAction = PendingAction.NONE
            }
        } finally {
            helper.close()
        }
    }


    private fun handleReadDualNdef(tag: Tag) {
        var historicText: String? = null
        var extraText: String? = null
        val errors = mutableListOf<String>()

        // 1) RO / Historic via Android NDEF
        val ndef = Ndef.get(tag)
        if (ndef != null) {
            try {
                ndef.connect()
                val msg = ndef.cachedNdefMessage ?: ndef.ndefMessage
                if (msg != null && msg.records.isNotEmpty()) {
                    val rec = msg.records[0]
                    // Assuming payload is UTF-8 JSON or text
                    historicText = rec.payload.toString(Charsets.UTF_8)
                } else {
                    errors += "No NDEF records on card"
                }
            } catch (e: Exception) {
                errors += "NDEF read failed: ${e.message}"
            } finally {
                try { ndef.close() } catch (_: Exception) {}
            }
        } else {
            errors += "Tag is not exposed as NDEF"
        }

        // 2) RW / extra via DESFire app 0x665544
        val helper = NDEFHelper.connect(tag, debug = true)
        if (helper != null) {
            try {
                val bytes = helper.readExtraPlain()
                if (bytes != null) {
                    // Trim trailing zero padding
                    val trimmed = bytes.dropLastWhile { it == 0.toByte() }.toByteArray()
                    extraText = trimmed.toString(Charsets.UTF_8)
                } else {
                    errors += "DESFire extra read returned null"
                }
            } catch (e: Exception) {
                errors += "DESFire extra read failed: ${e.message}"
            } finally {
                helper.close()
            }
        } else {
            errors += "DESFire connect failed for extra section"
        }

        runOnUiThread {
            historicText?.let { textHistoric.setText(it) }
            extraText?.let { textRw.setText(it) }

            statusText.text = buildString {
                append("READ Dual (NDEF + DESFire): ")
                append(
                    when {
                        historicText != null && extraText != null -> "OK"
                        historicText != null || extraText != null -> "partial"
                        else -> "failed"
                    }
                )
                if (errors.isNotEmpty()) {
                    append("\n")
                    append(errors.joinToString("\n"))
                }
            }
            pendingAction = PendingAction.NONE
        }
    }


    private fun handleFormatForDualNdef(tag: Tag) {
        val ok = NDEFHelper.formatPiccForDualNdef(tag, debug = true)
        runOnUiThread {
            if (ok) {
                statusText.text = "Card formatted & NDEF initialised"
                Toast.makeText(this, "PICC formatted for Dual NDEF", Toast.LENGTH_SHORT).show()
            } else {
                statusText.text = "Format for Dual NDEF failed (see logcat)"
                Toast.makeText(this, "Format Dual NDEF failed", Toast.LENGTH_LONG).show()
            }
            pendingAction = PendingAction.NONE
        }
    }


    private fun handleWriteDualNdef(tag: Tag) {
        val helper = NDEFHelper.connect(tag, debug = true)
        if (helper == null) {
            runOnUiThread {
                statusText.text = "Dual write: IsoDep / DESFire connect failed"
                Toast.makeText(this, "DESFire connection failed", Toast.LENGTH_SHORT).show()
                pendingAction = PendingAction.NONE
            }
            return
        }

        try {
            val npsText = textHistoric.text.toString().ifBlank {
                """{"type":"historic","msg":"NPS default"}"""
            }
            val rwText = textRw.text.toString().ifBlank {
                """{"type":"rw","msg":"Default RW extra data"}"""
            }

            val npsBytes = npsText.toByteArray(Charsets.UTF_8)
            val rwBytes  = rwText.toByteArray(Charsets.UTF_8)

            // If RO part doesn't fit current 000001/E104 capacity, reformat PICC for Dual
            val roFits = helper.canWriteType4NdefRo("application/x.nps.v1-0", npsBytes)
            if (!roFits) {
                val requiredCapacity = helper.requiredType4Capacity("application/x.nps.v1-0", npsBytes)

                // pick a practical capacity (aligned + headroom)
                val newCapacity = helper.chooseNdefCapacity(requiredCapacity)

                helper.close() // must close before reformat (new IsoDep session)

                val formatted = NDEFHelper.formatPiccForDualNdef(
                    tag = tag,
                    debug = true,
                    seedMimeType = "application/x.nps.v1-0",
                    seedPayload = """{"type":"seed","msg":"Dual reformat"}""".toByteArray(),
                    ndefCapacityBytes = newCapacity
                )

                if (!formatted) {
                    runOnUiThread {
                        statusText.text = "Dual write FAILED: could not reformat card for larger RO NDEF"
                        pendingAction = PendingAction.NONE
                    }
                    return
                }

                // reconnect after format
                val helper2 = NDEFHelper.connect(tag, debug = true)
                if (helper2 == null) {
                    runOnUiThread {
                        statusText.text = "Dual write FAILED: reconnect after reformat failed"
                        pendingAction = PendingAction.NONE
                    }
                    return
                }

                try {
                    val ok = helper2.writeDualSectionNdef(
                        roMimeType = "application/x.nps.v1-0",
                        roPayload  = npsBytes,
                        rwMimeType = "application/x.ext.v1-0",
                        rwPayload  = rwBytes
                    )

                    runOnUiThread {
                        statusText.text = if (ok) {
                            "Dual write OK (auto-resized RO NDEF)"
                        } else {
                            "Dual write FAILED"
                        }
                        pendingAction = PendingAction.NONE
                    }
                } finally {
                    helper2.close()
                }
                return
            }

            // Normal path (fits)
            val ok = helper.writeDualSectionNdef(
                roMimeType = "application/x.nps.v1-0",
                roPayload  = npsBytes,
                rwMimeType = "application/x.ext.v1-0",
                rwPayload  = rwBytes
            )

            runOnUiThread {
                statusText.text = if (ok) {
                    "Dual write OK: Type-4 NDEF (RO) + DESFire extra (RW)"
                } else {
                    "Dual write FAILED"
                }
                pendingAction = PendingAction.NONE
            }

        } catch (e: Exception) {
            e.printStackTrace()
            runOnUiThread {
                statusText.text = "Error during Dual write: ${e.message}"
                pendingAction = PendingAction.NONE
            }
        } finally {
            // note: may already be closed earlier in the resize path; safe anyway
            helper.close()
        }
    }




    private fun handleFormat(helper: DesfireHelper) {
        val ok = helper.formatPicc()

        runOnUiThread {
            statusText.text = if (ok) {
                "Card formatted: all DESFire apps & files removed"
            } else {
                "Format failed – see log"
            }
            pendingAction = PendingAction.NONE
        }
    }



    private fun handleWrite(helper: DesfireHelper) {
        // Take whatever is in the text boxes; if empty, use the dummy JSON.
        val histStr = textHistoric.text.toString()
            .ifBlank { dummyHistoricPayload.toString(Charsets.UTF_8) }

        val rwStr = textRw.text.toString()
            .ifBlank { dummyRwPayload.toString(Charsets.UTF_8) }

        val histBytes = histStr.toByteArray(Charsets.UTF_8)
        val rwBytes   = rwStr.toByteArray(Charsets.UTF_8)

        val ok = helper.writeTestPayload(historic = histBytes, rw = rwBytes)

        val versionSummary = helper.getVersionSummary() ?: "Version: (error or not supported)"
        val uid = helper.getUidHex() ?: "UID: (unavailable)"

        runOnUiThread {
            statusText.text = if (ok) {
                "WRITE to card OK\n$versionSummary\nUID: $uid"
            } else {
                "WRITE to card FAILED\n$versionSummary\nUID: $uid"
            }
            // Reflect what we *attempted* to write
            textHistoric.setText(histStr)
            textRw.setText(rwStr)
            pendingAction = PendingAction.NONE
        }
    }



    private fun handleRead(helper: DesfireHelper) {
        val payload = helper.readTestPayload()

        val versionSummary = helper.getVersionSummary() ?: "Version: (error or not supported)"
        val uid = helper.getUidHex() ?: "UID: (unavailable)"

        runOnUiThread {
            if (payload == null) {
                statusText.text = "READ from card FAILED\n$versionSummary\nUID: $uid"
            } else {
                val histStr = payload.historic.toString(Charsets.UTF_8)
                val rwStr   = payload.rw.toString(Charsets.UTF_8)

                textHistoric.setText(histStr)
                textRw.setText(rwStr)
                statusText.text = "READ from card OK\n$versionSummary\nUID: $uid"
            }
            pendingAction = PendingAction.NONE
        }
    }
}

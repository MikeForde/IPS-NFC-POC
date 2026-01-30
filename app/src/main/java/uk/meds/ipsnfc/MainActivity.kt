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
import android.view.View
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
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
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

    private val KEY_POC_AUTO_DECOMPRESS = "poc_auto_decompress_rw"

    private fun getPocAutoDecompress(): Boolean {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        return prefs.getBoolean(KEY_POC_AUTO_DECOMPRESS, true) // default ON
    }

    private fun setPocAutoDecompress(enabled: Boolean) {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().putBoolean(KEY_POC_AUTO_DECOMPRESS, enabled).apply()
    }

    private val KEY_SPLIT_MODE = "ips_split_mode"
    private val SPLIT_MODE_UNIFIED = 0
    private val SPLIT_MODE_POC = 1

    private fun getSplitMode(): Int {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        return prefs.getInt(KEY_SPLIT_MODE, SPLIT_MODE_UNIFIED)
    }

    private fun setSplitMode(mode: Int) {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().putInt(KEY_SPLIT_MODE, mode).apply()
    }

    private fun getIpsBase(): String {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        return prefs.getString(KEY_BASE_URL, BASE_AZURE) ?: BASE_AZURE
    }

    private fun setIpsBase(base: String) {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().putString(KEY_BASE_URL, base).apply()
    }

    private fun ipsListUrl(): String = "${getIpsBase()}/ips/list"

    private val KEY_PROTECT_LEVEL = "ips_protect_level"

    private val PROTECT_NONE = 0
    private val PROTECT_JWE  = 1
    private val PROTECT_OMIT = 2

    private fun getProtectLevel(): Int {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        return prefs.getInt(KEY_PROTECT_LEVEL, PROTECT_NONE)
    }

    private fun ipsSplitUrl(packageUuid: String): String {
        val protect = getProtectLevel()
        val base = getIpsBase()

        return when (getSplitMode()) {
            SPLIT_MODE_POC ->
                "$base/ipsdatasplitpoc/$packageUuid?protect=$protect"
            else ->
                "$base/ipsunifiedsplit/$packageUuid?protect=$protect"
        }
    }

    private fun setProtectLevel(level: Int) {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().putInt(KEY_PROTECT_LEVEL, level).apply()
    }


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
    private lateinit var tabHost: TabHost
    private lateinit var tabRoLabel: TextView
    private lateinit var tabRoSize: TextView
    private lateinit var tabRwLabel: TextView
    private lateinit var tabRwSize: TextView



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
            showSettingsDialog()
        }

        tabHost = findViewById(android.R.id.tabhost)
        tabHost.setup()

        val (roInd, roRefs) = makeTabIndicator("DATA 1 (RO)")
        tabRoLabel = roRefs.first
        tabRoSize  = roRefs.second

        val (rwInd, rwRefs) = makeTabIndicator("DATA 2 (RW)")
        tabRwLabel = rwRefs.first
        tabRwSize  = rwRefs.second

        tabHost.addTab(
            tabHost.newTabSpec("ro")
                .setIndicator(roInd)
                .setContent(R.id.tab_ro)
        )

        tabHost.addTab(
            tabHost.newTabSpec("rw")
                .setIndicator(rwInd)
                .setContent(R.id.tab_rw)
        )

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

        textHistoric.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) { updateTabSizes() }
        })

        textRw.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) { updateTabSizes() }
        })


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

        fun enableInnerScrolling(editText: EditText) {
            editText.setOnTouchListener { v, event ->
                if (v.hasFocus()) {
                    v.parent.requestDisallowInterceptTouchEvent(true)

                    if (event.action == android.view.MotionEvent.ACTION_UP) {
                        v.parent.requestDisallowInterceptTouchEvent(false)
                    }
                }
                false
            }
        }


        findViewById<Button>(R.id.buttonRefreshIps).setOnClickListener {
            refreshIpsList()
        }

        enableInnerScrolling(textHistoric)
        enableInnerScrolling(textRw)
        updateTabSizes()


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

    private fun decodeBase64(s: String): ByteArray {
        return android.util.Base64.decode(s, android.util.Base64.DEFAULT)
    }

    private fun gunzip(bytes: ByteArray): ByteArray {
        java.util.zip.GZIPInputStream(bytes.inputStream()).use { gis ->
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (true) {
                val n = gis.read(buf)
                if (n <= 0) break
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }
    }

    private fun makeTabIndicator(title: String): Pair<View, Pair<TextView, TextView>> {
        val wrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 8, 16, 8)
            setBackgroundResource(R.drawable.tab_indicator_bg)
            isClickable = true
            isFocusable = true
        }

        val t1 = TextView(this).apply {
            text = title
            textSize = 14f
            setSingleLine(true)
        }

        val t2 = TextView(this).apply {
            text = "0 B"
            textSize = 11f
            alpha = 0.8f
            setSingleLine(true)
        }

        wrap.addView(t1)
        wrap.addView(t2)
        return wrap to (t1 to t2)
    }

    private fun formatBytes(n: Int): String {
        if (n < 1024) return "$n B"
        val kb = n / 1024.0
        return String.format("%.1f KB (%d B)", kb, n)
    }

    private fun editTextByteSize(et: EditText): Int {
        // count bytes as actually written to NFC / sent over network (UTF-8)
        return et.text?.toString()?.toByteArray(Charsets.UTF_8)?.size ?: 0
    }

    private fun updateTabSizes() {
        tabRoSize.text = formatBytes(editTextByteSize(textHistoric))
        tabRwSize.text = formatBytes(editTextByteSize(textRw))
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

    private fun showSettingsDialog() {
        val baseOptions = arrayOf(
            "Local (http://localhost:5050)",
            "Azure (https://ipsmern-dep.azurewebsites.net)"
        )
        val protectOptions = arrayOf(
            "0 — No protection",
            "1 — Encrypt identifiers (JWE)",
            "2 — Omit identifiers"
        )

        val splitOptions = arrayOf(
            "Unified split (RO/RW JSON via /ipsunifiedsplit)",
            "POC split (RO plaintext + RW gzipped unified JSON via /ipsdatasplitpoc)"
        )

        var selectedSplit = getSplitMode().coerceIn(0, 1)

        var selectedAutoDecompress = getPocAutoDecompress()


        var selectedBaseIndex = when (getIpsBase()) {
            BASE_AZURE -> 1
            else -> 0
        }
        var selectedProtect = getProtectLevel().coerceIn(0, 2)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 0)
        }

        val baseLabel = TextView(this).apply { text = "API base URL"; textSize = 16f }
        content.addView(baseLabel)

        val baseGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            baseOptions.forEachIndexed { idx, label ->
                addView(RadioButton(this@MainActivity).apply {
                    text = label
                    id = 1000 + idx
                    isChecked = idx == selectedBaseIndex
                })
            }
            setOnCheckedChangeListener { _, checkedId ->
                selectedBaseIndex = checkedId - 1000
            }
        }
        content.addView(baseGroup)

        val spacer = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 24
            )
        }
        content.addView(spacer)

        val protectLabel = TextView(this).apply { text = "Protect level"; textSize = 16f }
        content.addView(protectLabel)

        val protectGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            protectOptions.forEachIndexed { idx, label ->
                addView(RadioButton(this@MainActivity).apply {
                    text = label
                    id = 2000 + idx
                    isChecked = idx == selectedProtect
                })
            }
            setOnCheckedChangeListener { _, checkedId ->
                selectedProtect = checkedId - 2000
            }
        }
        content.addView(protectGroup)

        val spacer2 = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 24
            )
        }
        content.addView(spacer2)

        val splitLabel = TextView(this).apply { text = "Split mode"; textSize = 16f }
        content.addView(splitLabel)

        val splitGroup = RadioGroup(this).apply {
            orientation = RadioGroup.VERTICAL
            splitOptions.forEachIndexed { idx, label ->
                addView(RadioButton(this@MainActivity).apply {
                    text = label
                    id = 3000 + idx
                    isChecked = idx == selectedSplit
                })
            }
            setOnCheckedChangeListener { _, checkedId ->
                selectedSplit = checkedId - 3000
            }
        }
        content.addView(splitGroup)

        val spacer3 = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 24
            )
        }
        content.addView(spacer3)

        val cb = android.widget.CheckBox(this).apply {
            text = "Auto Decompress/Unzip"
            isChecked = selectedAutoDecompress
            setOnCheckedChangeListener { _, checked ->
                selectedAutoDecompress = checked
            }
        }
        content.addView(cb)


        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Settings")
            .setView(content)
            .setPositiveButton("Save") { _, _ ->

                val previousBase = getIpsBase()
                val chosenBase = if (selectedBaseIndex == 1) BASE_AZURE else BASE_LOCAL

                val baseChanged = (chosenBase != previousBase)

                setIpsBase(chosenBase)
                setProtectLevel(selectedProtect)
                setSplitMode(selectedSplit)
                setPocAutoDecompress(selectedAutoDecompress)

                statusText.text =
                    "API: $chosenBase | protect=$selectedProtect | mode=$selectedSplit | unzip=$selectedAutoDecompress"

                if (baseChanged) {
                    // New server → list likely differs
                    refreshIpsList()
                } else {
                    // Same server → just re-fetch current patient with new protect/mode settings
                    selectedPackageUuid?.let { fetchAndShowSplit(it) }
                        ?: run { refreshIpsList() } // fallback if nothing selected yet
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun fetchAndShowSplit(packageUUID: String) {
        runOnUiThread {
            statusText.text = "Fetching IPS split for $packageUUID..."
            pendingAction = PendingAction.NONE
        }

        val url = ipsSplitUrl(packageUUID)

        val req = Request.Builder()
            .url(url)
            .get()
            .build()

        httpClient.newCall(req).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: java.io.IOException) {
                runOnUiThread { statusText.text = "Fetch failed: ${e.message}" }
            }

            override fun onResponse(call: okhttp3.Call, resp: okhttp3.Response) {
                resp.use {
                    if (!it.isSuccessful) {
                        runOnUiThread { statusText.text = "Fetch failed: HTTP ${it.code}" }
                        return
                    }

                    val body = it.body?.string().orEmpty()

                    try {
                        val mode = getSplitMode()
                        val autoDecompress = getPocAutoDecompress() // reuse this toggle for BOTH modes

                        if (mode == SPLIT_MODE_POC) {
                            // POC shape (your existing logic)
                            val root = org.json.JSONObject(body)
                            val roObj = root.optJSONObject("ro")
                            val rwObj = root.optJSONObject("rw")

                            val roText = roObj?.optString("text", "") ?: ""
                            val b64 = rwObj?.optString("bytesBase64", "") ?: ""

                            val rwDisplay = when {
                                b64.isBlank() -> ""
                                !autoDecompress -> b64
                                else -> {
                                    val gz = decodeBase64(b64)
                                    val jsonBytes = gunzip(gz)
                                    val jsonStr = jsonBytes.toString(Charsets.UTF_8)
                                    val parsed = gson.fromJson(jsonStr, Any::class.java)
                                    gson.toJson(parsed)
                                }
                            }

                            runOnUiThread {
                                textHistoric.setText(roText)
                                textRw.setText(rwDisplay)
                                statusText.text =
                                    if (autoDecompress)
                                        "Loaded POC split for $packageUUID (decompressed RW)"
                                    else
                                        "Loaded POC split for $packageUUID (compact RW base64)"
                            }

                        } else {
                            // Unified split: NOW supports gzip+base64 default response
                            val root = org.json.JSONObject(body)
                            val encoding = root.optString("encoding", "json")

                            if (encoding.equals("gzip+base64", ignoreCase = true)) {
                                val roB64 = root.optString("roGzB64", "")
                                val rwB64 = root.optString("rwGzB64", "")

                                val roBytesJson = root.optInt("roBytesJson", -1)
                                val rwBytesJson = root.optInt("rwBytesJson", -1)
                                val roBytesGz   = root.optInt("roBytesGz", -1)
                                val rwBytesGz   = root.optInt("rwBytesGz", -1)

                                val roDisplay = when {
                                    roB64.isBlank() -> ""
                                    !autoDecompress -> roB64
                                    else -> {
                                        val gz = decodeBase64(roB64)
                                        val jsonBytes = gunzip(gz)
                                        val jsonStr = jsonBytes.toString(Charsets.UTF_8)
                                        val parsed = gson.fromJson(jsonStr, Any::class.java)
                                        gson.toJson(parsed)
                                    }
                                }

                                val rwDisplay = when {
                                    rwB64.isBlank() -> ""
                                    !autoDecompress -> rwB64
                                    else -> {
                                        val gz = decodeBase64(rwB64)
                                        val jsonBytes = gunzip(gz)
                                        val jsonStr = jsonBytes.toString(Charsets.UTF_8)
                                        val parsed = gson.fromJson(jsonStr, Any::class.java)
                                        gson.toJson(parsed)
                                    }
                                }

                                runOnUiThread {
                                    textHistoric.setText(roDisplay)
                                    textRw.setText(rwDisplay)

                                    statusText.text =
                                        if (autoDecompress) {
                                            "Loaded unified split for $packageUUID (decompressed) " +
                                                    "RO: $roBytesGz→$roBytesJson bytes, RW: $rwBytesGz→$rwBytesJson bytes"
                                        } else {
                                            "Loaded unified split for $packageUUID (compact base64) " +
                                                    "RO gz=$roBytesGz, RW gz=$rwBytesGz"
                                        }
                                }

                            } else {
                                // Old JSON shape: { ro: {...}, rw: {...}, ... }
                                val split = gson.fromJson(body, SplitResponse::class.java)
                                val roPretty = gson.toJson(split.ro)
                                val rwPretty = gson.toJson(split.rw)

                                runOnUiThread {
                                    textHistoric.setText(roPretty)
                                    textRw.setText(rwPretty)
                                    statusText.text = "Loaded unified split for $packageUUID"
                                }
                            }
                        }

                    } catch (ex: Exception) {
                        runOnUiThread { statusText.text = "Parse failed: ${ex.message}" }
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

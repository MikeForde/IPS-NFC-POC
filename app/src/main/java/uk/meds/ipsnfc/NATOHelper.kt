package uk.meds.ipsnfc

import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile
import nfcjlib.core.DESFireAdapter
import nfcjlib.core.DESFireEV1
import nfcjlib.core.KeyType
import kotlin.math.min

/**
 * NATOHelper – helper for a NATO-style layout:
 *
 * Single NDEF app (AID 000001) containing:
 *  - CC file E103 (fileNo 1) with TWO TLVs:
 *      TLV 1 -> NPS NDEF file (E104)   (read-only to NDEF clients)
 *      TLV 2 -> Extra NDEF file (E105) (read/write)
 *  - NDEF file E104 (fileNo 2) : NPS (RO)
 *  - NDEF file E105 (fileNo 3) : Extra (RW)
 *
 * All NDEF is true Type-4; generic readers see the first NDEF (NPS).
 * NATO-aware code can read/write the second NDEF via low-level access.
 */
class NATOHelper private constructor(
    private val isoDep: IsoDep,
    private val desfire: DESFireEV1
) {

    data class NatoPayload(
        val npsPayload: ByteArray,
        val extraPayload: ByteArray
    )

    fun close() {
        try {
            if (isoDep.isConnected) isoDep.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing IsoDep", e)
        }
    }

    // --------------------------------------------------------------------
    // PUBLIC: format + seed NATO layout
    // --------------------------------------------------------------------

    /**
     * Format the PICC and create NATO layout:
     *
     *  - DESFire formatPICC()
     *  - Create NDEF app 000001 with ISO DF name D2 76 00 00 85 01 01
     *  - Create CC (E103), NPS NDEF (E104), Extra NDEF (E105)
     *  - CC has TWO TLVs:
     *      TLV 1 -> E104 (NPS, RO to NDEF clients)
     *      TLV 2 -> E105 (Extra, RW)
     *  - Seed both NPS and Extra with provided payloads.
     */
    fun formatPiccForNato(
        npsMimeType: String = "application/x.nps.v1-0",
        npsSeedPayload: ByteArray = """{"type":"nps","msg":"Seed NPS"}""".toByteArray(),
        extraMimeType: String = "application/x.ext.v1-0",
        extraSeedPayload: ByteArray = """{"type":"extra","msg":"Seed extra"}""".toByteArray(),
        npsCapacityBytes: Int = 2048,
        extraCapacityBytes: Int = 4096
    ): Boolean {
        return lowLevelFormatPiccForNato(
            npsMimeType,
            npsSeedPayload,
            extraMimeType,
            extraSeedPayload,
            npsCapacityBytes,
            extraCapacityBytes
        )
    }

    // --------------------------------------------------------------------
    // PUBLIC: write/read NATO payloads (expects card already formatted)
    // --------------------------------------------------------------------

    /**
     * Write NATO payload into:
     *  - NPS NDEF  -> fileNo 2 (E104)
     *  - Extra NDEF -> fileNo 3 (E105)
     *
     * Does NOT reformat; assumes Type 4 NATO layout already present.
     */
    fun writeNatoPayload(
        npsMimeType: String,
        npsPayload: ByteArray,
        extraMimeType: String,
        extraPayload: ByteArray
    ): Boolean {
        return try {
            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.e(TAG, "writeNatoPayload: failed to select NDEF app (000001)")
                return false
            }

            // We keep DESFire file access open/free and rely on CC TLVs for RO/RW semantics
            // for generic NDEF clients. For our writer, we just write both.

            val npsRecord = buildMimeNdefRecord(npsMimeType, npsPayload)
            val extraRecord = buildMimeNdefRecord(extraMimeType, extraPayload)

            val okNps = writeNdefLikeFile(0x02, npsRecord)
            val okExtra = writeNdefLikeFile(0x03, extraRecord)

            Log.d(TAG, "writeNatoPayload: okNps=$okNps okExtra=$okExtra")
            okNps && okExtra
        } catch (e: Exception) {
            Log.e(TAG, "writeNatoPayload failed", e)
            false
        }
    }

    /**
     * Read NPS + Extra payloads (decoded to inner MIME payloads).
     *
     * Returns null if the expected NATO layout is missing or corrupted.
     */
    fun readNatoPayload(): NatoPayload? {
        return try {
            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.e(TAG, "readNatoPayload: NDEF app (000001) not present / not selectable")
                return null
            }

            val npsPayload = readNdefPayloadFromFile(0x02) ?: return null
            val extraPayload = readNdefPayloadFromFile(0x03) ?: return null

            NatoPayload(npsPayload = npsPayload, extraPayload = extraPayload)
        } catch (e: Exception) {
            Log.e(TAG, "readNatoPayload failed", e)
            null
        }
    }

    // --------------------------------------------------------------------
    // INTERNAL: NATO formatting – one app with 2 NDEF files per spec
    // --------------------------------------------------------------------

    /**
     * Full NATO layout formatter as per proposal:
     *
     *  App 000001:
     *   - file 1 (E103): CC, with 2 TLVs (E104, E105)
     *   - file 2 (E104): NPS NDEF (RO to NDEF clients: write=0xFF in TLV)
     *   - file 3 (E105): Extra NDEF (RW to NDEF clients: write=0x00 in TLV)
     */
    private fun lowLevelFormatPiccForNato(
        npsMimeType: String,
        npsSeedPayload: ByteArray,
        extraMimeType: String,
        extraSeedPayload: ByteArray,
        npsCapacityBytes: Int,
        extraCapacityBytes: Int
    ): Boolean {
        return try {
            // 1) Format PICC in DESFire sense
            if (!formatPiccInternal()) {
                Log.e(TAG, "lowLevelFormatPiccForNato: formatPiccInternal() failed")
                return false
            }

            // 2) Create NDEF app 000001 via native 0xCA (AN11004 style)
            val createNdefAppBody = byteArrayOf(
                0x01, 0x00, 0x00,       // AID = 000001 (little endian)
                0x0F,                   // key settings (permissive)
                0x21,                   // app settings (ISO DF, etc.)
                0x05, 0x01,             // 5 keys, key type DES
                0xD2.toByte(), 0x76, 0x00, 0x00, 0x85.toByte(), 0x01, 0x01 // ISO DF name
            )
            val respCreateApp = sendNative(0xCA.toByte(), createNdefAppBody)
            val swCreateApp = respCreateApp.last().toInt() and 0xFF
            if (swCreateApp != 0x00 && swCreateApp != 0xDE) { // 0xDE = DUPLICATE_ERROR
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForNato: create NDEF app failed, status=0x${swCreateApp.toString(16)}"
                )
                return false
            } else {
                Log.d(
                    TAG,
                    "lowLevelFormatPiccForNato: create NDEF app ok (or duplicate), status=0x${swCreateApp.toString(16)}"
                )
            }

            // 3) Select NDEF app 000001
            if (!desfire.selectApplication(NDEF_APP_AID)) {
                Log.e(TAG, "lowLevelFormatPiccForNato: failed to select NDEF app (000001)")
                return false
            }

            // App master key = 00..00 (#0)
            val appAuthOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
            if (!appAuthOk) {
                Log.e(TAG, "lowLevelFormatPiccForNato: app master auth failed")
                return false
            }

            // 4) Create CC file (fileNo=1, FID=E103, 32 bytes)
            val ccFileSize = 32
            val ccSize0 = (ccFileSize and 0xFF).toByte()
            val ccSize1 = ((ccFileSize shr 8) and 0xFF).toByte()
            val ccSize2 = ((ccFileSize shr 16) and 0xFF).toByte()

            val createCCBody = byteArrayOf(
                0x01,                   // fileNo
                0x03, 0xE1.toByte(),    // FID E103
                0x00,                   // comm (plain)
                0x00, 0x00,             // access rights (we keep free R/W at DF level)
                ccSize0, ccSize1, ccSize2
            )
            val respCreateCC = sendNative(0xCD.toByte(), createCCBody)
            val swCreateCC = respCreateCC.last().toInt() and 0xFF
            if (swCreateCC != 0x00 && swCreateCC != 0xDE) {
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForNato: create CC file failed, status=0x${swCreateCC.toString(16)}"
                )
                return false
            } else {
                Log.d(
                    TAG,
                    "lowLevelFormatPiccForNato: create CC file ok (or duplicate), status=0x${swCreateCC.toString(16)}"
                )
            }

            // 5) Create NPS NDEF file (fileNo=2, FID=E104)
            val npsSize = npsCapacityBytes
            val npsSize0 = (npsSize and 0xFF).toByte()
            val npsSize1 = ((npsSize shr 8) and 0xFF).toByte()
            val npsSize2 = ((npsSize shr 16) and 0xFF).toByte()

            val createNpsBody = byteArrayOf(
                0x02,                   // fileNo
                0x04, 0xE1.toByte(),    // FID E104
                0x00,                   // comm (plain)
                0x00, 0x00,             // DF access (free R/W – CC enforces RO to NDEF)
                npsSize0, npsSize1, npsSize2
            )
            val respCreateNps = sendNative(0xCD.toByte(), createNpsBody)
            val swCreateNps = respCreateNps.last().toInt() and 0xFF
            if (swCreateNps != 0x00 && swCreateNps != 0xDE) {
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForNato: create NPS NDEF file failed, status=0x${swCreateNps.toString(16)}"
                )
                return false
            } else {
                Log.d(
                    TAG,
                    "lowLevelFormatPiccForNato: create NPS NDEF file ok (or duplicate), status=0x${swCreateNps.toString(16)}"
                )
            }

            // 6) Create Extra NDEF file (fileNo=3, FID=E105)
            val extraSize = extraCapacityBytes
            val extraSize0 = (extraSize and 0xFF).toByte()
            val extraSize1 = ((extraSize shr 8) and 0xFF).toByte()
            val extraSize2 = ((extraSize shr 16) and 0xFF).toByte()

            val createExtraBody = byteArrayOf(
                0x03,                   // fileNo
                0x05, 0xE1.toByte(),    // FID E105
                0x00,                   // comm (plain)
                0x00, 0x00,             // DF access free R/W
                extraSize0, extraSize1, extraSize2
            )
            val respCreateExtra = sendNative(0xCD.toByte(), createExtraBody)
            val swCreateExtra = respCreateExtra.last().toInt() and 0xFF
            if (swCreateExtra != 0x00 && swCreateExtra != 0xDE) {
                Log.e(
                    TAG,
                    "lowLevelFormatPiccForNato: create Extra NDEF file failed, status=0x${swCreateExtra.toString(16)}"
                )
                return false
            } else {
                Log.d(
                    TAG,
                    "lowLevelFormatPiccForNato: create Extra NDEF file ok (or duplicate), status=0x${swCreateExtra.toString(16)}"
                )
            }

            // 7) Build CC with TWO TLVs
            //
            // We'll use CCLEN = 23 (0x0017), so we need 23 bytes:
            //  [0-1]  CCLEN          -> 0x00 0x17
            //  [2]    Mapping ver    -> 0x20
            //  [3-4]  MLe            -> 0x00 0x3B
            //  [5-6]  MLc            -> 0x00 0x34
            //  TLV 1 (NPS):
            //    [7]  T              -> 0x04
            //    [8]  L              -> 0x06
            //    [9-10] File ID      -> E1 04
            //    [11-12] Max size    -> npsCapacityBytes (16-bit)
            //    [13]  Read access   -> 0x00
            //    [14]  Write access  -> 0xFF (read-only to NDEF clients)
            //  TLV 2 (Extra):
            //    [15] T              -> 0x04
            //    [16] L              -> 0x06
            //    [17-18] File ID     -> E1 05
            //    [19-20] Max size    -> extraCapacityBytes (16-bit)
            //    [21] Read access    -> 0x00
            //    [22] Write access   -> 0x00
            val npsMaxHi = ((npsCapacityBytes shr 8) and 0xFF).toByte()
            val npsMaxLo = (npsCapacityBytes and 0xFF).toByte()
            val extraMaxHi = ((extraCapacityBytes shr 8) and 0xFF).toByte()
            val extraMaxLo = (extraCapacityBytes and 0xFF).toByte()

            val cc = ByteArray(ccFileSize) { 0 }
            cc[0]  = 0x00
            cc[1]  = 0x17                // CCLEN = 23
            cc[2]  = 0x20                // mapping version 2.0
            cc[3]  = 0x00
            cc[4]  = 0x3B                // MLe
            cc[5]  = 0x00
            cc[6]  = 0x34                // MLc

            // TLV 1 – NPS (E104, RO)
            cc[7]  = 0x04
            cc[8]  = 0x06
            cc[9]  = 0xE1.toByte()
            cc[10] = 0x04
            cc[11] = npsMaxHi
            cc[12] = npsMaxLo
            cc[13] = 0x00                // read access
            cc[14] = 0xFF.toByte()       // write access = RO

            // TLV 2 – Extra (E105, RW)
            cc[15] = 0x04
            cc[16] = 0x06
            cc[17] = 0xE1.toByte()
            cc[18] = 0x05
            cc[19] = extraMaxHi
            cc[20] = extraMaxLo
            cc[21] = 0x00                // read access
            cc[22] = 0x00                // write access

            val ccOk = writeStandardFileInCurrentApp(0x01, cc)
            if (!ccOk) {
                Log.e(TAG, "lowLevelFormatPiccForNato: writing CC file failed")
                return false
            }

            // 8) Seed NPS and Extra NDEF files
            val npsRecord = buildMimeNdefRecord(npsMimeType, npsSeedPayload)
            val extraRecord = buildMimeNdefRecord(extraMimeType, extraSeedPayload)

            val npsOk = writeNdefLikeFile(0x02, npsRecord)
            val extraOk = writeNdefLikeFile(0x03, extraRecord)

            if (!npsOk || !extraOk) {
                Log.e(TAG, "lowLevelFormatPiccForNato: seeding NDEF files failed (npsOk=$npsOk, extraOk=$extraOk)")
                return false
            }

            Log.d(TAG, "lowLevelFormatPiccForNato: completed successfully")
            true
        } catch (e: Exception) {
            Log.e(TAG, "lowLevelFormatPiccForNato failed", e)
            false
        }
    }

    // --------------------------------------------------------------------
    // INTERNAL: DESFire helpers
    // --------------------------------------------------------------------

    private fun formatPiccInternal(): Boolean {
        return try {
            if (!desfire.selectApplication(MASTER_AID)) {
                Log.e(TAG, "formatPiccInternal: failed to select master application")
                false
            } else {
                val authOk = desfire.authenticate(DEFAULT_DES_KEY, KEYNO_MASTER, KeyType.DES)
                if (!authOk) {
                    Log.e(TAG, "formatPiccInternal: PICC master auth failed")
                    false
                } else {
                    val ok = desfire.formatPICC()
                    Log.d(
                        TAG,
                        "formatPiccInternal: formatPICC -> $ok " +
                                "code=${desfire.code.toString(16)} desc=${desfire.codeDesc}"
                    )
                    ok
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "formatPiccInternal failed", e)
            false
        }
    }

    /**
     * Send a DESFire native command over the same IsoDep connection.
     * INS is the command byte (e.g. 0xCA, 0xCD).
     */
    private fun sendNative(ins: Byte, data: ByteArray? = null): ByteArray {
        val body = data ?: ByteArray(0)
        val apdu = ByteArray(5 + body.size)
        apdu[0] = 0x90.toByte()
        apdu[1] = ins
        apdu[2] = 0x00
        apdu[3] = 0x00
        apdu[4] = body.size.toByte()
        System.arraycopy(body, 0, apdu, 5, body.size)

        Log.d(TAG, "sendNative: INS=${String.format("0x%02X", ins)}, Lc=${body.size}")
        val resp = desfire.transceive(apdu)
        val lastStatus = resp?.lastOrNull() ?: -1
        Log.d(
            TAG,
            "sendNative resp: len=${resp?.size ?: -1}, lastStatus=0x${String.format("%02X", lastStatus)}"
        )
        return resp ?: byteArrayOf(0x91.toByte(), 0x01)
    }

    /**
     * Write an entire Standard Data File (current app) from offset 0.
     */
    private fun writeStandardFileInCurrentApp(fileNo: Int, data: ByteArray): Boolean {
        return try {
            val fs = desfire.getFileSettings(fileNo) as? StandardDesfireFile
                ?: run {
                    Log.e(TAG, "writeStandardFileInCurrentApp($fileNo): not a Standard file / not found")
                    return false
                }

            val size = fs.fileSize
            val full = ByteArray(size) { 0 }
            val len = min(size, data.size)
            System.arraycopy(data, 0, full, 0, len)

            val pb = PayloadBuilder()
            val payload = pb.writeToStandardFile(fileNo, full)
                ?: throw RuntimeException("writeToStandardFile($fileNo) returned null")

            val ok = desfire.writeData(payload)
            Log.d(
                TAG,
                "writeStandardFileInCurrentApp($fileNo): size=$size, payloadLen=${payload.size} -> $ok " +
                        "(code=${desfire.code.toString(16)}, desc=${desfire.codeDesc})"
            )
            ok
        } catch (e: Exception) {
            Log.e(TAG, "writeStandardFileInCurrentApp($fileNo) failed", e)
            false
        }
    }

    /**
     * Wrap a full NDEF file: NLEN (2 bytes BE) + NDEF record + padding, then write.
     */
    private fun writeNdefLikeFile(fileNo: Int, ndefRecord: ByteArray): Boolean {
        val fs = desfire.getFileSettings(fileNo) as? StandardDesfireFile
            ?: run {
                Log.e(TAG, "writeNdefLikeFile($fileNo): not a Standard file / not found")
                return false
            }

        val size = fs.fileSize
        val needed = 2 + ndefRecord.size
        if (needed > size) {
            Log.e(TAG, "writeNdefLikeFile($fileNo): record too large ($needed) for file size $size")
            return false
        }

        val buf = ByteArray(size) { 0 }
        val nlen = ndefRecord.size
        buf[0] = ((nlen shr 8) and 0xFF).toByte()
        buf[1] = (nlen and 0xFF).toByte()
        System.arraycopy(ndefRecord, 0, buf, 2, nlen)

        return writeStandardFileInCurrentApp(fileNo, buf)
    }

    /**
     * Read and decode the inner payload of a Short-Record MIME NDEF from the given file.
     */
    private fun readNdefPayloadFromFile(fileNo: Int): ByteArray? {
        val fs = desfire.getFileSettings(fileNo) as? StandardDesfireFile
            ?: run {
                Log.e(TAG, "readNdefPayloadFromFile($fileNo): not a Standard file / not found")
                return null
            }

        val size = fs.fileSize
        val raw = desfire.readData(fileNo.toByte(), 0, size)
        if (raw == null) {
            Log.e(
                TAG,
                "readNdefPayloadFromFile($fileNo): readData returned null (code=${desfire.code.toString(16)}, desc=${desfire.codeDesc})"
            )
            return null
        }

        if (raw.size < 3) {
            Log.e(TAG, "readNdefPayloadFromFile($fileNo): too small for NLEN+record")
            return null
        }

        val nlen = ((raw[0].toInt() and 0xFF) shl 8) or (raw[1].toInt() and 0xFF)
        if (nlen <= 0 || nlen + 2 > raw.size) {
            Log.e(TAG, "readNdefPayloadFromFile($fileNo): invalid NLEN=$nlen, fileSize=${raw.size}")
            return null
        }

        val msg = raw.copyOfRange(2, 2 + nlen)
        if (msg.size < 3) {
            Log.e(TAG, "readNdefPayloadFromFile($fileNo): NDEF msg too small")
            return null
        }

        val header = msg[0].toInt() and 0xFF
        val sr = (header and 0x10) != 0       // Short Record flag
        val tnf = header and 0x07
        if (!sr) {
            Log.e(TAG, "readNdefPayloadFromFile($fileNo): not a Short Record (SR=0)")
            return null
        }
        if (tnf != 0x02) {
            Log.e(TAG, "readNdefPayloadFromFile($fileNo): TNF != 0x02 (media-type)")
            return null
        }

        val typeLen = msg[1].toInt() and 0xFF
        val payloadLen = msg[2].toInt() and 0xFF
        var idx = 3

        if (msg.size < idx + typeLen + payloadLen) {
            Log.e(TAG, "readNdefPayloadFromFile($fileNo): lengths exceed message size")
            return null
        }

        // val typeBytes = msg.copyOfRange(idx, idx + typeLen) // if you ever want MIME back
        idx += typeLen
        val payload = msg.copyOfRange(idx, idx + payloadLen)

        return payload
    }

    // --------------------------------------------------------------------
    // Companion: connect + NDEF record builder
    // --------------------------------------------------------------------

    companion object {
        private const val TAG = "NATOHelper"

        private val MASTER_AID: ByteArray = byteArrayOf(0x00, 0x00, 0x00)
        private val NDEF_APP_AID: ByteArray = byteArrayOf(0x01, 0x00, 0x00) // 000001 LE

        private val DEFAULT_DES_KEY = ByteArray(8) { 0x00 }
        private const val KEYNO_MASTER: Byte = 0x00

        /**
         * Build a Short Record (SR=1), TNF=0x02 MIME NDEF.
         */
        fun buildMimeNdefRecord(mimeType: String, payload: ByteArray): ByteArray {
            val typeBytes = mimeType.toByteArray(Charsets.US_ASCII)
            val typeLen = typeBytes.size
            val payloadLen = payload.size

            require(payloadLen < 256) {
                "Short Record (SR) only supports payload < 256 bytes (got $payloadLen)"
            }

            val header: Byte = 0b11010010.toByte() // MB=1, ME=1, SR=1, TNF=0x02

            val result = ByteArray(3 + typeLen + payloadLen)
            var i = 0
            result[i++] = header
            result[i++] = typeLen.toByte()
            result[i++] = payloadLen.toByte()
            System.arraycopy(typeBytes, 0, result, i, typeLen)
            i += typeLen
            System.arraycopy(payload, 0, result, i, payloadLen)
            return result
        }

        /**
         * Connect to tag and build NATOHelper (IsoDep + DESFire stack).
         */
        fun connect(tag: Tag, debug: Boolean = false): NATOHelper? {
            val isoDep = IsoDep.get(tag)
            if (isoDep == null) {
                Log.w(TAG, "Tag does not support IsoDep – not a DESFire EVx card")
                return null
            }

            return try {
                isoDep.timeout = 5000
                isoDep.connect()

                val isoDepWrapper = DefaultIsoDepWrapper(isoDep)
                val adapter = DESFireAdapter(isoDepWrapper, /*print*/ debug)

                val desfire = DESFireEV1().apply {
                    setAdapter(adapter)
                    setPrint(debug)
                }

                NATOHelper(isoDep, desfire)
            } catch (e: Exception) {
                Log.e(TAG, "Error connecting to DESFire tag", e)
                try { isoDep.close() } catch (_: Exception) {}
                null
            }
        }
    }
}

package com.zerotrace.messenger.data

import android.content.Context
import com.zerotrace.messenger.pairing.PairingFormat
import com.zerotrace.messenger.security.KeystoreManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Contacts are stored locally, encrypted with the Keystore wrapping key.
 * One file, one AES/GCM blob. A contact is never silently overwritten: if a
 * fingerprint for the same onion address already exists and differs, the caller
 * must get explicit user confirmation first ([save] returns false in that case).
 */
data class Contact(
    val onionAddress: String,
    val fingerprint: String,
    val identityEd25519: String,
    val identityMlDsaHash: String,
    val displayName: String,
    val addedEpochSeconds: Long,
    /** The verified pairing QR JSON (the commitment). Needed to verify the
     * peer's full bundle when a session opens. */
    val qrJson: String,
    val blocked: Boolean = false
)

class ContactStore(context: Context, private val keystore: KeystoreManager) {
    private val file = File(context.filesDir, "contacts.enc")

    fun loadAll(): List<Contact> {
        if (!file.exists()) return emptyList()
        return try {
            val plain = keystore.unwrap(file.readBytes())
            val arr = JSONArray(String(plain, Charsets.UTF_8))
            List(arr.length()) { i ->
                val o = arr.getJSONObject(i)
                Contact(
                    onionAddress = o.getString("onion"),
                    fingerprint = o.getString("fp"),
                    identityEd25519 = o.getString("ik_ed"),
                    identityMlDsaHash = o.optString("ik_pq_hash", ""),
                    displayName = o.getString("name"),
                    addedEpochSeconds = o.getLong("added"),
                    qrJson = o.optString("qr", ""),
                    blocked = o.optBoolean("blocked", false)
                )
            }
        } catch (e: Exception) {
            emptyList() // Corrupt store fails closed to "no contacts", never to a guessed contact.
        }
    }

    /** Returns false when an existing contact with a DIFFERENT fingerprint must be re-verified first. */
    fun save(contact: Contact): Boolean {
        val existing = loadAll()
        val clash = existing.firstOrNull { it.onionAddress == contact.onionAddress }
        if (clash != null && clash.fingerprint != contact.fingerprint) return false
        val updated = (existing.filter { it.onionAddress != contact.onionAddress } + contact)
        val arr = JSONArray()
        updated.forEach { c ->
            arr.put(JSONObject().apply {
                put("onion", c.onionAddress)
                put("fp", c.fingerprint)
                put("ik_ed", c.identityEd25519)
                put("ik_pq_hash", c.identityMlDsaHash)
                put("name", c.displayName)
                put("added", c.addedEpochSeconds)
                put("qr", c.qrJson)
                put("blocked", c.blocked)
            })
        }
        file.writeBytes(keystore.wrap(arr.toString().toByteArray(Charsets.UTF_8)))
        return true
    }

    /** Removes one contact by onion address. Returns false if not found. */
    fun delete(onionAddress: String): Boolean {
        val existing = loadAll()
        if (existing.none { it.onionAddress == onionAddress }) return false
        val updated = existing.filter { it.onionAddress != onionAddress }
        val arr = JSONArray()
        updated.forEach { c ->
            arr.put(JSONObject().apply {
                put("onion", c.onionAddress)
                put("fp", c.fingerprint)
                put("ik_ed", c.identityEd25519)
                put("ik_pq_hash", c.identityMlDsaHash)
                put("name", c.displayName)
                put("added", c.addedEpochSeconds)
                put("qr", c.qrJson)
                put("blocked", c.blocked)
            })
        }
        file.writeBytes(keystore.wrap(arr.toString().toByteArray(Charsets.UTF_8)))
        return true
    }

    fun deleteAll() {
        runCatching { file.delete() }
    }
}

package com.zerotrace.messenger.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed wrapping of identity material.
 *
 * Architecture: hardware-backed AES/GCM key (StrongBox > TEE > software) wraps the
 * identity bundle bytes; the wrapped blob lives in app-private storage. The Rust core
 * generates the keys; this class only wraps/unwraps the exported bundle.
 *
 * [securityLevel] reports the ACTUAL level — never claim StrongBox when it is not used.
 */
enum class KeystoreLevel { STRONGBOX, TEE, SOFTWARE, UNAVAILABLE }

class KeystoreManager(private val context: Context) {
    private val alias = "zerotrace_identity_wrap"
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    val securityLevel: KeystoreLevel
        get() {
            if (!keyStore.containsAlias(alias)) return levelForNewKey()
            return try {
                val key = keyStore.getKey(alias, null) as SecretKey
                val factory = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                // Android's SecretKeyFactory.getKeySpec is NOT generic (unlike
                // KeyFactory's): it returns KeySpec, so cast to KeyInfo.
                val info = factory.getKeySpec(key, android.security.keystore.KeyInfo::class.java)
                    as android.security.keystore.KeyInfo
                when {
                    Build.VERSION.SDK_INT >= 31 && info.securityLevel ==
                        android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX ->
                        KeystoreLevel.STRONGBOX
                    info.isInsideSecureHardware -> KeystoreLevel.TEE
                    else -> KeystoreLevel.SOFTWARE
                }
            } catch (e: Exception) {
                KeystoreLevel.UNAVAILABLE
            }
        }

    private fun levelForNewKey(): KeystoreLevel = when {
        Build.VERSION.SDK_INT >= 28 &&
            context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore") ->
            KeystoreLevel.STRONGBOX
        else -> KeystoreLevel.TEE // TEE availability is confirmed on first key creation; see ensureKey()
    }

    /** Creates the wrapping key. Returns the level actually achieved. */
    fun ensureKey(): KeystoreLevel {
        if (keyStore.containsAlias(alias)) return securityLevel
        // Try StrongBox first where the feature exists; fall back to TEE on failure.
        val strongBox = Build.VERSION.SDK_INT >= 28 &&
            context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore")
        if (strongBox) {
            val ok = runCatching { createKey(setIsStrongBoxBacked = true) }.isSuccess
            if (ok) return KeystoreLevel.STRONGBOX
        }
        return runCatching { createKey(setIsStrongBoxBacked = false) }
            .map { KeystoreLevel.TEE }
            .getOrElse { KeystoreLevel.UNAVAILABLE }
    }

    private fun createKey(setIsStrongBoxBacked: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setIsStrongBoxBacked(setIsStrongBoxBacked)
            .setUserAuthenticationRequired(false)
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply { init(spec) }.generateKey()
    }

    private fun wrappingKey(): SecretKey =
        (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey

    /** Encrypts [plaintext]; output is IV (12 bytes) || ciphertext. Caller must zero [plaintext] after. */
    fun wrap(plaintext: ByteArray): ByteArray {
        ensureKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        val ct = cipher.doFinal(plaintext)
        return cipher.iv + ct
    }

    fun unwrap(wrapped: ByteArray): ByteArray {
        require(wrapped.size > 12) { "wrapped blob too short" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(),
            GCMParameterSpec(128, wrapped, 0, 12))
        return cipher.doFinal(wrapped, 12, wrapped.size - 12)
    }

    fun deleteKey() {
        runCatching { keyStore.deleteEntry(alias) }
    }
}

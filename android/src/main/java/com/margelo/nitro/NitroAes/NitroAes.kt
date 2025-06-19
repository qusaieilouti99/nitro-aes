package com.margelo.nitro.NitroAes

import android.util.Base64
import com.margelo.nitro.core.Promise
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Implementation of the Nitro AES module with PBKDF2 and HMAC-key support.
 */
class NitroAes : HybridAesNitroSpec() {
  companion object {
    init { NitroAesOnLoad.initializeNative() }
    private const val KEY_ALGORITHM = "AES"
    private const val TEXT_CIPHER = "AES/CBC/PKCS7Padding"
    private const val FILE_CIPHER = "AES/CBC/NoPadding"
    private const val HMAC_SHA256 = "HmacSHA256"
    private const val BLOCK_SIZE = 16
    private const val CHUNK_SIZE = BLOCK_SIZE * 4 * 1024
  }

  override fun pbkdf2(
    password: String,
    salt: String,
    cost: Double,
    length: Double
  ): Promise<String> = Promise { resolve, reject ->
    try {
      // PBKDF2 with HmacSHA512 (length in bits)
      val spec = PBEKeySpec(
        password.toCharArray(),
        salt.toByteArray(StandardCharsets.UTF_8),
        cost.toInt(),
        (length * 8).toInt()
      )
      val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
      val keyBytes = factory.generateSecret(spec).encoded
      resolve(bytesToHex(keyBytes))
    } catch (e: Exception) {
      reject(e)
    }
  }

  override fun encrypt(text: String, key: String, iv: String, algorithm: Algorithms): Promise<String> = Promise { resolve, reject ->
    try { resolve(encryptText(text, key, iv)) } catch (e: Throwable) { reject(e) }
  }

  override fun decrypt(ciphertext: String, key: String, iv: String, algorithm: Algorithms): Promise<String> = Promise { resolve, reject ->
    try { resolve(decryptText(ciphertext, key, iv)) } catch (e: Throwable) { reject(e) }
  }

  override fun encryptFile(
    key: String,
    iv: String,
    hmacKey: String,
    inputPath: String,
    outputPath: String
  ): Promise<String> = Promise { resolve, reject ->
    try {
      val (auth, padding) = doEncryptFile(key, iv, hmacKey, inputPath, outputPath)
      resolve("{\"auth\":\"$auth\",\"paddingSize\":$padding}")
    } catch (e: Throwable) {
      reject(e)
    }
  }

  override fun decryptFile(
    key: String,
    iv: String,
    hmacKey: String,
    auth: String,
    inputPath: String,
    outputPath: String,
    paddingSize: Double
  ): Promise<String> = Promise { resolve, reject ->
    try {
      doDecryptFile(key, iv, hmacKey, auth, inputPath, outputPath, paddingSize.toInt())
      resolve("OK")
    } catch (e: Throwable) {
      reject(e)
    }
  }

  override fun hmac256(ciphertext: String, key: String): Promise<String> = Promise { res, rej ->
    try { res(hmac(ciphertext, key, HMAC_SHA256)) } catch (e: Throwable) { rej(e) }
  }

  override fun hmac512(ciphertext: String, key: String): Promise<String> = Promise { res, rej ->
    try { res(hmac(ciphertext, key, "HmacSHA512")) } catch (e: Throwable) { rej(e) }
  }

  override fun randomKey(length: Double): Promise<String> = Promise { res, rej ->
    try { res(generateRandomKey(length.toInt())) } catch (e: Throwable) { rej(e) }
  }

  override fun sha1(text: String): Promise<String> = Promise { res, rej ->
    try { res(sha(text, "SHA-1")) } catch (e: Throwable) { rej(e) }
  }

  override fun sha256(text: String): Promise<String> = Promise { res, rej ->
    try { res(sha(text, "SHA-256")) } catch (e: Throwable) { rej(e) }
  }

  override fun sha512(text: String): Promise<String> = Promise { res, rej ->
    try { res(sha(text, "SHA-512")) } catch (e: Throwable) { rej(e) }
  }

  // --- Utilities ---
  private fun hexToBytes(hex: String): ByteArray = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
  private fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

  private fun encryptText(text: String, keyHex: String, ivHex: String): String {
    val key = hexToBytes(keyHex)
    val iv = if (ivHex.isEmpty()) ByteArray(BLOCK_SIZE) else hexToBytes(ivHex)
    val cipher = Cipher.getInstance(TEXT_CIPHER)
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
    return Base64.encodeToString(cipher.doFinal(text.toByteArray(StandardCharsets.UTF_8)), Base64.NO_WRAP)
  }

  private fun decryptText(cipher: String, keyHex: String, ivHex: String): String {
    val key = hexToBytes(keyHex)
    val iv = if (ivHex.isEmpty()) ByteArray(BLOCK_SIZE) else hexToBytes(ivHex)
    val data = Base64.decode(cipher, Base64.NO_WRAP)
    val cipher = Cipher.getInstance(TEXT_CIPHER)
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
    return String(cipher.doFinal(data), StandardCharsets.UTF_8)
  }

  private fun hmac(text: String, keyHex: String, alg: String): String {
    val mac = Mac.getInstance(alg)
    mac.init(SecretKeySpec(hexToBytes(keyHex), alg))
    return bytesToHex(mac.doFinal(text.toByteArray(StandardCharsets.UTF_8)))
  }

  private fun sha(text: String, algorithm: String): String = bytesToHex(MessageDigest.getInstance(algorithm).digest(text.toByteArray(StandardCharsets.UTF_8)))

  private fun generateRandomKey(len: Int): String {
    val b = ByteArray(len)
    SecureRandom().nextBytes(b)
    return bytesToHex(b)
  }

  private fun doEncryptFile(
    keyHex: String,
    ivHex: String,
    hmacHex: String,
    inputPath: String,
    outputPath: String
  ): Pair<String, Int> {
    val key = hexToBytes(keyHex)
    val iv = hexToBytes(ivHex)
    val hmacKey = hexToBytes(hmacHex)
    val secretKey = SecretKeySpec(key, KEY_ALGORITHM)
    val macKey = SecretKeySpec(hmacKey, HMAC_SHA256)
    val cipher = Cipher.getInstance(FILE_CIPHER).apply { init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv)) }
    val mac = Mac.getInstance(HMAC_SHA256).apply { init(macKey) }
    val digest = MessageDigest.getInstance("SHA-256")
    FileInputStream(File(inputPath)).use { input ->
      FileOutputStream(File(outputPath)).use { output ->
        val size = File(inputPath).length()
        val padding = if (size % BLOCK_SIZE == 0L) 0 else (BLOCK_SIZE - (size % BLOCK_SIZE)).toInt()
        val buffer = ByteArray(CHUNK_SIZE)
        val chunks = Math.ceil(size.toDouble() / CHUNK_SIZE).toInt()
        for (i in 0 until chunks) {
          var read = input.read(buffer)
          if (i == chunks -1 && padding > 0) {
            for (j in read until read + padding) buffer[j] = padding.toByte()
            read += padding
          }
          val enc = cipher.update(buffer, 0, read)
          mac.update(enc); digest.update(enc)
          output.write(enc)
        }
        val final = cipher.doFinal()
        mac.update(final); digest.update(final)
        output.write(final)
        val hmac = mac.doFinal()
        digest.update(hmac)
        output.write(hmac)
        val auth = bytesToHex(digest.digest())
        return Pair(auth, padding)
      }
    }
  }

  private fun doDecryptFile(
    keyHex: String,
    ivHex: String,
    hmacHex: String,
    theirAuth: String,
    inputPath: String,
    outputPath: String,
    paddingSize: Int
  ) {
    val key = hexToBytes(keyHex)
    val iv = hexToBytes(ivHex)
    val hmacKey = hexToBytes(hmacHex)
    val secretKey = SecretKeySpec(key, KEY_ALGORITHM)
    val macKey = SecretKeySpec(hmacKey, HMAC_SHA256)
    val cipher = Cipher.getInstance(FILE_CIPHER).apply { init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv)) }
    val mac = Mac.getInstance(HMAC_SHA256).apply { init(macKey) }
    val digest = MessageDigest.getInstance("SHA-256")
    FileInputStream(File(inputPath)).use { input ->
      FileOutputStream(File(outputPath)).use { output ->
        val size = File(inputPath).length()
        val macLen = mac.macLength
        val encLen = size - macLen
        val buffer = ByteArray(CHUNK_SIZE)
        var rem = encLen.toInt()

        while (rem > 0) {
          val toRead = minOf(rem, CHUNK_SIZE)
          val read = input.read(buffer, 0, toRead)
          mac.update(buffer, 0, read); digest.update(buffer, 0, read)
          val dec = cipher.update(buffer, 0, read)
          if (rem <= CHUNK_SIZE) output.write(dec, 0, dec.size - paddingSize) else output.write(dec)
          rem -= read
        }
        val ourHmac = mac.doFinal()
        val theirHmac = ByteArray(macLen).also { input.read(it) }
        require(ourHmac.contentEquals(theirHmac)) { "HMAC mismatch" }
        digest.update(theirHmac)
        require(bytesToHex(digest.digest()) == theirAuth) { "Auth mismatch" }
        val final = cipher.doFinal()
        if (final.isNotEmpty()) output.write(final)
      }
    }
  }
}

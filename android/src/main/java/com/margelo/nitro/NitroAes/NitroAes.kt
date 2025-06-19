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

/**
 * Implementation of the Nitro AES module.
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

  // Text encrypt/decrypt
  override fun encrypt(text: String, key: String, iv: String, algorithm: Algorithms): Promise<String> = Promise { resolve, reject ->
    try {
      val encrypted = encryptText(text, key, iv)
      resolve(encrypted)
    } catch (e: Throwable) {
      reject(e)
    }
  }

  override fun decrypt(ciphertext: String, key: String, iv: String, algorithm: Algorithms): Promise<String> = Promise { resolve, reject ->
    try {
      val decrypted = decryptText(ciphertext, key, iv)
      resolve(decrypted)
    } catch (e: Throwable) {
      reject(e)
    }
  }

  // File encrypt: returns JSON string { auth: string, paddingSize: number }
  override fun encryptFile(key: String, iv: String, inputPath: String, outputPath: String): Promise<String> = Promise { resolve, reject ->
    try {
      // Use same key for HMAC
      val (auth, padding) = doEncryptFile(key, iv, key, inputPath, outputPath)
      val json = "{\"auth\":\"$auth\",\"paddingSize\":$padding}"
      resolve(json)
    } catch (e: Throwable) {
      reject(e)
    }
  }

  // File decrypt
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

  // HMAC & hashing
  override fun hmac256(ciphertext: String, key: String): Promise<String> = Promise { res, rej ->
    try { res(hmac(ciphertext, key, HMAC_SHA256)) } catch(e: Throwable) { rej(e) }
  }
  override fun hmac512(ciphertext: String, key: String): Promise<String> = Promise { res, rej ->
    try { res(hmac(ciphertext, key, "HmacSHA512")) } catch(e: Throwable) { rej(e) }
  }
  override fun sha1(text: String): Promise<String> = Promise { res, rej ->
    try { res(sha(text, "SHA-1")) } catch(e: Throwable) { rej(e) }
  }
  override fun sha256(text: String): Promise<String> = Promise { res, rej ->
    try { res(sha(text, "SHA-256")) } catch(e: Throwable) { rej(e) }
  }
  override fun sha512(text: String): Promise<String> = Promise { res, rej ->
    try { res(sha(text, "SHA-512")) } catch(e: Throwable) { rej(e) }
  }

  // Random key
  override fun randomKey(length: Double): Promise<String> = Promise { res, rej ->
    try { res(generateRandomKey(length.toInt())) } catch(e: Throwable) { rej(e) }
  }

  // Private utilities
  private fun hexToBytes(hex: String): ByteArray =
    hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

  private fun bytesToHex(bytes: ByteArray): String =
    bytes.joinToString("") { "%02x".format(it) }

  private fun encryptText(text: String, keyHex: String, ivHex: String): String {
    val key = hexToBytes(keyHex)
    val iv  = if (ivHex.isEmpty()) ByteArray(BLOCK_SIZE) else hexToBytes(ivHex)
    val cipher = Cipher.getInstance(TEXT_CIPHER)
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
    val out = cipher.doFinal(text.toByteArray(StandardCharsets.UTF_8))
    return Base64.encodeToString(out, Base64.NO_WRAP)
  }

  private fun decryptText(cipher: String, keyHex: String, ivHex: String): String {
    val key = hexToBytes(keyHex)
    val iv  = if (ivHex.isEmpty()) ByteArray(BLOCK_SIZE) else hexToBytes(ivHex)
    val data = Base64.decode(cipher, Base64.NO_WRAP)
    val cipher = Cipher.getInstance(TEXT_CIPHER)
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
    return String(cipher.doFinal(data), StandardCharsets.UTF_8)
  }

  private fun hmac(text: String, keyHex: String, alg: String): String {
    val key = hexToBytes(keyHex)
    val mac = Mac.getInstance(alg).apply { init(SecretKeySpec(key, alg)) }
    val out = mac.doFinal(text.toByteArray(StandardCharsets.UTF_8))
    return bytesToHex(out)
  }

  private fun sha(text: String, alg: String): String {
    val md = MessageDigest.getInstance(alg)
    val digest = md.digest(text.toByteArray(StandardCharsets.UTF_8))
    return bytesToHex(digest)
  }

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
    // Adapted from your Java implementation:
    val key = hexToBytes(keyHex)
    val hmacKey = hexToBytes(hmacHex)
    val iv = hexToBytes(ivHex)

    val secretKey = SecretKeySpec(key, KEY_ALGORITHM)
    val macKey = SecretKeySpec(hmacKey, HMAC_SHA256)
    val cipher = Cipher.getInstance(FILE_CIPHER).apply {
      init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
    }
    val mac = Mac.getInstance(HMAC_SHA256).apply { init(macKey) }
    val digest = MessageDigest.getInstance("SHA-256")

    FileOutputStream(File(outputPath)).use { outputStream ->
      FileInputStream(File(inputPath)).use { inputStream ->
        val file = File(inputPath)
        val fileSize = file.length()
        val paddingSize = if (fileSize % BLOCK_SIZE == 0L) 0 else (BLOCK_SIZE - (fileSize % BLOCK_SIZE)).toInt()
        val buffer = ByteArray(CHUNK_SIZE)
        val chunks = Math.ceil(fileSize.toDouble() / CHUNK_SIZE).toInt()

        for (i in 0 until chunks) {
          var read = inputStream.read(buffer)
          if (i == chunks -1 && paddingSize > 0) {
            for (j in read until read + paddingSize) buffer[j] = paddingSize.toByte()
            read += paddingSize
          }
          val enc = cipher.update(buffer, 0, read)
          mac.update(enc)
          digest.update(enc)
          outputStream.write(enc)
        }
        val finalEnc = cipher.doFinal()
        digest.update(finalEnc)
        mac.update(finalEnc)
        outputStream.write(finalEnc)
        val hmac = mac.doFinal()
        digest.update(hmac)
        outputStream.write(hmac)

        val auth = bytesToHex(digest.digest())
        return Pair(auth, paddingSize)
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
    // Adapted from your Java implementation:
    val key = hexToBytes(keyHex)
    val hmacKey = hexToBytes(hmacHex)
    val iv = hexToBytes(ivHex)

    val secretKey = SecretKeySpec(key, KEY_ALGORITHM)
    val macKey = SecretKeySpec(hmacKey, HMAC_SHA256)
    val cipher = Cipher.getInstance(FILE_CIPHER).apply {
      init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
    }
    val mac = Mac.getInstance(HMAC_SHA256).apply { init(macKey) }
    val digest = MessageDigest.getInstance("SHA-256")

    FileOutputStream(File(outputPath)).use { outputStream ->
      FileInputStream(File(inputPath)).use { inputStream ->
        val fileSize = File(inputPath).length()
        val macLen = mac.macLength
        val encSize = fileSize - macLen
        val buffer = ByteArray(CHUNK_SIZE)
        var remaining = encSize

        while (remaining > 0) {
          val toRead = minOf(buffer.size, remaining.toInt())
          val read = inputStream.read(buffer, 0, toRead)
          mac.update(buffer, 0, read)
          digest.update(buffer, 0, read)
          val dec = cipher.update(buffer, 0, read)
          if (remaining <= CHUNK_SIZE) {
            // last
            outputStream.write(dec, 0, dec.size - paddingSize)
          } else {
            outputStream.write(dec)
          }
          remaining -= read
        }
        val ourHmac = mac.doFinal()
        val theirHmac = ByteArray(macLen).also { inputStream.read(it) }
        if (!MessageDigest.isEqual(ourHmac, theirHmac)) throw Exception("HMAC mismatch")
        digest.update(theirHmac)
        val ourAuth = bytesToHex(digest.digest())
        if (ourAuth != theirAuth) throw Exception("Auth mismatch")
        val finalDec = cipher.doFinal()
        if (finalDec.isNotEmpty()) outputStream.write(finalDec)
      }
    }
  }
}

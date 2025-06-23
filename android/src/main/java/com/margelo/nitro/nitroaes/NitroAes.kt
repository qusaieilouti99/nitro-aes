package com.margelo.nitro.nitroaes

import android.util.Base64
import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.core.Promise
import com.margelo.nitro.nitroaes.NitroAesOnLoad
import com.margelo.nitro.nitroaes.Algorithms
import com.margelo.nitro.nitroaes.EncryptFileResult
import com.margelo.nitro.nitroaes.HybridNitroAesSpec
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

@DoNotStrip
class NitroAes : HybridNitroAesSpec() {

  companion object {
    private const val KEY_ALGORITHM = "AES"
    private const val TEXT_CIPHER = "AES/CBC/PKCS7Padding"
    private const val FILE_CIPHER = "AES/CBC/NoPadding"
    private const val HMAC_SHA256 = "HmacSHA256"
    private const val BLOCK_SIZE = 16
    private const val CHUNK_SIZE = BLOCK_SIZE * 4 * 1024

    private val isInitialized: Boolean by lazy {
      NitroAesOnLoad.initializeNative()
      true
    }

    private fun ensureInitialized() {
      // Force native load
      isInitialized
    }
  }

  @DoNotStrip
  override fun pbkdf2(
    password: String,
    salt: String,
    cost: Double,
    length: Double
  ): Promise<String> = Promise.async {
    ensureInitialized()
    val spec = PBEKeySpec(
      password.toCharArray(),
      salt.toByteArray(StandardCharsets.UTF_8),
      cost.toInt(),
      (length * 8).toInt()
    )
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
    val keyBytes = factory.generateSecret(spec).encoded
    bytesToHex(keyBytes)
  }

  @DoNotStrip
  override fun encrypt(
    text: String,
    key: String,
    iv: String,
    algorithm: Algorithms
  ): Promise<String> = Promise.async {
    ensureInitialized()
    encryptText(text, key, iv)
  }

  @DoNotStrip
  override fun decrypt(
    ciphertext: String,
    key: String,
    iv: String,
    algorithm: Algorithms
  ): Promise<String> = Promise.async {
    ensureInitialized()
    decryptText(ciphertext, key, iv)
  }

  @DoNotStrip
  override fun encryptFile(
    key: String,
    iv: String,
    hmacKey: String,
    inputPath: String,
    outputPath: String
  ): Promise<EncryptFileResult> = Promise.async {
    ensureInitialized()
    val (auth, padding) = doEncryptFile(key, iv, hmacKey, inputPath, outputPath)
    EncryptFileResult(auth, padding.toDouble())
  }

  @DoNotStrip
  override fun decryptFile(
    keyHex: String,
    ivHex: String,
    hmacHex: String,
    theirAuth: String,
    inputPath: String,
    outputPath: String,
    paddingSize: Double
  ): Promise<String> = Promise.async {
    ensureInitialized()
    try {
      doDecryptFile(keyHex, ivHex, hmacHex, theirAuth, inputPath, outputPath, paddingSize.toInt())
      "OK"
    } catch (e: FileNotFoundException) {
      throw Error("File not found: ${e.message}")
    } catch (e: IllegalArgumentException) {
      throw Error("Decryption failed: ${e.message}")
    } catch (e: Exception) {
      throw Error("Unknown decryption error: ${e.message}")
    }
  }

  @DoNotStrip
  override fun hmac256(
    ciphertext: String,
    key: String
  ): Promise<String> = Promise.async {
    ensureInitialized()
    hmac(ciphertext, key, HMAC_SHA256)
  }

  @DoNotStrip
  override fun hmac512(
    ciphertext: String,
    key: String
  ): Promise<String> = Promise.async {
    ensureInitialized()
    hmac(ciphertext, key, "HmacSHA512")
  }

  @DoNotStrip
  override fun randomKey(length: Double): Promise<String> = Promise.async {
    ensureInitialized()
    generateRandomKey(length.toInt())
  }

  @DoNotStrip
  override fun sha1(text: String): Promise<String> = Promise.async {
    ensureInitialized()
    sha(text, "SHA-1")
  }

  @DoNotStrip
  override fun sha256(text: String): Promise<String> = Promise.async {
    ensureInitialized()
    sha(text, "SHA-256")
  }

  @DoNotStrip
  override fun sha512(text: String): Promise<String> = Promise.async {
    ensureInitialized()
    sha(text, "SHA-512")
  }

  private fun hexToBytes(hex: String): ByteArray =
    hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

  private fun bytesToHex(bytes: ByteArray): String =
    bytes.joinToString("") { "%02x".format(it) }

  private fun encryptText(
    text: String,
    keyHex: String,
    ivHex: String
  ): String {
    val key = hexToBytes(keyHex)
    val iv = if (ivHex.isEmpty()) ByteArray(BLOCK_SIZE) else hexToBytes(ivHex)
    val cipher = Cipher.getInstance(TEXT_CIPHER)
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
    val encrypted = cipher.doFinal(text.toByteArray(StandardCharsets.UTF_8))
    return Base64.encodeToString(encrypted, Base64.NO_WRAP)
  }

  private fun decryptText(
    cipherText: String,
    keyHex: String,
    ivHex: String
  ): String {
    val key = hexToBytes(keyHex)
    val iv = if (ivHex.isEmpty()) ByteArray(BLOCK_SIZE) else hexToBytes(ivHex)
    val data = Base64.decode(cipherText, Base64.NO_WRAP)
    val cipher = Cipher.getInstance(TEXT_CIPHER)
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
    val decrypted = cipher.doFinal(data)
    return String(decrypted, StandardCharsets.UTF_8)
  }

  private fun hmac(
    text: String,
    keyHex: String,
    algorithm: String
  ): String {
    val mac = Mac.getInstance(algorithm)
    mac.init(SecretKeySpec(hexToBytes(keyHex), algorithm))
    val result = mac.doFinal(text.toByteArray(StandardCharsets.UTF_8))
    return bytesToHex(result)
  }

  private fun sha(text: String, algorithm: String): String =
    bytesToHex(MessageDigest.getInstance(algorithm).digest(text.toByteArray(StandardCharsets.UTF_8)))

  private fun generateRandomKey(len: Int): String {
    val bytes = ByteArray(len)
    SecureRandom().nextBytes(bytes)
    return bytesToHex(bytes)
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
          if (i == chunks - 1 && padding > 0) {
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
    val inFile = File(inputPath)
    if (!inFile.exists()) {
      throw Error("Input file does not exist at path: $inputPath")
    }
    val outFile = File(outputPath).apply { parentFile?.mkdirs() }
    FileInputStream(inFile).use { input ->
      FileOutputStream(outFile).use { output ->
        val size = inFile.length()
        val macLen = mac.macLength
        val encLen = (size - macLen).toInt()
        val buffer = ByteArray(CHUNK_SIZE)
        var rem = encLen
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
        if (!ourHmac.contentEquals(theirHmac)) {
          throw Error("HMAC mismatch: computed=${bytesToHex(ourHmac)} expected=$theirAuth")
        }
        digest.update(theirHmac)
        val computedAuth = bytesToHex(digest.digest())
        if (computedAuth != theirAuth) {
          throw Error("Auth digest mismatch: computed=$computedAuth expected=$theirAuth")
        }
        cipher.doFinal().takeIf { it.isNotEmpty() }?.let { output.write(it) }
      }
    }
  }
}

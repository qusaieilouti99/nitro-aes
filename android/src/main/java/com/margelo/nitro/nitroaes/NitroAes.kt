package com.margelo.nitro.nitroaes

import android.util.Base64
import android.util.Log
import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.core.Promise
import com.margelo.nitro.nitroaes.NitroAesOnLoad
import com.margelo.nitro.nitroaes.Algorithms
import com.margelo.nitro.nitroaes.EncryptFileResult
import com.margelo.nitro.nitroaes.HybridNitroAesSpec
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
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
    private const val TAG = "NitroAes"
    private const val KEY_ALGORITHM = "AES"
    private const val TEXT_CIPHER = "AES/CBC/PKCS7Padding"
    private const val FILE_CIPHER = "AES/CBC/NoPadding"
    private const val HMAC_SHA256 = "HmacSHA256"
    private const val BLOCK_SIZE = 16
    private const val CHUNK_SIZE = BLOCK_SIZE * 4 * 1024

    // Pre-compiled regex for better performance
    private val HEX_PATTERN = Regex("^[0-9a-fA-F]+$")

    // Hex lookup table for faster conversion
    private val HEX_CHARS = "0123456789abcdef".toCharArray()

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
    try {
      ensureInitialized()

      if (password.isEmpty()) {
        throw IllegalArgumentException("Password cannot be empty")
      }
      if (salt.isEmpty()) {
        throw IllegalArgumentException("Salt cannot be empty")
      }
      if (cost <= 0) {
        throw IllegalArgumentException("Cost must be positive")
      }
      if (length <= 0) {
        throw IllegalArgumentException("Length must be positive")
      }

      val spec = PBEKeySpec(
        password.toCharArray(),
        salt.toByteArray(StandardCharsets.UTF_8),
        cost.toInt(),
        (length * 8).toInt()
      )
      val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
      val keyBytes = factory.generateSecret(spec).encoded
      spec.clearPassword() // Clear sensitive data
      bytesToHex(keyBytes)
    } catch (e: Exception) {
      Log.e(TAG, "PBKDF2 error: ${e.message}", e)
      throw RuntimeException("PBKDF2 failed: ${e.message}", e)
    }
  }

  @DoNotStrip
  override fun encrypt(
    text: String,
    key: String,
    iv: String,
    algorithm: Algorithms
  ): Promise<String> = Promise.async {
    try {
      ensureInitialized()
      validateHexString(key, "key")
      if (iv.isNotEmpty()) {
        validateHexString(iv, "iv")
      }
      encryptText(text, key, iv, algorithm)
    } catch (e: Exception) {
      Log.e(TAG, "Encrypt error: ${e.message}", e)
      throw RuntimeException("Encryption failed: ${e.message}", e)
    }
  }

  @DoNotStrip
  override fun decrypt(
    ciphertext: String,
    key: String,
    iv: String,
    algorithm: Algorithms
  ): Promise<String> = Promise.async {
    try {
      ensureInitialized()
      validateHexString(key, "key")
      if (iv.isNotEmpty()) {
        validateHexString(iv, "iv")
      }
      decryptText(ciphertext, key, iv, algorithm)
    } catch (e: Exception) {
      Log.e(TAG, "Decrypt error: ${e.message}", e)
      throw RuntimeException("Decryption failed: ${e.message}", e)
    }
  }

  @DoNotStrip
  override fun encryptFile(
    key: String,
    iv: String,
    hmacKey: String,
    inputPath: String,
    outputPath: String
  ): Promise<EncryptFileResult> = Promise.async {
    try {
      ensureInitialized()
      validateHexString(key, "key")
      validateHexString(iv, "iv")
      validateHexString(hmacKey, "hmacKey")

      if (inputPath.isEmpty() || outputPath.isEmpty()) {
        throw IllegalArgumentException("File paths cannot be empty")
      }

      val (auth, padding) = doEncryptFile(key, iv, hmacKey, inputPath, outputPath)
      EncryptFileResult(auth, padding.toDouble())
    } catch (e: Exception) {
      Log.e(TAG, "Encrypt file error: ${e.message}", e)
      throw RuntimeException("File encryption failed: ${e.message}", e)
    }
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
    try {
      ensureInitialized()

      validateHexString(keyHex, "key")
      validateHexString(ivHex, "iv")
      validateHexString(hmacHex, "hmacKey")
      validateHexString(theirAuth, "auth")

      if (inputPath.isEmpty() || outputPath.isEmpty()) {
        throw IllegalArgumentException("File paths cannot be empty")
      }

      if (paddingSize < 0 || paddingSize >= BLOCK_SIZE) {
        throw IllegalArgumentException("Invalid padding size: $paddingSize")
      }

      Log.d(TAG, "Decrypting file: $inputPath -> $outputPath")

      doDecryptFile(keyHex, ivHex, hmacHex, theirAuth, inputPath, outputPath, paddingSize.toInt())
      "OK"
    } catch (e: FileNotFoundException) {
      Log.e(TAG, "File not found: ${e.message}", e)
      throw RuntimeException("File not found: ${e.message}", e)
    } catch (e: SecurityException) {
      Log.e(TAG, "Security error: ${e.message}", e)
      throw RuntimeException("Security error: ${e.message}", e)
    } catch (e: IllegalArgumentException) {
      Log.e(TAG, "Invalid argument: ${e.message}", e)
      throw RuntimeException("Invalid argument: ${e.message}", e)
    } catch (e: IOException) {
      Log.e(TAG, "IO error: ${e.message}", e)
      throw RuntimeException("IO error: ${e.message}", e)
    } catch (e: Exception) {
      Log.e(TAG, "Decryption error: ${e.message}", e)
      throw RuntimeException("Decryption failed: ${e.message}", e)
    }
  }

  @DoNotStrip
  override fun hmac256(
    ciphertext: String,
    key: String
  ): Promise<String> = Promise.async {
    try {
      ensureInitialized()
      validateHexString(key, "key")
      hmac(ciphertext, key, HMAC_SHA256)
    } catch (e: Exception) {
      Log.e(TAG, "HMAC256 error: ${e.message}", e)
      throw RuntimeException("HMAC256 failed: ${e.message}", e)
    }
  }

  @DoNotStrip
  override fun hmac512(
    ciphertext: String,
    key: String
  ): Promise<String> = Promise.async {
    try {
      ensureInitialized()
      validateHexString(key, "key")
      hmac(ciphertext, key, "HmacSHA512")
    } catch (e: Exception) {
      Log.e(TAG, "HMAC512 error: ${e.message}", e)
      throw RuntimeException("HMAC512 failed: ${e.message}", e)
    }
  }

  @DoNotStrip
  override fun randomKey(length: Double): Promise<String> = Promise.async {
    try {
      ensureInitialized()
      if (length <= 0) {
        throw IllegalArgumentException("Length must be positive")
      }
      generateRandomKey(length.toInt())
    } catch (e: Exception) {
      Log.e(TAG, "Random key generation error: ${e.message}", e)
      throw RuntimeException("Random key generation failed: ${e.message}", e)
    }
  }

  @DoNotStrip
  override fun sha1(text: String): Promise<String> = Promise.async {
    try {
      ensureInitialized()
      sha(text, "SHA-1")
    } catch (e: Exception) {
      Log.e(TAG, "SHA1 error: ${e.message}", e)
      throw RuntimeException("SHA1 failed: ${e.message}", e)
    }
  }

  @DoNotStrip
  override fun sha256(text: String): Promise<String> = Promise.async {
    try {
      ensureInitialized()
      sha(text, "SHA-256")
    } catch (e: Exception) {
      Log.e(TAG, "SHA256 error: ${e.message}", e)
      throw RuntimeException("SHA256 failed: ${e.message}", e)
    }
  }

  @DoNotStrip
  override fun sha512(text: String): Promise<String> = Promise.async {
    try {
      ensureInitialized()
      sha(text, "SHA-512")
    } catch (e: Exception) {
      Log.e(TAG, "SHA512 error: ${e.message}", e)
      throw RuntimeException("SHA512 failed: ${e.message}", e)
    }
  }

  private fun validateHexString(hex: String, name: String) {
    if (hex.isEmpty()) {
      throw IllegalArgumentException("$name cannot be empty")
    }
    if (hex.length % 2 != 0) {
      throw IllegalArgumentException("$name must have even length")
    }
    if (!HEX_PATTERN.matches(hex)) {
      throw IllegalArgumentException("$name contains invalid hex characters")
    }
  }

  private fun hexToBytes(hex: String): ByteArray {
    try {
      val len = hex.length
      val result = ByteArray(len / 2)
      for (i in 0 until len step 2) {
        result[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
      }
      return result
    } catch (e: Exception) {
      throw IllegalArgumentException("Invalid hex string: $hex", e)
    }
  }

  // Optimized hex conversion using lookup table
  private fun bytesToHex(bytes: ByteArray): String {
    val result = StringBuilder(bytes.size * 2)
    for (byte in bytes) {
      val b = byte.toInt() and 0xFF
      result.append(HEX_CHARS[b ushr 4])
      result.append(HEX_CHARS[b and 0x0F])
    }
    return result.toString()
  }

  private fun encryptText(
    text: String,
    keyHex: String,
    ivHex: String,
    algorithm: Algorithms
  ): String {
    val key = hexToBytes(keyHex)
    val iv = if (ivHex.isEmpty()) ByteArray(BLOCK_SIZE) else hexToBytes(ivHex)

    // Validate key size based on algorithm
    val expectedKeySize = when (algorithm) {
      Algorithms.AES_128_CBC -> 16
      Algorithms.AES_192_CBC -> 24
      Algorithms.AES_256_CBC -> 32
    }

    if (key.size != expectedKeySize) {
      throw IllegalArgumentException("Key must be ${expectedKeySize * 8} bits for $algorithm")
    }

    if (iv.size != BLOCK_SIZE) {
      throw IllegalArgumentException("IV must be 128 bits (32 hex characters)")
    }

    val cipher = Cipher.getInstance(TEXT_CIPHER)
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
    val encrypted = cipher.doFinal(text.toByteArray(StandardCharsets.UTF_8))
    return Base64.encodeToString(encrypted, Base64.NO_WRAP)
  }

  private fun decryptText(
    cipherText: String,
    keyHex: String,
    ivHex: String,
    algorithm: Algorithms
  ): String {
    val key = hexToBytes(keyHex)
    val iv = if (ivHex.isEmpty()) ByteArray(BLOCK_SIZE) else hexToBytes(ivHex)

    // Validate key size based on algorithm
    val expectedKeySize = when (algorithm) {
      Algorithms.AES_128_CBC -> 16
      Algorithms.AES_192_CBC -> 24
      Algorithms.AES_256_CBC -> 32
    }

    if (key.size != expectedKeySize) {
      throw IllegalArgumentException("Key must be ${expectedKeySize * 8} bits for $algorithm")
    }

    if (iv.size != BLOCK_SIZE) {
      throw IllegalArgumentException("IV must be 128 bits (32 hex characters)")
    }

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
    val key = hexToBytes(keyHex)
    val mac = Mac.getInstance(algorithm)
    mac.init(SecretKeySpec(key, algorithm))
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

    if (key.size != 32) {
      throw IllegalArgumentException("Key must be 256 bits")
    }
    if (iv.size != BLOCK_SIZE) {
      throw IllegalArgumentException("IV must be 128 bits")
    }
    if (hmacKey.size != 32) {
      throw IllegalArgumentException("HMAC key must be 256 bits")
    }

    val inFile = File(inputPath)
    if (!inFile.exists()) {
      throw FileNotFoundException("Input file does not exist: $inputPath")
    }
    if (!inFile.canRead()) {
      throw SecurityException("Cannot read input file: $inputPath")
    }

    val outFile = File(outputPath)
    outFile.parentFile?.let { parent ->
      if (!parent.exists() && !parent.mkdirs()) {
        throw IOException("Cannot create output directory: ${parent.absolutePath}")
      }
    }

    val secretKey = SecretKeySpec(key, KEY_ALGORITHM)
    val macKey = SecretKeySpec(hmacKey, HMAC_SHA256)
    val cipher = Cipher.getInstance(FILE_CIPHER).apply {
      init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
    }
    val mac = Mac.getInstance(HMAC_SHA256).apply { init(macKey) }
    val digest = MessageDigest.getInstance("SHA-256")

    // Use buffered streams for better I/O performance with original chunk size
    BufferedInputStream(FileInputStream(inFile), CHUNK_SIZE).use { input ->
      BufferedOutputStream(FileOutputStream(outFile), CHUNK_SIZE).use { output ->
        val size = inFile.length()
        val padding = if (size % BLOCK_SIZE == 0L) 0 else (BLOCK_SIZE - (size % BLOCK_SIZE)).toInt()
        val buffer = ByteArray(CHUNK_SIZE)
        val chunks = Math.ceil(size.toDouble() / CHUNK_SIZE).toInt()

        for (i in 0 until chunks) {
          var read = input.read(buffer)
          if (read == -1) break

          if (i == chunks - 1 && padding > 0) {
            for (j in read until read + padding) {
              buffer[j] = padding.toByte()
            }
            read += padding
          }

          val enc = cipher.update(buffer, 0, read)
          if (enc != null) {
            mac.update(enc)
            digest.update(enc)
            output.write(enc)
          }
        }

        val final = cipher.doFinal()
        if (final.isNotEmpty()) {
          mac.update(final)
          digest.update(final)
          output.write(final)
        }

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

    if (key.size != 32) {
      throw IllegalArgumentException("Key must be 256 bits")
    }
    if (iv.size != BLOCK_SIZE) {
      throw IllegalArgumentException("IV must be 128 bits")
    }
    if (hmacKey.size != 32) {
      throw IllegalArgumentException("HMAC key must be 256 bits")
    }

    val secretKey = SecretKeySpec(key, KEY_ALGORITHM)
    val macKey = SecretKeySpec(hmacKey, HMAC_SHA256)
    val cipher = Cipher.getInstance(FILE_CIPHER).apply {
      init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
    }
    val mac = Mac.getInstance(HMAC_SHA256).apply { init(macKey) }
    val digest = MessageDigest.getInstance("SHA-256")

    val inFile = File(inputPath)
    if (!inFile.exists()) {
      throw FileNotFoundException("Input file does not exist: $inputPath")
    }
    if (!inFile.canRead()) {
      throw SecurityException("Cannot read input file: $inputPath")
    }

    val outFile = File(outputPath)
    outFile.parentFile?.let { parent ->
      if (!parent.exists() && !parent.mkdirs()) {
        throw IOException("Cannot create output directory: ${parent.absolutePath}")
      }
    }

    // Use buffered streams for better I/O performance with original chunk size
    BufferedInputStream(FileInputStream(inFile), CHUNK_SIZE).use { input ->
      BufferedOutputStream(FileOutputStream(outFile), CHUNK_SIZE).use { output ->
        val size = inFile.length()
        val macLen = mac.macLength

        if (size <= macLen) {
          throw IllegalArgumentException("File too small to contain valid encrypted data")
        }

        val encLen = (size - macLen).toInt()
        val buffer = ByteArray(CHUNK_SIZE)
        var rem = encLen

        while (rem > 0) {
          val toRead = minOf(rem, CHUNK_SIZE)
          val read = input.read(buffer, 0, toRead)
          if (read == -1) {
            throw IOException("Unexpected end of file")
          }

          mac.update(buffer, 0, read)
          digest.update(buffer, 0, read)

          val dec = cipher.update(buffer, 0, read)
          if (dec != null) {
            if (rem <= CHUNK_SIZE && paddingSize > 0) {
              // Last chunk, remove padding
              val writeLen = maxOf(0, dec.size - paddingSize)
              if (writeLen > 0) {
                output.write(dec, 0, writeLen)
              }
            } else {
              output.write(dec)
            }
          }
          rem -= read
        }

        // Read and verify HMAC
        val ourHmac = mac.doFinal()
        val theirHmac = ByteArray(macLen)
        val hmacRead = input.read(theirHmac)
        if (hmacRead != macLen) {
          throw IOException("Could not read HMAC from file")
        }

        if (!ourHmac.contentEquals(theirHmac)) {
          throw SecurityException("HMAC verification failed - file may be corrupted or tampered")
        }

        digest.update(theirHmac)
        val computedAuth = bytesToHex(digest.digest())
        if (computedAuth != theirAuth) {
          throw SecurityException("Authentication failed - computed auth does not match expected")
        }

        // Finalize cipher
        val finalBytes = cipher.doFinal()
        if (finalBytes.isNotEmpty()) {
          output.write(finalBytes)
        }

        Log.d(TAG, "File decryption completed successfully")
      }
    }
  }
}

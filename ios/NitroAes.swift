import Foundation
import CommonCrypto
import NitroModules

public class NitroAes: HybridNitroAesSpec {
  public override init() { super.init() }

  private static let BLOCK_SIZE = kCCBlockSizeAES128 // 16
  private static let CHUNK_SIZE = 64 * 1024

  // Pre-compiled regex for hex validation
  private static let hexRegex = try! NSRegularExpression(pattern: "^[0-9a-fA-F]+$")

  // Hex lookup tables for faster conversion
  private static let hexChars: [Character] = Array("0123456789abcdef")

  // MARK: - PBKDF2
  public func pbkdf2(password: String, salt: String, cost: Double, length: Double) throws -> Promise<String> {
    return Promise.async {
      guard !password.isEmpty else { throw RuntimeError.error("Password cannot be empty") }
      guard !salt.isEmpty else { throw RuntimeError.error("Salt cannot be empty") }
      guard cost > 0 else { throw RuntimeError.error("Cost must be positive") }
      guard length > 0 else { throw RuntimeError.error("Length must be positive") }

      let passwordData = password.data(using: .utf8)!
      let saltData = salt.data(using: .utf8)!
      var hashKeyData = Data(count: Int(length))

      let status = hashKeyData.withUnsafeMutableBytes { hashKeyBytes in
        CCKeyDerivationPBKDF(
          kCCPBKDF2,
          passwordData.withUnsafeBytes { $0.baseAddress! },
          passwordData.count,
          saltData.withUnsafeBytes { $0.baseAddress! },
          saltData.count,
          kCCPRFHmacAlgSHA512,
          UInt32(cost),
          hashKeyBytes.baseAddress!,
          hashKeyData.count
        )
      }

      guard status == kCCSuccess else {
        throw RuntimeError.error("PBKDF2 failed")
      }

      return Self.toHex(hashKeyData)
    }
  }

  // MARK: - Text Encryption/Decryption
  public func encrypt(text: String, key: String, iv: String, algorithm: Algorithms) throws -> Promise<String> {
    return Promise.async {
      guard !text.isEmpty && !key.isEmpty && !iv.isEmpty else {
        throw RuntimeError.error("Invalid input")
      }

      try Self.validateHexString(key, name: "key")
      try Self.validateHexString(iv, name: "iv")

      let result = Self.encryptText(clearText: text, key: key, iv: iv, algorithm: algorithm)
      guard let encrypted = result else {
        throw RuntimeError.error("Encryption failed")
      }
      return encrypted
    }
  }

  public func decrypt(ciphertext: String, key: String, iv: String, algorithm: Algorithms) throws -> Promise<String> {
    return Promise.async {
      guard !ciphertext.isEmpty && !key.isEmpty && !iv.isEmpty else {
        throw RuntimeError.error("Invalid input")
      }

      try Self.validateHexString(key, name: "key")
      try Self.validateHexString(iv, name: "iv")

      let result = Self.decryptText(cipherText: ciphertext, key: key, iv: iv, algorithm: algorithm)
      guard let decrypted = result else {
        throw RuntimeError.error("Decryption failed")
      }
      return decrypted
    }
  }

  public func encryptFile(
    key: String,
    iv: String,
    hmacKey: String,
    inputPath: String,
    outputPath: String
  ) throws -> Promise<EncryptFileResult> {
    return Promise.async {
      try Self.validateHexString(key, name: "key")
      try Self.validateHexString(iv, name: "iv")
      try Self.validateHexString(hmacKey, name: "hmacKey")

      let result = Self.performFileEncryption(
        hexKey: key,
        iv: iv,
        hmacKey: hmacKey,
        inputPath: inputPath,
        outputPath: outputPath
      )

      guard let encryptResult = result,
            let auth = encryptResult["auth"] as? String,
            let paddingSize = encryptResult["paddingSize"] as? NSNumber else {
        throw RuntimeError.error("Invalid encryption result")
      }

      return EncryptFileResult(auth: auth, paddingSize: paddingSize.doubleValue)
    }
  }

  public func decryptFile(
    key: String,
    iv: String,
    hmacKey: String,
    auth: String,
    inputPath: String,
    outputPath: String,
    paddingSize: Double
  ) throws -> Promise<String> {
    return Promise.async {
      try Self.validateHexString(key, name: "key")
      try Self.validateHexString(iv, name: "iv")
      try Self.validateHexString(hmacKey, name: "hmacKey")
      try Self.validateHexString(auth, name: "auth")

      return try await withCheckedThrowingContinuation { continuation in
        Self.performFileDecryption(
          hexKey: key,
          iv: iv,
          hmacKey: hmacKey,
          digest: auth,
          inputPath: inputPath,
          outputPath: outputPath,
          paddingSize: UInt(paddingSize)
        ) { result in
          if result == "Success" {
            continuation.resume(returning: "OK")
          } else {
            continuation.resume(throwing: RuntimeError.error(result))
          }
        }
      }
    }
  }

  // MARK: - HMAC
  public func hmac256(ciphertext: String, key: String) throws -> Promise<String> {
    return Promise.async {
      try Self.validateHexString(key, name: "key")
      return Self.computeHMAC256(input: ciphertext, key: key)
    }
  }

  public func hmac512(ciphertext: String, key: String) throws -> Promise<String> {
    return Promise.async {
      try Self.validateHexString(key, name: "key")
      return Self.computeHMAC512(input: ciphertext, key: key)
    }
  }

  // MARK: - Hashing
  public func sha1(text: String) throws -> Promise<String> {
    return Promise.async {
      return Self.computeSHA1(input: text)
    }
  }

  public func sha256(text: String) throws -> Promise<String> {
    return Promise.async {
      return Self.computeSHA256(input: text)
    }
  }

  public func sha512(text: String) throws -> Promise<String> {
    return Promise.async {
      return Self.computeSHA512(input: text)
    }
  }

  // MARK: - Random Generation
  public func randomKey(length: Double) throws -> Promise<String> {
    return Promise.async {
      let result = Self.generateRandomKey(length: Int(length))
      guard let key = result else {
        throw RuntimeError.error("Random key generation failed")
      }
      return key
    }
  }

  // MARK: - Private Implementation Methods
  private static func validateHexString(_ hex: String, name: String) throws {
    guard !hex.isEmpty else {
      throw RuntimeError.error("\(name) cannot be empty")
    }
    guard hex.count % 2 == 0 else {
      throw RuntimeError.error("\(name) must have even length")
    }

    let range = NSRange(location: 0, length: hex.utf16.count)
    guard hexRegex.firstMatch(in: hex, options: [], range: range) != nil else {
      throw RuntimeError.error("\(name) contains invalid hex characters")
    }
  }

  // Optimized hex conversion using lookup tables
  private static func toHex(_ data: Data) -> String {
    var result = ""
    result.reserveCapacity(data.count * 2)

    for byte in data {
      result.append(hexChars[Int(byte >> 4)])
      result.append(hexChars[Int(byte & 0x0F)])
    }
    return result
  }

  private static func fromHex(_ string: String) -> Data? {
    guard !string.isEmpty, string.count % 2 == 0 else { return nil }

    var data = Data()
    data.reserveCapacity(string.count / 2)

    var index = string.startIndex
    while index < string.endIndex {
      let nextIndex = string.index(index, offsetBy: 2)
      let byteString = string[index..<nextIndex]

      guard let byte = UInt8(byteString, radix: 16) else { return nil }
      data.append(byte)
      index = nextIndex
    }
    return data
  }

  private static func getAlgorithmKeySize(_ algorithm: Algorithms) -> size_t {
    switch algorithm {
    case .aes128Cbc:
      return kCCKeySizeAES128
    case .aes192Cbc:
      return kCCKeySizeAES192
    case .aes256Cbc:
      return kCCKeySizeAES256
    }
  }

  private static func performAESCBC(
    operation: String,
    data: Data,
    key: String,
    iv: String,
    algorithm: Algorithms
  ) -> Data? {
    guard let keyData = fromHex(key),
          let ivData = fromHex(iv) else {
      return nil
    }

    let keyLength = getAlgorithmKeySize(algorithm)

    // Validate key size
    guard keyData.count == keyLength else {
      print("Key must be \(keyLength * 8) bits for \(algorithm)")
      return nil
    }

    // Validate IV size
    guard ivData.count == BLOCK_SIZE else {
      print("IV must be 128 bits (32 hex characters)")
      return nil
    }

    var buffer = Data(count: data.count + BLOCK_SIZE)
    var numBytes: size_t = 0

    let cryptStatus = buffer.withUnsafeMutableBytes { bufferBytes in
      data.withUnsafeBytes { dataBytes in
        keyData.withUnsafeBytes { keyBytes in
          ivData.withUnsafeBytes { ivBytes in
            CCCrypt(
              operation == "encrypt" ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt),
              CCAlgorithm(kCCAlgorithmAES),
              CCOptions(kCCOptionPKCS7Padding),
              keyBytes.baseAddress, keyLength,
              ivData.count > 0 ? ivBytes.baseAddress : nil,
              dataBytes.baseAddress, data.count,
              bufferBytes.baseAddress, buffer.count,
              &numBytes
            )
          }
        }
      }
    }

    guard cryptStatus == kCCSuccess else {
      print("AES error: \(cryptStatus)")
      return nil
    }

    buffer.count = numBytes
    return buffer
  }

  private static func encryptText(clearText: String, key: String, iv: String, algorithm: Algorithms) -> String? {
    guard !clearText.isEmpty && !key.isEmpty && !iv.isEmpty else {
      print("Encryption failed due to invalid input")
      return nil
    }

    guard let data = clearText.data(using: .utf8) else { return nil }

    let result = performAESCBC(operation: "encrypt", data: data, key: key, iv: iv, algorithm: algorithm)
    guard let encryptedData = result else {
      print("Encryption failed")
      return nil
    }

    return encryptedData.base64EncodedString()
  }

  private static func decryptText(cipherText: String, key: String, iv: String, algorithm: Algorithms) -> String? {
    guard !cipherText.isEmpty && !key.isEmpty && !iv.isEmpty else {
      return nil
    }

    guard let data = Data(base64Encoded: cipherText) else { return nil }

    let result = performAESCBC(operation: "decrypt", data: data, key: key, iv: iv, algorithm: algorithm)
    guard let decryptedData = result else {
      return nil
    }

    return String(data: decryptedData, encoding: .utf8)
  }

  private static func computeHMAC256(input: String, key: String) -> String {
    guard let keyData = fromHex(key),
          let inputData = input.data(using: .utf8) else {
      return ""
    }

    var buffer = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    buffer.withUnsafeMutableBytes { bufferBytes in
      inputData.withUnsafeBytes { inputBytes in
        keyData.withUnsafeBytes { keyBytes in
          CCHmac(
            kCCHmacAlgSHA256,
            keyBytes.baseAddress, keyData.count,
            inputBytes.baseAddress, inputData.count,
            bufferBytes.baseAddress
          )
        }
      }
    }
    return toHex(buffer)
  }

  private static func computeHMAC512(input: String, key: String) -> String {
    guard let keyData = fromHex(key),
          let inputData = input.data(using: .utf8) else {
      return ""
    }

    var buffer = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
    buffer.withUnsafeMutableBytes { bufferBytes in
      inputData.withUnsafeBytes { inputBytes in
        keyData.withUnsafeBytes { keyBytes in
          CCHmac(
            kCCHmacAlgSHA512,
            keyBytes.baseAddress, keyData.count,
            inputBytes.baseAddress, inputData.count,
            bufferBytes.baseAddress
          )
        }
      }
    }
    return toHex(buffer)
  }

  private static func computeSHA1(input: String) -> String {
    guard let inputData = input.data(using: .utf8) else { return "" }

    var result = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
    result.withUnsafeMutableBytes { resultBytes in
      inputData.withUnsafeBytes { inputBytes in
        CC_SHA1(inputBytes.baseAddress, CC_LONG(inputData.count), resultBytes.baseAddress?.assumingMemoryBound(to: UInt8.self))
      }
    }
    return toHex(result)
  }

  private static func computeSHA256(input: String) -> String {
    guard let inputData = input.data(using: .utf8) else { return "" }

    var buffer = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    buffer.withUnsafeMutableBytes { bufferBytes in
      inputData.withUnsafeBytes { inputBytes in
        CC_SHA256(inputBytes.baseAddress, CC_LONG(inputData.count), bufferBytes.baseAddress?.assumingMemoryBound(to: UInt8.self))
      }
    }
    return toHex(buffer)
  }

  private static func computeSHA512(input: String) -> String {
    guard let inputData = input.data(using: .utf8) else { return "" }

    var buffer = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
    buffer.withUnsafeMutableBytes { bufferBytes in
      inputData.withUnsafeBytes { inputBytes in
        CC_SHA512(inputBytes.baseAddress, CC_LONG(inputData.count), bufferBytes.baseAddress?.assumingMemoryBound(to: UInt8.self))
      }
    }
    return toHex(buffer)
  }

  private static func generateRandomKey(length: Int) -> String? {
    var data = Data(count: length)
    let result = data.withUnsafeMutableBytes {
      SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!)
    }
    guard result == errSecSuccess else { return nil }
    return toHex(data)
  }

  private static func getFileSizeAtPath(_ filePath: String) -> UInt {
    let fileManager = FileManager.default
    guard let attributes = try? fileManager.attributesOfItem(atPath: filePath),
          let fileSize = attributes[.size] as? NSNumber else {
      return 0
    }
    return fileSize.uintValue
  }

  // MARK: - File Operations Implementation

  private static func performFileEncryption(
    hexKey: String,
    iv: String,
    hmacKey: String,
    inputPath: String,
    outputPath: String
  ) -> [String: Any]? {
    let fileManager = FileManager.default
    guard let keyData = fromHex(hexKey),
          let ivData = fromHex(iv),
          let hmacKeyData = fromHex(hmacKey) else {
      print("Failed to convert hex keys to data")
      return nil
    }

    // Validate key sizes
    guard keyData.count == 32 else {
      print("Key must be 256 bits")
      return nil
    }
    guard ivData.count == BLOCK_SIZE else {
      print("IV must be 128 bits")
      return nil
    }
    guard hmacKeyData.count == 32 else {
      print("HMAC key must be 256 bits")
      return nil
    }

    guard fileManager.fileExists(atPath: inputPath) else {
      print("Input file doesn't exist.")
      return nil
    }

    guard let inputStream = InputStream(fileAtPath: inputPath),
          let outputStream = OutputStream(toFileAtPath: outputPath, append: false) else {
      print("Failed to open input or output stream.")
      return nil
    }

    inputStream.open()
    outputStream.open()

    defer {
      inputStream.close()
      outputStream.close()
    }

    // Calculate file size
    let fileSize = getFileSizeAtPath(inputPath)

    // Set up cipher for encryption with NoPadding
    var cryptor: CCCryptorRef?
    let status = CCCryptorCreate(
      kCCEncrypt,
      kCCAlgorithmAES,
      0, // No padding
      keyData.withUnsafeBytes { $0.baseAddress! },
      keyData.count,
      ivData.withUnsafeBytes { $0.baseAddress! },
      &cryptor
    )

    guard status == kCCSuccess, let encryptor = cryptor else {
      print("Failed to create cryptor: \(status)")
      return nil
    }

    defer {
      CCCryptorRelease(encryptor)
    }

    // Set up MAC
    var hmacContext = CCHmacContext()
    CCHmacInit(&hmacContext, kCCHmacAlgSHA256, hmacKeyData.withUnsafeBytes { $0.baseAddress! }, hmacKeyData.count)

    let bufferSize = CHUNK_SIZE
    var buffer = Data(count: bufferSize)
    var totalBytesRead: UInt = 0
    var streamDigest = Data()

    // Calculate padding size
    let isMultipleOfBlockSize = fileSize % 16 == 0
    let paddingSize = isMultipleOfBlockSize ? 0 : (16 - (fileSize % 16))

    // Read data from the input file, encrypt it, and write to the output file
    while true {
      autoreleasepool {
        let bytesRead = buffer.withUnsafeMutableBytes { bufferBytes in
          inputStream.read(bufferBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), maxLength: bufferSize)
        }

        guard bytesRead > 0 else { return }

        totalBytesRead += UInt(bytesRead)
        let isLastChunk = (totalBytesRead == fileSize)

        var actualBytesToEncrypt = bytesRead

        if isLastChunk && paddingSize > 0 {
          // Ensure there's enough space for adding the padding
          if bytesRead + Int(paddingSize) <= bufferSize {
            buffer.withUnsafeMutableBytes { bufferBytes in
              let bytes = bufferBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
              for i in 0..<paddingSize {
                bytes[bytesRead + Int(i)] = UInt8(paddingSize)
              }
            }
            actualBytesToEncrypt += Int(paddingSize)
          } else {
            print("Buffer overflow: Cannot add padding, buffer too small")
            return
          }
        }

        var encryptedBuffer = Data(count: bufferSize)
        var bytesEncrypted: size_t = 0

        let encryptStatus = encryptedBuffer.withUnsafeMutableBytes { encryptedBytes in
          buffer.withUnsafeBytes { inputBytes in
            CCCryptorUpdate(
              encryptor,
              inputBytes.baseAddress!,
              actualBytesToEncrypt,
              encryptedBytes.baseAddress!,
              bufferSize,
              &bytesEncrypted
            )
          }
        }

        guard encryptStatus == kCCSuccess else {
          print("Failed to encrypt data: \(encryptStatus)")
          return
        }

        if bytesEncrypted > 0 {
          let encryptedData = encryptedBuffer.prefix(bytesEncrypted)
          outputStream.write(encryptedData.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) }, maxLength: bytesEncrypted)

          encryptedData.withUnsafeBytes { encryptedBytes in
            CCHmacUpdate(&hmacContext, encryptedBytes.baseAddress!, bytesEncrypted)
          }
          streamDigest.append(encryptedData)
        }
      }
    }

    // Finalize encryption
    var finalBuffer = Data(count: bufferSize)
    var finalBytesEncrypted: size_t = 0

    finalBuffer.withUnsafeMutableBytes { finalBytes in
      CCCryptorFinal(encryptor, finalBytes.baseAddress!, bufferSize, &finalBytesEncrypted)
    }

    if finalBytesEncrypted > 0 {
      let finalData = finalBuffer.prefix(finalBytesEncrypted)
      outputStream.write(finalData.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) }, maxLength: finalBytesEncrypted)

      finalData.withUnsafeBytes { finalBytes in
        CCHmacUpdate(&hmacContext, finalBytes.baseAddress!, finalBytesEncrypted)
      }
      streamDigest.append(finalData)
    }

    // Generate MAC digest
    var finalMac = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    finalMac.withUnsafeMutableBytes { macBytes in
      CCHmacFinal(&hmacContext, macBytes.baseAddress!)
    }

    // Append finalMac to streamDigest
    streamDigest.append(finalMac)

    // Write the hmacData to encrypted file
    outputStream.write(finalMac.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) }, maxLength: finalMac.count)

    // Do the hashing for the digest
    var digestData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    digestData.withUnsafeMutableBytes { digestBytes in
      streamDigest.withUnsafeBytes { streamBytes in
        CC_SHA256(streamBytes.baseAddress!, CC_LONG(streamDigest.count), digestBytes.baseAddress!.assumingMemoryBound(to: UInt8.self))
      }
    }

    // Create result dictionary
    let auth = toHex(digestData)
    return [
      "auth": auth,
      "paddingSize": NSNumber(value: paddingSize)
    ]
  }

  private static func performFileDecryption(
    hexKey: String,
    iv: String,
    hmacKey: String,
    digest: String,
    inputPath: String,
    outputPath: String,
    paddingSize: UInt,
    completion: @escaping (String) -> Void
  ) {
    DispatchQueue.global(qos: .userInitiated).async {
      var inputStream: InputStream?
      var outputStream: OutputStream?
      var cryptor: CCCryptorRef?

      defer {
        inputStream?.close()
        outputStream?.close()
        if let cryptor = cryptor {
          CCCryptorRelease(cryptor)
        }
      }

      do {
        // Convert hex strings to data
        guard let keyData = fromHex(hexKey),
              let ivData = fromHex(iv),
              let hmacKeyData = fromHex(hmacKey) else {
          throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid input parameters!"])
        }

        // Validate key sizes
        guard keyData.count == 32 else {
          throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key must be 256 bits"])
        }
        guard ivData.count == BLOCK_SIZE else {
          throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "IV must be 128 bits"])
        }
        guard hmacKeyData.count == 32 else {
          throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "HMAC key must be 256 bits"])
        }

        // Validate file existence
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: inputPath) else {
          throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "Input file does not exist."])
        }

        // Open streams
        inputStream = InputStream(fileAtPath: inputPath)
        outputStream = OutputStream(toFileAtPath: outputPath, append: false)
        inputStream?.open()
        outputStream?.open()

        // Check stream readiness
        guard let input = inputStream, let output = outputStream,
              input.streamStatus == .open, output.streamStatus == .open else {
          throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "Stream failure!"])
        }

        // Create the cryptor
        let status = CCCryptorCreate(
          kCCDecrypt,
          kCCAlgorithmAES,
          0, // No padding
          keyData.withUnsafeBytes { $0.baseAddress! },
          keyData.count,
          ivData.withUnsafeBytes { $0.baseAddress! },
          &cryptor
        )

        guard status == kCCSuccess, let decryptor = cryptor else {
          throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create cryptor"])
        }

        // Set up HMAC and SHA-256 contexts
        var hmacContext = CCHmacContext()
        CCHmacInit(&hmacContext, kCCHmacAlgSHA256, hmacKeyData.withUnsafeBytes { $0.baseAddress! }, hmacKeyData.count)

        var sha256Context = CC_SHA256_CTX()
        CC_SHA256_Init(&sha256Context)

        var streamDigest = Data()

        // Read and decrypt data
        let fileSize = getFileSizeAtPath(inputPath)
        var remainingData = Int(fileSize) - Int(CC_SHA256_DIGEST_LENGTH)
        let chunkSize = CHUNK_SIZE
        var buffer = Data(count: chunkSize)

        while remainingData > 0 {
          autoreleasepool {
            let bytesToRead = min(chunkSize, remainingData)
            let bytesRead = buffer.withUnsafeMutableBytes { bufferBytes in
              input.read(bufferBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), maxLength: bytesToRead)
            }

            guard bytesRead > 0 else { return }

            let readData = buffer.prefix(bytesRead)

            // Update HMAC and SHA-256
            readData.withUnsafeBytes { readBytes in
              CCHmacUpdate(&hmacContext, readBytes.baseAddress!, bytesRead)
              CC_SHA256_Update(&sha256Context, readBytes.baseAddress!, CC_LONG(bytesRead))
            }
            streamDigest.append(readData)

            // Decrypt the data
            var decryptedBuffer = Data(count: chunkSize)
            var bytesDecrypted: size_t = 0

            decryptedBuffer.withUnsafeMutableBytes { decryptedBytes in
              readData.withUnsafeBytes { readBytes in
                CCCryptorUpdate(
                  decryptor,
                  readBytes.baseAddress!,
                  bytesRead,
                  decryptedBytes.baseAddress!,
                  chunkSize,
                  &bytesDecrypted
                )
              }
            }

            // Handle last chunk padding
            if remainingData <= chunkSize && paddingSize > 0 {
              let actualLength = bytesDecrypted
              if actualLength > paddingSize {
                let writeLength = actualLength - Int(paddingSize)
                decryptedBuffer.withUnsafeBytes { decryptedBytes in
                  output.write(decryptedBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), maxLength: writeLength)
                }
              }
            } else {
              decryptedBuffer.withUnsafeBytes { decryptedBytes in
                output.write(decryptedBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), maxLength: bytesDecrypted)
              }
            }

            remainingData -= bytesRead
          }
        }

        // Verify MAC and digest
        var ourMac = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        ourMac.withUnsafeMutableBytes { macBytes in
          CCHmacFinal(&hmacContext, macBytes.baseAddress!)
        }

        var theirMac = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        let macBytesRead = theirMac.withUnsafeMutableBytes { macBytes in
          input.read(macBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), maxLength: Int(CC_SHA256_DIGEST_LENGTH))
        }

        guard macBytesRead == Int(CC_SHA256_DIGEST_LENGTH) else {
          throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to read MAC"])
        }

        guard ourMac == theirMac else {
          throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "MAC mismatch!"])
        }

        // Finalize decryption
        var finalBuffer = Data(count: chunkSize)
        var finalBytesDecrypted: size_t = 0

        finalBuffer.withUnsafeMutableBytes { finalBytes in
          CCCryptorFinal(decryptor, finalBytes.baseAddress!, chunkSize, &finalBytesDecrypted)
        }

        if finalBytesDecrypted > 0 {
          finalBuffer.withUnsafeBytes { finalBytes in
            output.write(finalBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), maxLength: finalBytesDecrypted)
          }
        }

        // Success
        completion("Success")

      } catch {
        completion(error.localizedDescription)
      }
    }
  }
}

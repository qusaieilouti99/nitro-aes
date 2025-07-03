import Foundation
import CommonCrypto
import NitroModules

public class NitroAes: HybridNitroAesSpec {
  public override init() {
    super.init()
  }

  private static let BLOCK_SIZE = kCCBlockSizeAES128 // 16
  private static let CHUNK_SIZE = 64 * 1024

  // Pre-compiled regex for hex validation
  private static let hexRegex = try! NSRegularExpression(
    pattern: "^[0-9a-fA-F]+$"
  )

  // Hex lookup tables for faster conversion
  private static let hexChars: [Character] =
    Array("0123456789abcdef")

  // MARK: - PBKDF2
  public func pbkdf2(
    password: String,
    salt: String,
    cost: Double,
    length: Double
  ) throws -> Promise<String> {
    return Promise.async {
      guard !password.isEmpty else {
        throw RuntimeError.error(withMessage:
                                  "Password cannot be empty")
      }
      guard !salt.isEmpty else {
        throw RuntimeError.error(withMessage:
                                  "Salt cannot be empty")
      }
      guard cost > 0 else {
        throw RuntimeError.error(withMessage:
                                  "Cost must be positive")
      }
      guard length > 0 else {
        throw RuntimeError.error(withMessage:
                                  "Length must be positive")
      }

      let pwdData = password.data(using: .utf8)!
      let saltData = salt.data(using: .utf8)!
      var keyData = Data(count: Int(length))
      let keyLen = keyData.count

      let status = pwdData.withUnsafeBytes { pwPtr in
        saltData.withUnsafeBytes { saltPtr in
          keyData.withUnsafeMutableBytes { outPtr in
            CCKeyDerivationPBKDF(
              CCPBKDFAlgorithm(kCCPBKDF2),
              pwPtr.baseAddress!.assumingMemoryBound(
                to: Int8.self
              ),
              pwdData.count,
              saltPtr.baseAddress!.assumingMemoryBound(
                to: UInt8.self
              ),
              saltData.count,
              CCPseudoRandomAlgorithm(
                kCCPRFHmacAlgSHA512
              ),
              UInt32(cost),
              outPtr.baseAddress!.assumingMemoryBound(
                to: UInt8.self
              ),
              keyLen
            )
          }
        }
      }

      guard status == kCCSuccess else {
        throw RuntimeError.error(withMessage:
                                  "PBKDF2 failed")
      }
      return Self.toHex(keyData)
    }
  }

  // MARK: - Text Encryption/Decryption
  public func encrypt(
    text: String,
    key: String,
    iv: String,
    algorithm: Algorithms
  ) throws -> Promise<String> {
    return Promise.async {
      guard !text.isEmpty,
            !key.isEmpty,
            !iv.isEmpty else {
        throw RuntimeError.error(withMessage:
                                  "Invalid input")
      }
      try Self.validateHexString(key, name: "key")
      try Self.validateHexString(iv,  name: "iv")

      guard let out = Self.encryptText(
        clearText: text,
        key: key,
        iv: iv,
        algorithm: algorithm
      ) else {
        throw RuntimeError.error(withMessage:
                                  "Encryption failed")
      }
      return out
    }
  }

  public func decrypt(
    ciphertext: String,
    key: String,
    iv: String,
    algorithm: Algorithms
  ) throws -> Promise<String> {
    return Promise.async {
      guard !ciphertext.isEmpty,
            !key.isEmpty,
            !iv.isEmpty else {
        throw RuntimeError.error(withMessage:
                                  "Invalid input")
      }
      try Self.validateHexString(key, name: "key")
      try Self.validateHexString(iv,  name: "iv")

      guard let out = Self.decryptText(
        cipherText: ciphertext,
        key: key,
        iv: iv,
        algorithm: algorithm
      ) else {
        throw RuntimeError.error(withMessage:
                                  "Decryption failed")
      }
      return out
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
      try Self.validateHexString(key,    name: "key")
      try Self.validateHexString(iv,     name: "iv")
      try Self.validateHexString(hmacKey,name: "hmacKey")

      guard let result = Self.performFileEncryption(
        hexKey:    key,
        iv:        iv,
        hmacKey:   hmacKey,
        inputPath: inputPath,
        outputPath: outputPath
      ),
      let auth = result["auth"] as? String,
      let pad  = result["paddingSize"] as? NSNumber
      else {
        throw RuntimeError.error(withMessage:
                                  "File encryption failed")
      }
      return EncryptFileResult(
        auth: auth,
        paddingSize: pad.doubleValue
      )
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
      try Self.validateHexString(key,    name: "key")
      try Self.validateHexString(iv,     name: "iv")
      try Self.validateHexString(hmacKey,name: "hmacKey")
      try Self.validateHexString(auth,   name: "auth")

      return try await withCheckedThrowingContinuation { cont in
        Self.performFileDecryption(
          hexKey:      key,
          iv:          iv,
          hmacKey:     hmacKey,
          digest:      auth,
          inputPath:   inputPath,
          outputPath:  outputPath,
          paddingSize: UInt(paddingSize)
        ) { result in
          if result == "Success" {
            cont.resume(returning: "OK")
          } else {
            cont.resume(
              throwing: RuntimeError.error(
                withMessage: result
              )
            )
          }
        }
      }
    }
  }

  // MARK: - HMAC
  public func hmac256(
    ciphertext: String,
    key: String
  ) throws -> Promise<String> {
    return Promise.async {
      try Self.validateHexString(key, name: "key")
      return Self.computeHMAC256(input: ciphertext,
                                 key: key)
    }
  }

  public func hmac512(
    ciphertext: String,
    key: String
  ) throws -> Promise<String> {
    return Promise.async {
      try Self.validateHexString(key, name: "key")
      return Self.computeHMAC512(input: ciphertext,
                                 key: key)
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
  public func randomKey(length: Double) throws ->
    Promise<String> {
    return Promise.async {
      let rnd = Self.generateRandomKey(
        length: Int(length)
      )
      guard let key = rnd else {
        throw RuntimeError.error(
          withMessage: "Random key generation failed"
        )
      }
      return key
    }
  }

  // MARK: - Utilities
  private static func validateHexString(
    _ hex: String,
    name: String
  ) throws {
    guard !hex.isEmpty else {
      throw RuntimeError.error(withMessage:
                                "\(name) cannot be empty")
    }
    guard hex.count % 2 == 0 else {
      throw RuntimeError.error(withMessage:
                                "\(name) must have even length")
    }
    let range = NSRange(location: 0,
                        length: hex.utf16.count)
    guard hexRegex.firstMatch(in: hex,
                               options: [],
                               range: range) != nil else {
      throw RuntimeError.error(withMessage:
                                "\(name) contains invalid hex")
    }
  }

  private static func toHex(_ data: Data) -> String {
    var s = ""
    s.reserveCapacity(data.count * 2)
    for b in data {
      s.append(hexChars[Int(b >> 4)])
      s.append(hexChars[Int(b & 0x0F)])
    }
    return s
  }

  private static func fromHex(_ str: String) -> Data? {
    guard !str.isEmpty, str.count % 2 == 0 else {
      return nil
    }
    var d = Data()
    d.reserveCapacity(str.count/2)
    var idx = str.startIndex
    while idx < str.endIndex {
      let nxt = str.index(idx, offsetBy: 2)
      let byteStr = str[idx..<nxt]
      guard let b = UInt8(byteStr, radix: 16) else {
        return nil
      }
      d.append(b)
      idx = nxt
    }
    return d
  }

  private static func getFileSizeAtPath(
    _ path: String
  ) -> UInt {
    let fm = FileManager.default
    guard let attr = try? fm.attributesOfItem(
            atPath: path),
          let size = attr[.size] as? NSNumber
    else { return 0 }
    return size.uintValue
  }

  // MARK: - CBC Core for text
  private static func getAlgorithmKeySize(
    _ alg: Algorithms
  ) -> size_t {
    switch alg {
    case .aes128Cbc: return kCCKeySizeAES128
    case .aes192Cbc: return kCCKeySizeAES192
    case .aes256Cbc: return kCCKeySizeAES256
    }
  }

  private static func performAESCBC(
    operation: String,
    data: Data,
    key: String,
    iv: String,
    algorithm: Algorithms
  ) -> Data? {
    guard let k = fromHex(key),
          let v = fromHex(iv) else {
      return nil
    }
    let keyLen = getAlgorithmKeySize(algorithm)
    guard k.count == keyLen else {
      print("Key must be \(keyLen*8) bits")
      return nil
    }
    guard v.count == BLOCK_SIZE else {
      print("IV must be 128 bits")
      return nil
    }

    var buf = Data(count: data.count+BLOCK_SIZE)
    let bufCount = buf.count // Store count to avoid overlapping access
    var outN: size_t = 0
    let st = k.withUnsafeBytes { kPtr in
      v.withUnsafeBytes { ivPtr in
        data.withUnsafeBytes { dPtr in
          buf.withUnsafeMutableBytes { bPtr in
            CCCrypt(
              operation=="encrypt"
                ? CCOperation(kCCEncrypt)
                : CCOperation(kCCDecrypt),
              CCAlgorithm(kCCAlgorithmAES),
              CCOptions(kCCOptionPKCS7Padding),
              kPtr.baseAddress,
              keyLen,
              ivPtr.baseAddress,
              dPtr.baseAddress,
              data.count,
              bPtr.baseAddress,
              bufCount, // Use local variable instead of buf.count
              &outN
            )
          }
        }
      }
    }
    guard st == kCCSuccess else {
      print("AES error: \(st)")
      return nil
    }
    buf.count = outN
    return buf
  }

  private static func encryptText(
    clearText: String,
    key: String,
    iv: String,
    algorithm: Algorithms
  ) -> String? {
    guard let d = clearText.data(using: .utf8) else {
      return nil
    }
    guard let enc = performAESCBC(
      operation: "encrypt",
      data: d,
      key: key,
      iv: iv,
      algorithm: algorithm
    ) else { return nil }
    return enc.base64EncodedString()
  }

  private static func decryptText(
    cipherText: String,
    key: String,
    iv: String,
    algorithm: Algorithms
  ) -> String? {
    guard let d = Data(base64Encoded: cipherText) else {
      return nil
    }
    guard let dec = performAESCBC(
      operation: "decrypt",
      data: d,
      key: key,
      iv: iv,
      algorithm: algorithm
    ) else { return nil }
    return String(data: dec, encoding: .utf8)
  }

  // MARK: - HMAC & Hash
  private static func computeHMAC256(
    input: String,
    key: String
  ) -> String {
    guard let k = fromHex(key),
          let d = input.data(using: .utf8) else {
      return ""
    }
    var buf = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    _ = buf.withUnsafeMutableBytes { bPtr in
      d.withUnsafeBytes { dPtr in
        k.withUnsafeBytes { kPtr in
          CCHmac(
            CCHmacAlgorithm(kCCHmacAlgSHA256),
            kPtr.baseAddress,
            k.count,
            dPtr.baseAddress,
            d.count,
            bPtr.baseAddress
          )
        }
      }
    }
    return toHex(buf)
  }

  private static func computeHMAC512(
    input: String,
    key: String
  ) -> String {
    guard let k = fromHex(key),
          let d = input.data(using: .utf8) else {
      return ""
    }
    var buf = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
    _ = buf.withUnsafeMutableBytes { bPtr in
      d.withUnsafeBytes { dPtr in
        k.withUnsafeBytes { kPtr in
          CCHmac(
            CCHmacAlgorithm(kCCHmacAlgSHA512),
            kPtr.baseAddress,
            k.count,
            dPtr.baseAddress,
            d.count,
            bPtr.baseAddress
          )
        }
      }
    }
    return toHex(buf)
  }

  private static func computeSHA1(input: String) -> String {
    guard let d = input.data(using: .utf8) else {
      return ""
    }
    var buf = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
    _ = buf.withUnsafeMutableBytes { bPtr in
      d.withUnsafeBytes { dPtr in
        CC_SHA1(dPtr.baseAddress,
                CC_LONG(d.count),
                bPtr.baseAddress!
                  .assumingMemoryBound(to: UInt8.self))
      }
    }
    return toHex(buf)
  }

  private static func computeSHA256(input: String) -> String {
    guard let d = input.data(using: .utf8) else {
      return ""
    }
    var buf = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    _ = buf.withUnsafeMutableBytes { bPtr in
      d.withUnsafeBytes { dPtr in
        CC_SHA256(dPtr.baseAddress,
                  CC_LONG(d.count),
                  bPtr.baseAddress!
                    .assumingMemoryBound(to: UInt8.self))
      }
    }
    return toHex(buf)
  }

  private static func computeSHA512(input: String) -> String {
    guard let d = input.data(using: .utf8) else {
      return ""
    }
    var buf = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
    _ = buf.withUnsafeMutableBytes { bPtr in
      d.withUnsafeBytes { dPtr in
        CC_SHA512(dPtr.baseAddress,
                  CC_LONG(d.count),
                  bPtr.baseAddress!
                    .assumingMemoryBound(to: UInt8.self))
      }
    }
    return toHex(buf)
  }

  private static func generateRandomKey(
    length: Int
  ) -> String? {
    var data = Data(count: length)
    let res = data.withUnsafeMutableBytes {
      SecRandomCopyBytes(kSecRandomDefault,
                         length,
                         $0.baseAddress!)
    }
    guard res == errSecSuccess else { return nil }
    return toHex(data)
  }

  // MARK: - File Encryption
  private static func performFileEncryption(
    hexKey: String,
    iv: String,
    hmacKey: String,
    inputPath: String,
    outputPath: String
  ) -> [String:Any]? {
    let fm = FileManager.default
    guard let kData = fromHex(hexKey),
          let ivData = fromHex(iv),
          let hData = fromHex(hmacKey) else {
      print("Hex conversion failed")
      return nil
    }
    guard kData.count == 32 else {
      print("Key must be 256 bits"); return nil
    }
    guard ivData.count == BLOCK_SIZE else {
      print("IV must be 128 bits"); return nil
    }
    guard hData.count == 32 else {
      print("HMAC key must be 256 bits"); return nil
    }
    guard fm.fileExists(atPath: inputPath) else {
      print("Input file missing"); return nil
    }
    guard let inStream = InputStream(fileAtPath: inputPath),
          let outStream = OutputStream(
            toFileAtPath: outputPath,
            append: false
          ) else {
      print("Stream open failed"); return nil
    }
    inStream.open(); defer{inStream.close()}
    outStream.open(); defer{outStream.close()}

    var cryptorRef: CCCryptorRef?
    let cRes = CCCryptorCreate(
      CCOperation(kCCEncrypt),
      CCAlgorithm(kCCAlgorithmAES),
      CCOptions(0),
      kData.withUnsafeBytes{ $0.baseAddress },
      kData.count,
      ivData.withUnsafeBytes{ $0.baseAddress },
      &cryptorRef
    )
    guard cRes == kCCSuccess,
          let encryptor = cryptorRef else {
      print("Encryptor create error \(cRes)"); return nil
    }
    defer{CCCryptorRelease(encryptor)}

    var hCtx = CCHmacContext()
    CCHmacInit(&hCtx,
               CCHmacAlgorithm(kCCHmacAlgSHA256),
               hData.withUnsafeBytes{ $0.baseAddress },
               hData.count)

    let fileSize = getFileSizeAtPath(inputPath)
    let padSize = Int((UInt(BLOCK_SIZE) -
                   (fileSize % UInt(BLOCK_SIZE))) %
                   UInt(BLOCK_SIZE))
    let chunk = CHUNK_SIZE
    var buf = Data(count: chunk)
    var total: UInt = 0
    var digestBuf = Data()

    while true {
      let read = buf.withUnsafeMutableBytes{ ptr in
        inStream.read(ptr.baseAddress!
                      .assumingMemoryBound(to: UInt8.self),
                      maxLength: chunk)
      }
      guard read > 0 else { break }
      total += UInt(read)
      let isLast = (total == fileSize)

      var chunkData = buf.prefix(read)
      if isLast && padSize > 0 {
        chunkData.append(Data(repeating: UInt8(padSize),
                              count: padSize))
      }

      var encBuf = Data(count: chunkData.count+BLOCK_SIZE)
      let encBufCount = encBuf.count // Store count to avoid overlapping access
      var outLen: size_t = 0
      let uRes = encBuf.withUnsafeMutableBytes{ ePtr in
        chunkData.withUnsafeBytes{ cPtr in
          CCCryptorUpdate(encryptor,
                          cPtr.baseAddress,
                          cPtr.count,
                          ePtr.baseAddress,
                          encBufCount, // Use local variable
                          &outLen)
        }
      }
      guard uRes == kCCSuccess else {
        print("Encrypt update error \(uRes)"); return nil
      }
      let outData = encBuf.prefix(outLen)
      _ = outData.withUnsafeBytes{ ptr in
        outStream.write(ptr.baseAddress!
                        .assumingMemoryBound(to: UInt8.self),
                        maxLength: outData.count)
      }
      CCHmacUpdate(&hCtx,
                   outData.withUnsafeBytes{ $0.baseAddress },
                   outData.count)
      digestBuf.append(outData)
    }

    var finBuf = Data(count: BLOCK_SIZE)
    let finBufCount = finBuf.count // Store count to avoid overlapping access
    var finLen: size_t = 0
    let fRes = finBuf.withUnsafeMutableBytes{ fPtr in
      CCCryptorFinal(encryptor,
                     fPtr.baseAddress,
                     finBufCount, // Use local variable
                     &finLen)
    }
    if fRes==kCCSuccess && finLen>0 {
      let fData = finBuf.prefix(finLen)
      _ = fData.withUnsafeBytes{ ptr in
        outStream.write(ptr.baseAddress!
                        .assumingMemoryBound(
                          to: UInt8.self),
                        maxLength: fData.count)
      }
      CCHmacUpdate(&hCtx,
                   fData.withUnsafeBytes{ $0.baseAddress },
                   fData.count)
      digestBuf.append(fData)
    }

    var macBuf = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    CCHmacFinal(&hCtx,
                macBuf.withUnsafeMutableBytes{ $0.baseAddress })
    _ = macBuf.withUnsafeBytes{ ptr in
      outStream.write(ptr.baseAddress!
                      .assumingMemoryBound(
                        to: UInt8.self),
                      maxLength: ptr.count)
    }
    digestBuf.append(macBuf)

    var authBuf =
      Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    _ = authBuf.withUnsafeMutableBytes{ aPtr in
      digestBuf.withUnsafeBytes{ dPtr in
        CC_SHA256(dPtr.baseAddress,
                  CC_LONG(digestBuf.count),
                  aPtr.baseAddress!
                    .assumingMemoryBound(
                      to: UInt8.self))
      }
    }
    let authHex = toHex(authBuf)
    return [
      "auth": authHex,
      "paddingSize": NSNumber(value: padSize)
    ]
  }

  // MARK: - File Decryption
  private static func performFileDecryption(
    hexKey: String,
    iv: String,
    hmacKey: String,
    digest: String,
    inputPath: String,
    outputPath: String,
    paddingSize: UInt,
    completion: @escaping (String)->Void
  ) {
    DispatchQueue.global(qos: .userInitiated).async {
      var iStream: InputStream?
      var oStream: OutputStream?
      var cryptorRef: CCCryptorRef?

      defer {
        iStream?.close()
        oStream?.close()
        if let r = cryptorRef {
          CCCryptorRelease(r)
        }
      }

      do {
        guard let kData = fromHex(hexKey),
              let ivData = fromHex(iv),
              let hData = fromHex(hmacKey) else {
          throw NSError(domain: "NitroAes",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey:
                                   "Invalid hex params"])
        }
        guard kData.count==32 else {
          throw NSError(domain: "NitroAes",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey:
                                   "Key must be 256 bits"])
        }
        guard ivData.count==BLOCK_SIZE else {
          throw NSError(domain: "NitroAes",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey:
                                   "IV must be 128 bits"])
        }
        guard hData.count==32 else {
          throw NSError(domain: "NitroAes",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey:
                                   "HMAC key must be 256 bits"])
        }
        let fm = FileManager.default
        guard fm.fileExists(atPath: inputPath) else {
          throw NSError(domain: "NitroAes",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey:
                                   "Input file missing"])
        }
        guard let ins = InputStream(fileAtPath: inputPath),
              let ous = OutputStream(
                toFileAtPath: outputPath,
                append: false
              ) else {
          throw NSError(domain: "NitroAes",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey:
                                   "Stream open failed"])
        }
        iStream = ins; oStream = ous
        ins.open(); ous.open()
        guard ins.streamStatus == .open,
              ous.streamStatus == .open else {
          throw NSError(domain: "NitroAes",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey:
                                   "Stream not open"])
        }

        let cRes = CCCryptorCreate(
          CCOperation(kCCDecrypt),
          CCAlgorithm(kCCAlgorithmAES),
          CCOptions(0),
          kData.withUnsafeBytes{ $0.baseAddress },
          kData.count,
          ivData.withUnsafeBytes{ $0.baseAddress },
          &cryptorRef
        )
        guard cRes==kCCSuccess,
              let decryptor=cryptorRef else {
          throw NSError(domain: "NitroAes",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey:
                                   "Decryptor create failed"])
        }

        var hCtx = CCHmacContext()
        CCHmacInit(&hCtx,
                   CCHmacAlgorithm(kCCHmacAlgSHA256),
                   hData.withUnsafeBytes{ $0.baseAddress },
                   hData.count)

        let totalSize = getFileSizeAtPath(inputPath)
        let macLen = Int(CC_SHA256_DIGEST_LENGTH)
        let encLen = Int(totalSize) - macLen
        let chunk = CHUNK_SIZE
        var buf = Data(count: chunk)
        var left = encLen

        while left > 0 {
          let toRead = min(chunk, left)
          let rd = buf.withUnsafeMutableBytes{ ptr in
            ins.read(ptr.baseAddress!
                     .assumingMemoryBound(to: UInt8.self),
                     maxLength: toRead)
          }
          guard rd > 0 else {
            throw NSError(domain: "NitroAes",
                          code: -1,
                          userInfo: [NSLocalizedDescriptionKey:
                                     "Unexpected EOF"])
          }
          left -= rd
          let eChunk = buf.prefix(rd)
          CCHmacUpdate(&hCtx,
                       eChunk.withUnsafeBytes{ $0.baseAddress },
                       eChunk.count)

          var dBuf = Data(count: eChunk.count+BLOCK_SIZE)
          let dBufCount = dBuf.count // Store count to avoid overlapping access
          var outLen: size_t = 0
          let uRes = dBuf.withUnsafeMutableBytes{ dPtr in
            eChunk.withUnsafeBytes{ ePtr in
              CCCryptorUpdate(decryptor,
                              ePtr.baseAddress,
                              ePtr.count,
                              dPtr.baseAddress,
                              dBufCount, // Use local variable
                              &outLen)
            }
          }
          guard uRes==kCCSuccess else {
            throw NSError(domain: "NitroAes",
                          code: -1,
                          userInfo: [NSLocalizedDescriptionKey:
                                     "Decrypt update error"])
          }

          let writeCnt: Int
          if left==0 && paddingSize>0 {
            writeCnt = max(0,
                           outLen - Int(paddingSize))
          } else {
            writeCnt = outLen
          }
          if writeCnt>0 {
            let oData = dBuf.prefix(writeCnt)
            _ = oData.withUnsafeBytes{ ptr in
              ous.write(ptr.baseAddress!
                        .assumingMemoryBound(
                          to: UInt8.self),
                        maxLength: oData.count)
            }
          }
        }

        // Verify HMAC
        var ourMac = Data(
          count: macLen
        )
        CCHmacFinal(&hCtx,
                    ourMac.withUnsafeMutableBytes{ $0.baseAddress })

        var theirMac = Data(count: macLen)
        let mRead = theirMac.withUnsafeMutableBytes{ ptr in
          ins.read(ptr.baseAddress!
                   .assumingMemoryBound(to: UInt8.self),
                   maxLength: macLen)
        }
        guard mRead==macLen,
              ourMac==theirMac else {
          throw NSError(domain: "NitroAes",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey:
                                   "MAC mismatch"])
        }

        // Finalize decryption
        var fBuf = Data(count: BLOCK_SIZE)
        let fBufCount = fBuf.count // Store count to avoid overlapping access
        var fLen: size_t = 0
        let fRes2 = fBuf.withUnsafeMutableBytes{ fPtr in
          CCCryptorFinal(decryptor,
                         fPtr.baseAddress,
                         fBufCount, // Use local variable
                         &fLen)
        }
        if fRes2==kCCSuccess && fLen>0 {
          let data = fBuf.prefix(fLen)
          _ = data.withUnsafeBytes{ ptr in
            ous.write(ptr.baseAddress!
                      .assumingMemoryBound(
                        to: UInt8.self),
                      maxLength: data.count)
          }
        }

        completion("Success")
      } catch {
        completion(error.localizedDescription)
      }
    }
  }
}

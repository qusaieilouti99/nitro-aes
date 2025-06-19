import Foundation
import CommonCrypto
import NitroModules

public class NitroAes: HybridAesNitroSpec {
  public override init() { super.init() }

  // MARK: - Text Encryption / Decryption
  public func encrypt(text: String, key: String, iv: String, algorithm: Algorithms) throws -> Promise<String> {
    return Promise { resolve, reject in
      DispatchQueue.global().async {
        do {
          let keyData = Self.hexToData(key)
          let ivData = Self.hexToData(iv)
          let inputData = text.data(using: .utf8)!
          var outData = Data(count: inputData.count + kCCBlockSizeAES128)
          var outLen: size_t = 0
          let status = outData.withUnsafeMutableBytes { outBytes in
            inputData.withUnsafeBytes { inBytes in
              keyData.withUnsafeBytes { keyBytes in
                ivData.withUnsafeBytes { ivBytes in
                  CCCrypt(
                    CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, keyData.count,
                    ivBytes.baseAddress,
                    inBytes.baseAddress, inputData.count,
                    outBytes.baseAddress, outData.count,
                    &outLen
                  )
                }
              }
            }
          }
          guard status == kCCSuccess else { throw NSError(domain: "NitroAes", code: Int(status), userInfo: nil) }
          outData.count = outLen
          let base64 = outData.base64EncodedString()
          resolve(base64)
        } catch {
          reject(error)
        }
      }
    }
  }

  public func decrypt(ciphertext: String, key: String, iv: String, algorithm: Algorithms) throws -> Promise<String> {
    return Promise { resolve, reject in
      DispatchQueue.global().async {
        do {
          let keyData = Self.hexToData(key)
          let ivData = Self.hexToData(iv)
          let inData = Data(base64Encoded: ciphertext)!
          var outData = Data(count: inData.count)
          var outLen: size_t = 0
          let status = outData.withUnsafeMutableBytes { outBytes in
            inData.withUnsafeBytes { inBytes in
              keyData.withUnsafeBytes { keyBytes in
                ivData.withUnsafeBytes { ivBytes in
                  CCCrypt(
                    CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, keyData.count,
                    ivBytes.baseAddress,
                    inBytes.baseAddress, inData.count,
                    outBytes.baseAddress, outData.count,
                    &outLen
                  )
                }
              }
            }
          }
          guard status == kCCSuccess else { throw NSError(domain: "NitroAes", code: Int(status), userInfo: nil) }
          outData.count = outLen
          let result = String(data: outData, encoding: .utf8)!
          resolve(result)
        } catch {
          reject(error)
        }
      }
    }
  }

  // MARK: - File Encryption
  public func encryptFile(key: String, iv: String, inputPath: String, outputPath: String) throws -> Promise<String> {
    return Promise { resolve, reject in
      DispatchQueue.global().async {
        do {
          let (auth, padding) = try Self.performFileEncryption(
            keyHex: key, ivHex: iv,
            hmacHex: key,
            inputPath: inputPath, outputPath: outputPath
          )
          let dict: [String: Any] = ["auth": auth, "paddingSize": padding]
          let data = try JSONSerialization.data(withJSONObject: dict, options: [])
          resolve(String(data: data, encoding: .utf8)!)
        } catch {
          reject(error)
        }
      }
    }
  }

  public func decryptFile(key: String, iv: String, hmacKey: String, auth: String, inputPath: String, outputPath: String, paddingSize: Double) throws -> Promise<String> {
    return Promise { resolve, reject in
      DispatchQueue.global().async {
        do {
          try Self.performFileDecryption(
            keyHex: key, ivHex: iv,
            hmacHex: hmacKey, theirAuth: auth,
            inputPath: inputPath, outputPath: outputPath,
            paddingSize: Int(paddingSize)
          )
          resolve("OK")
        } catch {
          reject(error)
        }
      }
    }
  }

  // MARK: - HMAC & Hashing & Random
  public func hmac256(ciphertext: String, key: String) throws -> Promise<String> {
    return Promise { res, rej in
      DispatchQueue.global().async {
        do {
          let hex = try Self.computeHMAC(ciphertext: ciphertext, keyHex: key, algorithm: kCCHmacAlgSHA256)
          res(hex)
        } catch { rej(error) }
      }
    }
  }
  public func hmac512(ciphertext: String, key: String) throws -> Promise<String> {
    return Promise { res, rej in
      DispatchQueue.global().async {
        do {
          let hex = try Self.computeHMAC(ciphertext: ciphertext, keyHex: key, algorithm: kCCHmacAlgSHA512)
          res(hex)
        } catch { rej(error) }
      }
    }
  }
  public func randomKey(length: Double) throws -> Promise<String> {
    return Promise { res, rej in
      DispatchQueue.global().async {
        do {
          var data = Data(count: Int(length))
          let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, Int(length), $0.baseAddress!) }
          guard status == errSecSuccess else { throw NSError(domain: "NitroAes", code: Int(status), userInfo: nil) }
          res(Self.dataToHex(data))
        } catch { rej(error) }
      }
    }
  }
  public func sha1(text: String) throws -> Promise<String> {
    return Promise { res, rej in
      DispatchQueue.global().async {
        do { res(try Self.computeSHA(text: text, algorithm: .sha1)) } catch { rej(error) }
      }
    }
  }
  public func sha256(text: String) throws -> Promise<String> {
    return Promise { res, rej in
      DispatchQueue.global().async {
        do { res(try Self.computeSHA(text: text, algorithm: .sha256)) } catch { rej(error) }
      }
    }
  }
  public func sha512(text: String) throws -> Promise<String> {
    return Promise { res, rej in
      DispatchQueue.global().async {
        do { res(try Self.computeSHA(text: text, algorithm: .sha512)) } catch { rej(error) }
      }
    }
  }

  // MARK: - Static Utilities
  private enum SHAAlgorithm { case sha1, sha256, sha512 }

  private static func hexToData(_ hex: String) -> Data {
    var data = Data()
    var tmp = ""
    for c in hex {
      tmp.append(c)
      if tmp.count == 2 {
        data.append(UInt8(tmp, radix: 16)!)
        tmp = ""
      }
    }
    return data
  }

  private static func dataToHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }

  private static func computeHMAC(ciphertext: String, keyHex: String, algorithm: CCHmacAlgorithm) throws -> String {
    let keyData = hexToData(keyHex)
    let data = ciphertext.data(using: .utf8)!
    var mac = Data(count: algorithm == kCCHmacAlgSHA256 ? Int(CC_SHA256_DIGEST_LENGTH) : Int(CC_SHA512_DIGEST_LENGTH))
    mac.withUnsafeMutableBytes { macBytes in
      data.withUnsafeBytes { dataBytes in
        keyData.withUnsafeBytes { keyBytes in
          CCHmac(algorithm, keyBytes.baseAddress, keyData.count, dataBytes.baseAddress, data.count, macBytes.baseAddress)
        }
      }
    }
    return dataToHex(mac)
  }

  private static func computeSHA(text: String, algorithm: SHAAlgorithm) throws -> String {
    let data = text.data(using: .utf8)!
    var digest: Data
    var ctx: Any
    switch algorithm {
    case .sha1:
      ctx = CC_SHA1_CTX()
      CC_SHA1_Init(&ctx as! CC_SHA1_CTX)
    case .sha256:
      ctx = CC_SHA256_CTX()
      CC_SHA256_Init(&ctx as! CC_SHA256_CTX)
    case .sha512:
      ctx = CC_SHA512_CTX()
      CC_SHA512_Init(&ctx as! CC_SHA512_CTX)
    }
    data.withUnsafeBytes {
      switch algorithm {
      case .sha1: CC_SHA1_Update(&ctx as! CC_SHA1_CTX, $0.baseAddress, CC_LONG(data.count))
      case .sha256: CC_SHA256_Update(&ctx as! CC_SHA256_CTX, $0.baseAddress, CC_LONG(data.count))
      case .sha512: CC_SHA512_Update(&ctx as! CC_SHA512_CTX, $0.baseAddress, CC_LONG(data.count))
      }
    }
    switch algorithm {
    case .sha1:
      var out = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
      out.withUnsafeMutableBytes { CC_SHA1_FINAL(&ctx as! CC_SHA1_CTX, $0.baseAddress!.assumingMemoryBound(to: UInt8.self)) }
      return dataToHex(out)
    case .sha256:
      var out = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
      out.withUnsafeMutableBytes { CC_SHA256_FINAL(&ctx as! CC_SHA256_CTX, $0.baseAddress!.assumingMemoryBound(to: UInt8.self)) }
      return dataToHex(out)
    case .sha512:
      var out = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
      out.withUnsafeMutableBytes { CC_SHA512_FINAL(&ctx as! CC_SHA512_CTX, $0.baseAddress!.assumingMemoryBound(to: UInt8.self)) }
      return dataToHex(out)
    }
  }

  private static func performFileEncryption(
    keyHex: String, ivHex: String, hmacHex: String,
    inputPath: String, outputPath: String
  ) throws -> (String, Int) {
    let keyData = hexToData(keyHex)
    let ivData = hexToData(ivHex)
    let hmacKeyData = hexToData(hmacHex)
    let fileURL = URL(fileURLWithPath: inputPath)
    let outURL = URL(fileURLWithPath: outputPath)
    let attrs = try FileManager.default.attributesOfItem(atPath: inputPath)
    let fileSize = attrs[.size] as! UInt64
    let padding = fileSize % UInt64(kCCBlockSizeAES128) == 0 ? 0 : Int(kCCBlockSizeAES128 - (fileSize % UInt64(kCCBlockSizeAES128)))
    FileManager.default.createFile(atPath: outputPath, contents: nil)
    let readHandle = try FileHandle(forReadingFrom: fileURL)
    let writeHandle = try FileHandle(forWritingTo: outURL)
    defer { readHandle.closeFile(); writeHandle.closeFile() }

    var cryptor: CCCryptorRef? = nil
    CCCryptorCreate(
      CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
      keyData.withUnsafeBytes { $0.baseAddress }, keyData.count,
      ivData.withUnsafeBytes { $0.baseAddress }, &cryptor
    )
    var macCtx = CCHmacContext()
    CCHmacInit(&macCtx, CCHmacAlgorithm(kCCHmacAlgSHA256), hmacKeyData.withUnsafeBytes { $0.baseAddress }, hmacKeyData.count)
    var shaCtx = CC_SHA256_CTX()
    CC_SHA256_Init(&shaCtx)

    let chunkSize = kCCBlockSizeAES128 * 4 * 1024
    while true {
      let chunk = readHandle.readData(ofLength: chunkSize)
      if chunk.isEmpty { break }
      var block = chunk
      if readHandle.offsetInFile == fileSize && padding > 0 {
        block.append(Data(repeating: UInt8(padding), count: padding))
      }
      let outLenMax = CCCryptorGetOutputLength(cryptor, block.count, false)
      var outData = Data(count: outLenMax)
      var outLen: size_t = 0
      CCCryptorUpdate(
        cryptor,
        block.withUnsafeBytes { $0.baseAddress }, block.count,
        outData.withUnsafeMutableBytes { $0.baseAddress }, outData.count,
        &outLen
      )
      outData.count = outLen
      CCHmacUpdate(&macCtx, outData.withUnsafeBytes { $0.baseAddress }, outData.count)
      CC_SHA256_Update(&shaCtx, outData.withUnsafeBytes { $0.baseAddress }, CC_LONG(outData.count))
      writeHandle.write(outData)
    }

    var finalLen: size_t = 0
    let finalMax = CCCryptorGetOutputLength(cryptor, 0, true)
    var finalData = Data(count: finalMax)
    CCCryptorFinal(
      cryptor,
      finalData.withUnsafeMutableBytes { $0.baseAddress }, finalData.count,
      &finalLen
    )
    finalData.count = finalLen
    CCHmacUpdate(&macCtx, finalData.withUnsafeBytes { $0.baseAddress }, finalData.count)
    CC_SHA256_Update(&shaCtx, finalData.withUnsafeBytes { $0.baseAddress }, CC_LONG(finalData.count))
    writeHandle.write(finalData)

    var hmacOut = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    hmacOut.withUnsafeMutableBytes { CCHmacFinal(&macCtx, $0.baseAddress) }
    CC_SHA256_Update(&shaCtx, hmacOut.withUnsafeBytes { $0.baseAddress }, CC_LONG(hmacOut.count))
    writeHandle.write(hmacOut)

    var authOut = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    authOut.withUnsafeMutableBytes { CC_SHA256_Final($0.baseAddress!.assumingMemoryBound(to: UInt8.self), &shaCtx) }
    let authHex = authOut.map { String(format: "%02x", $0) }.joined()

    CCCryptorRelease(cryptor)
    return (authHex, padding)
  }

  private static func performFileDecryption(
    keyHex: String, ivHex: String, hmacHex: String, theirAuth: String,
    inputPath: String, outputPath: String, paddingSize: Int
  ) throws {
    let keyData = hexToData(keyHex)
    let ivData = hexToData(ivHex)
    let hmacKeyData = hexToData(hmacHex)
    let fileURL = URL(fileURLWithPath: inputPath)
    let outURL = URL(fileURLWithPath: outputPath)
    let fileSize = try FileManager.default.attributesOfItem(atPath: inputPath)[.size] as! UInt64
    let macLen = Int(CC_SHA256_DIGEST_LENGTH)
    let encLen = Int(fileSize) - macLen
    FileManager.default.createFile(atPath: outputPath, contents: nil)
    let readHandle = try FileHandle(forReadingFrom: fileURL)
    let writeHandle = try FileHandle(forWritingTo: outURL)
    defer { readHandle.closeFile(); writeHandle.closeFile() }

    var cryptor: CCCryptorRef? = nil
    CCCryptorCreate(
      CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
      keyData.withUnsafeBytes { $0.baseAddress }, keyData.count,
      ivData.withUnsafeBytes { $0.baseAddress }, &cryptor
    )
    var macCtx = CCHmacContext()
    CCHmacInit(&macCtx, CCHmacAlgorithm(kCCHmacAlgSHA256), hmacKeyData.withUnsafeBytes { $0.baseAddress }, hmacKeyData.count)
    var shaCtx = CC_SHA256_CTX()
    CC_SHA256_Init(&shaCtx)

    var remaining = encLen
    let chunkSize = kCCBlockSizeAES128 * 4 * 1024
    while remaining > 0 {
      let size = min(remaining, chunkSize)
      let chunk = readHandle.readData(ofLength: size)
      CCHmacUpdate(&macCtx, chunk.withUnsafeBytes { $0.baseAddress }, chunk.count)
      CC_SHA256_Update(&shaCtx, chunk.withUnsafeBytes { $0.baseAddress }, CC_LONG(chunk.count))
      var outData = Data(count: CCCryptorGetOutputLength(cryptor, chunk.count, false))
      var outLen: size_t = 0
      CCCryptorUpdate(
        cryptor,
        chunk.withUnsafeBytes { $0.baseAddress }, chunk.count,
        outData.withUnsafeMutableBytes { $0.baseAddress }, outData.count,
        &outLen
      )
      outData.count = outLen
      if remaining <= chunkSize {
        writeHandle.write(outData.prefix(outData.count - paddingSize))
      } else {
        writeHandle.write(outData)
      }
      remaining -= chunk.count
    }

    var ourHmac = Data(count: macLen)
    ourHmac.withUnsafeMutableBytes { CCHmacFinal(&macCtx, $0.baseAddress) }
    let theirHmac = readHandle.readData(ofLength: macLen)
    guard ourHmac == theirHmac else { throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "HMAC mismatch"]) }
    CC_SHA256_Update(&shaCtx, theirHmac.withUnsafeBytes { $0.baseAddress }, CC_LONG(theirHmac.count))
    var authOut = Data(count: macLen)
    authOut.withUnsafeMutableBytes { CC_SHA256_Final($0.baseAddress!.assumingMemoryBound(to: UInt8.self), &shaCtx) }
    let authHex = authOut.map { String(format: "%02x", $0) }.joined()
    guard authHex == theirAuth else { throw NSError(domain: "NitroAes", code: -1, userInfo: [NSLocalizedDescriptionKey: "Auth mismatch"]) }

    var finalData = Data(count: CCCryptorGetOutputLength(cryptor, 0, true))
    var finalLen: size_t = 0
    CCCryptorFinal(
      cryptor,
      finalData.withUnsafeMutableBytes { $0.baseAddress }, finalData.count,
      &finalLen
    )
    if finalLen > 0 {
      writeHandle.write(finalData.prefix(finalLen))
    }
    CCCryptorRelease(cryptor)
  }
}

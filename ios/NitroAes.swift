import Foundation
import CommonCrypto
import NitroModules

public class NitroAes: HybridAesNitroSpec {
  public override init() { super.init() }

  public func pbkdf2(password: String, salt: String, cost: Double, length: Double) throws -> Promise<String> {
    return Promise { resolve, reject in
      DispatchQueue.global().async {
        let saltData = Data(salt.utf8)
        var derived = Data(count: Int(length))
        let status = derived.withUnsafeMutableBytes { derivedBytes in
          CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            password, password.utf8.count,
            saltData.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) }, saltData.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
            UInt32(cost),
            derivedBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
            Int(length)
          )
        }
        if status == kCCSuccess {
          resolve(Self.dataToHex(derived))
        } else {
          reject(NSError(domain: "NitroAes", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "PBKDF2 failed"]))
        }
      }
    }
  }

  // MARK: - Text Encryption / Decryption
  public func encrypt(text: String, key: String, iv: String, algorithm: Algorithms) throws -> Promise<String> {
    return Promise { resolve, reject in
      DispatchQueue.global().async {
        do {
          let encrypted = try Self.encryptText(text: text, keyHex: key, ivHex: iv)
          resolve(encrypted)
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
          let decrypted = try Self.decryptText(cipher: ciphertext, keyHex: key, ivHex: iv)
          resolve(decrypted)
        } catch {
          reject(error)
        }
      }
    }
  }

  // MARK: - File Encryption
  public func encryptFile(key: String, iv: String, hmacKey: String, inputPath: String, outputPath: String) throws -> Promise<String> {
    return Promise { resolve, reject in
      DispatchQueue.global().async {
        do {
          let (auth, padding) = try Self.performFileEncryption(
            keyHex: key,
            ivHex: iv,
            hmacHex: hmacKey,
            inputPath: inputPath,
            outputPath: outputPath
          )
          let result: [String: Any] = ["auth": auth, "paddingSize": padding]
          let data = try JSONSerialization.data(withJSONObject: result, options: [])
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
            keyHex: key,
            ivHex: iv,
            hmacHex: hmacKey,
            theirAuth: auth,
            inputPath: inputPath,
            outputPath: outputPath,
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
    return Promise { resolve, reject in
      DispatchQueue.global().async {
        let hex = Self.computeHMAC(data: ciphertext, keyHex: key, algorithm: kCCHmacAlgSHA256)
        resolve(hex)
      }
    }
  }
  public func hmac512(ciphertext: String, key: String) throws -> Promise<String> {
    return Promise { resolve, reject in
      DispatchQueue.global().async {
        let hex = Self.computeHMAC(data: ciphertext, keyHex: key, algorithm: kCCHmacAlgSHA512)
        resolve(hex)
      }
    }
  }
  public func randomKey(length: Double) throws -> Promise<String> {
    return Promise { resolve, reject in
      DispatchQueue.global().async {
        var data = Data(count: Int(length))
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, Int(length), $0.baseAddress!) }
        if status == errSecSuccess {
          resolve(Self.dataToHex(data))
        } else {
          reject(NSError(domain: "NitroAes", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Random key failed"]))
        }
      }
    }
  }
  public func sha1(text: String) throws -> Promise<String> { return Promise { $0.resolve(try! Self.computeSHA(text: text, algorithm: .sha1)) } }
  public func sha256(text: String) throws -> Promise<String> { return Promise { $0.resolve(try! Self.computeSHA(text: text, algorithm: .sha256)) } }
  public func sha512(text: String) throws -> Promise<String> { return Promise { $0.resolve(try! Self.computeSHA(text: text, algorithm: .sha512)) } }

  // MARK: - Utilities
  private static func hexToData(_ hex: String) -> Data {
    var data = Data(); var tmp = ""
    for c in hex { tmp.append(c); if tmp.count == 2 { data.append(UInt8(tmp, radix: 16)!); tmp = "" } }
    return data
  }
  private static func dataToHex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

  private static func encryptText(text: String, keyHex: String, ivHex: String) throws -> String {
    let key = hexToData(keyHex), iv = ivHex.isEmpty ? Data(repeating: 0, count: kCCBlockSizeAES128) : hexToData(ivHex)
    let input = text.data(using: .utf8)!, bufSize = input.count + kCCBlockSizeAES128
    var buf = Data(count: bufSize), outLen: size_t = 0
    let status = buf.withUnsafeMutableBytes { bufBytes in
      input.withUnsafeBytes { inBytes in
        key.withUnsafeBytes { keyBytes in
          iv.withUnsafeBytes { ivBytes in
            CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                    inBytes.baseAddress, input.count,
                    bufBytes.baseAddress, bufSize, &outLen)
          }
        }
      }
    }
    guard status == kCCSuccess else { throw NSError(domain: "NitroAes", code: Int(status), userInfo: nil) }
    buf.count = outLen; return buf.base64EncodedString()
  }

  private static func decryptText(cipher: String, keyHex: String, ivHex: String) throws -> String {
    let key = hexToData(keyHex), iv = ivHex.isEmpty ? Data(repeating: 0, count: kCCBlockSizeAES128) : hexToData(ivHex)
    let input = Data(base64Encoded: cipher)!, bufSize = input.count, var buf = Data(count: bufSize), outLen: size_t = 0
    let status = buf.withUnsafeMutableBytes { bufBytes in
      input.withUnsafeBytes { inBytes in
        key.withUnsafeBytes { keyBytes in
          iv.withUnsafeBytes { ivBytes in
            CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                    inBytes.baseAddress, input.count,
                    bufBytes.baseAddress, bufSize, &outLen)
          }
        }
      }
    }
    guard status == kCCSuccess else { throw NSError(domain: "NitroAes", code: Int(status), userInfo: nil) }
    buf.count = outLen; return String(data: buf, encoding: .utf8)!  }

  private static func computeHMAC(data: String, keyHex: String, algorithm: CCHmacAlgorithm) -> String {
    let key = hexToData(keyHex), msg = data.data(using: .utf8)!
    var mac = Data(count: algorithm==kCCHmacAlgSHA256 ? Int(CC_SHA256_DIGEST_LENGTH) : Int(CC_SHA512_DIGEST_LENGTH))
    mac.withUnsafeMutableBytes { macBytes in
      msg.withUnsafeBytes { msgBytes in
        key.withUnsafeBytes { keyBytes in
          CCHmac(algorithm, keyBytes.baseAddress, key.count, msgBytes.baseAddress, msg.count, macBytes.baseAddress)
        }
      }
    }
    return dataToHex(mac) }

  private enum SHAAlg { case sha1, sha256, sha512 }
  private static func computeSHA(text: String, algorithm: SHAAlg) throws -> String {
    let data = text.data(using: .utf8)!, len = data.count
    var out: Data; switch algorithm {
    case .sha1: out = Data(count: Int(CC_SHA1_DIGEST_LENGTH)); withUnsafeMutablePointer(to: &out) { ptr in CC_SHA1(data.withUnsafeBytes { $0.baseAddress }, CC_LONG(len), ptr.pointee) }
    case .sha256: out = Data(count: Int(CC_SHA256_DIGEST_LENGTH)); withUnsafeMutablePointer(to: &out) { ptr in CC_SHA256(data.withUnsafeBytes { $0.baseAddress }, CC_LONG(len), ptr.pointee) }
    case .sha512: out = Data(count: Int(CC_SHA512_DIGEST_LENGTH)); withUnsafeMutablePointer(to: &out) { ptr in CC_SHA512(data.withUnsafeBytes { $0.baseAddress }, CC_LONG(len), ptr.pointee) }
    }
    return dataToHex(out)
  }
}

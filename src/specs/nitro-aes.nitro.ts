import type { HybridObject } from 'react-native-nitro-modules'

type Algorithms = 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc'
interface EncryptFileResult {
  auth: string
  paddingSize: number
}
export interface NitroAes
  extends HybridObject<{ ios: 'swift'; android: 'kotlin' }> {
  pbkdf2(
    password: string,
    salt: string,
    cost: number,
    length: number
  ): Promise<string>
  encrypt(
    text: string,
    key: string,
    iv: string,
    algorithm: Algorithms
  ): Promise<string>
  decrypt(
    ciphertext: string,
    key: string,
    iv: string,
    algorithm: Algorithms
  ): Promise<string>
  encryptFile(
    key: string,
    iv: string,
    hmacKey: string,
    inputPath: string,
    outputPath: string
  ): Promise<EncryptFileResult>
  decryptFile(
    key: string,
    iv: string,
    hmacKey: string,
    auth: string,
    inputPath: string,
    outputPath: string,
    paddingSize: number
  ): Promise<string>
  hmac256(ciphertext: string, key: string): Promise<string>
  hmac512(ciphertext: string, key: string): Promise<string>
  randomKey(length: number): Promise<string>
  sha1(text: string): Promise<string>
  sha256(text: string): Promise<string>
  sha512(text: string): Promise<string>
}

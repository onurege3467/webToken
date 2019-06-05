/**
 * AES-256-GCM encryption/decryption implementation
 * Used for v1.local mode - symmetric encryption with authentication
 */

import { webcrypto } from 'node:crypto'

const crypto = webcrypto as unknown as Crypto

const AES_KEY_SIZE = 32 // 256 bits
const AES_IV_SIZE = 12 // 96 bits for GCM
const AES_TAG_SIZE = 16 // 128 bits
const AES_ALGORITHM = 'AES-GCM'

export class AES256GCM {
  /**
   * Generate a new 256-bit key
   */
  static async generateKey(): Promise<Buffer> {
    const key = await crypto.subtle.generateKey(
      {
        name: AES_ALGORITHM,
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    ) as CryptoKey
    
    const exported = await crypto.subtle.exportKey('raw', key)
    return Buffer.from(exported as ArrayBuffer)
  }

  /**
   * Import key from buffer
   */
  private static async importKey(keyBuffer: Buffer): Promise<CryptoKey> {
    if (keyBuffer.length !== AES_KEY_SIZE) {
      throw new Error(`Invalid key size: expected ${AES_KEY_SIZE} bytes, got ${keyBuffer.length}`)
    }
    
    return await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      {
        name: AES_ALGORITHM,
        length: 256,
      },
      false,
      ['encrypt', 'decrypt']
    ) as CryptoKey
  }

  /**
   * Encrypt data with AES-256-GCM
   * Format: [iv (12 bytes)] [ciphertext] [tag (16 bytes)]
   */
  static async encrypt(plaintext: Buffer, key: Buffer, aad?: Buffer): Promise<Buffer> {
    const iv = crypto.getRandomValues(new Uint8Array(AES_IV_SIZE))
    const cryptoKey = await this.importKey(key)
    
    const encrypted = await crypto.subtle.encrypt(
      {
        name: AES_ALGORITHM,
        iv,
        additionalData: aad,
        tagLength: AES_TAG_SIZE * 8,
      },
      cryptoKey,
      plaintext
    )
    
    // Combine IV + ciphertext + tag
    const result = Buffer.allocUnsafe(AES_IV_SIZE + encrypted.byteLength)
    result.set(iv, 0)
    result.set(new Uint8Array(encrypted), AES_IV_SIZE)
    
    return result
  }

  /**
   * Decrypt data with AES-256-GCM
   * Format: [iv (12 bytes)] [ciphertext] [tag (16 bytes)]
   */
  static async decrypt(ciphertext: Buffer, key: Buffer, aad?: Buffer): Promise<Buffer> {
    if (ciphertext.length < AES_IV_SIZE + AES_TAG_SIZE) {
      throw new Error('Ciphertext too short')
    }
    
    const iv = ciphertext.subarray(0, AES_IV_SIZE)
    const encrypted = ciphertext.subarray(AES_IV_SIZE)
    const cryptoKey = await this.importKey(key)
    
    try {
      const decrypted = await crypto.subtle.decrypt(
        {
          name: AES_ALGORITHM,
          iv,
          additionalData: aad,
          tagLength: AES_TAG_SIZE * 8,
        },
        cryptoKey,
        encrypted
      )
      
      return Buffer.from(decrypted as ArrayBuffer)
    } catch (error) {
      throw new Error('Decryption failed: invalid key or corrupted data')
    }
  }

  /**
   * Derive key from password using PBKDF2
   */
  static async deriveKey(password: string, salt: Buffer, iterations: number = 100000): Promise<Buffer> {
    const encoder = new TextEncoder()
    const passwordBuffer = encoder.encode(password)
    
    const baseKey = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    ) as CryptoKey
    
    const derived = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: 'SHA-256',
      },
      baseKey,
      256
    )
    
    return Buffer.from(derived as ArrayBuffer)
  }
}

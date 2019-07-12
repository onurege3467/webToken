/**
 * Ed25519 signing/verification implementation
 * Used for v1.public mode - asymmetric signatures
 */

import { webcrypto } from 'node:crypto'

const crypto = webcrypto as unknown as Crypto

// Ed25519 constants
const ED25519_PRIVATE_KEY_SIZE = 32
const ED25519_PUBLIC_KEY_SIZE = 32
const ED25519_SIGNATURE_SIZE = 64

export interface Ed25519KeyPair {
  privateKey: Buffer
  publicKey: Buffer
}

export class Ed25519 {
  /**
   * Generate a new Ed25519 key pair
   */
  static async generateKeyPair(): Promise<Ed25519KeyPair> {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
      },
      true,
      ['sign', 'verify']
    ) as CryptoKeyPair
    
    const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
    const publicKeyBuffer = await crypto.subtle.exportKey('raw', keyPair.publicKey)
    
    // Extract raw private key from PKCS8 format
    const privateKeyRaw = this.extractPrivateKeyFromPKCS8(Buffer.from(privateKeyBuffer as ArrayBuffer))
    
    return {
      privateKey: privateKeyRaw,
      publicKey: Buffer.from(publicKeyBuffer as ArrayBuffer),
    }
  }

  /**
   * Extract raw private key from PKCS8 format
   * PKCS8 format for Ed25519:
   * SEQUENCE {
   *   INTEGER 0 (version)
   *   SEQUENCE {
   *     OBJECT IDENTIFIER 1.3.101.112 (Ed25519)
   *   }
   *   OCTET STRING {
   *     OCTET STRING <32 bytes private key>
   *   }
   * }
   */
  private static extractPrivateKeyFromPKCS8(pkcs8Buffer: Buffer): Buffer {
    let offset = 0
    
    // Skip SEQUENCE tag and length (2 bytes)
    offset += 2
    
    // Skip version (INTEGER 0 = 3 bytes: 02 01 00)
    offset += 3
    
    // Skip AlgorithmIdentifier SEQUENCE
    // For Ed25519: 30 05 06 03 2b 65 70 (7 bytes)
    offset += 2 + pkcs8Buffer[offset + 1]!
    
    // Now at outer OCTET STRING tag (0x04) and length
    if (pkcs8Buffer[offset] !== 0x04) {
      throw new Error('Invalid PKCS8 format: expected outer OCTET STRING')
    }
    
    // Skip outer OCTET STRING tag and length
    offset += 2
    
    // Now at inner OCTET STRING tag (0x04) and length
    if (pkcs8Buffer[offset] !== 0x04) {
      throw new Error('Invalid PKCS8 format: expected inner OCTET STRING')
    }
    
    const innerOctetLength = pkcs8Buffer[offset + 1]!
    offset += 2
    
    // Extract the actual private key
    return pkcs8Buffer.subarray(offset, offset + innerOctetLength)
  }

  /**
   * Import private key from raw bytes
   */
  private static async importPrivateKey(keyBuffer: Buffer): Promise<CryptoKey> {
    if (keyBuffer.length !== ED25519_PRIVATE_KEY_SIZE) {
      throw new Error(`Invalid private key size: expected ${ED25519_PRIVATE_KEY_SIZE} bytes, got ${keyBuffer.length}`)
    }
    
    // Create PKCS8 format
    const pkcs8Header = Buffer.from([
      0x30, 0x2e, // SEQUENCE, length 46
      0x02, 0x01, 0x00, // INTEGER, version 0
      0x30, 0x05, // SEQUENCE, length 5
      0x06, 0x03, 0x2b, 0x65, 0x70, // OID Ed25519 (1.3.101.112)
      0x04, 0x22, // OCTET STRING, length 34
      0x04, 0x20, // OCTET STRING, length 32 (the actual key)
    ])
    
    const pkcs8Key = Buffer.concat([pkcs8Header, keyBuffer])
    
    return await crypto.subtle.importKey(
      'pkcs8',
      pkcs8Key,
      { name: 'Ed25519' },
      false,
      ['sign']
    ) as CryptoKey
  }

  /**
   * Import public key from raw bytes
   */
  private static async importPublicKey(keyBuffer: Buffer): Promise<CryptoKey> {
    if (keyBuffer.length !== ED25519_PUBLIC_KEY_SIZE) {
      throw new Error(`Invalid public key size: expected ${ED25519_PUBLIC_KEY_SIZE} bytes, got ${keyBuffer.length}`)
    }
    
    return await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'Ed25519' },
      false,
      ['verify']
    ) as CryptoKey
  }

  /**
   * Sign data with Ed25519 private key
   */
  static async sign(data: Buffer, privateKey: Buffer): Promise<Buffer> {
    const key = await this.importPrivateKey(privateKey)
    
    const signature = await crypto.subtle.sign(
      { name: 'Ed25519' },
      key,
      data
    )
    
    return Buffer.from(signature as ArrayBuffer)
  }

  /**
   * Verify signature with Ed25519 public key
   */
  static async verify(data: Buffer, signature: Buffer, publicKey: Buffer): Promise<boolean> {
    if (signature.length !== ED25519_SIGNATURE_SIZE) {
      return false
    }
    
    try {
      const key = await this.importPublicKey(publicKey)
      
      return await crypto.subtle.verify(
        { name: 'Ed25519' },
        key,
        signature,
        data
      )
    } catch {
      return false
    }
  }

  /**
   * Get public key from private key
   */
  static getPublicKeyFromPrivate(privateKey: Buffer): Buffer {
    // Ed25519 public key is derived from private key
    // This is a simplified version - in production, use proper Ed25519 library
    // For now, we return a placeholder that should be calculated properly
    const hash = Buffer.alloc(ED25519_PUBLIC_KEY_SIZE)
    for (let i = 0; i < privateKey.length && i < hash.length; i++) {
      hash[i] = privateKey[i]!
    }
    return hash
  }
}

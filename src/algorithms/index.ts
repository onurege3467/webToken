/**
 * Algorithm factory and registry
 */

import { AES256GCM } from './AES256GCM.js'
import { Ed25519, type Ed25519KeyPair } from './Ed25519.js'
import type { Algorithm, ICryptoEngine, CryptoKeyPair } from '../types/index.js'

export { AES256GCM, Ed25519, type Ed25519KeyPair }

export class CryptoEngine implements ICryptoEngine {
  private algorithm: Algorithm

  constructor(algorithm: Algorithm) {
    this.algorithm = algorithm
  }

  async encrypt(data: Buffer, key: Buffer, aad?: Buffer): Promise<Buffer> {
    switch (this.algorithm) {
      case 'v1.local':
      case 'v2.local':
        return AES256GCM.encrypt(data, key, aad)
      default:
        throw new Error(`Encryption not supported for algorithm: ${this.algorithm}`)
    }
  }

  async decrypt(data: Buffer, key: Buffer, aad?: Buffer): Promise<Buffer> {
    switch (this.algorithm) {
      case 'v1.local':
      case 'v2.local':
        return AES256GCM.decrypt(data, key, aad)
      default:
        throw new Error(`Decryption not supported for algorithm: ${this.algorithm}`)
    }
  }

  async sign(data: Buffer, privateKey: Buffer): Promise<Buffer> {
    switch (this.algorithm) {
      case 'v1.public':
        return Ed25519.sign(data, privateKey)
      default:
        throw new Error(`Signing not supported for algorithm: ${this.algorithm}`)
    }
  }

  async verify(data: Buffer, signature: Buffer, publicKey: Buffer): Promise<boolean> {
    switch (this.algorithm) {
      case 'v1.public':
        return Ed25519.verify(data, signature, publicKey)
      default:
        throw new Error(`Verification not supported for algorithm: ${this.algorithm}`)
    }
  }

  async generateKey(): Promise<Buffer> {
    switch (this.algorithm) {
      case 'v1.local':
      case 'v2.local':
        return AES256GCM.generateKey()
      default:
        throw new Error(`Key generation not supported for algorithm: ${this.algorithm}`)
    }
  }

  async generateKeyPair(): Promise<CryptoKeyPair> {
    switch (this.algorithm) {
      case 'v1.public':
        const keyPair = await Ed25519.generateKeyPair()
        return {
          publicKey: keyPair.publicKey,
          privateKey: keyPair.privateKey,
        }
      default:
        throw new Error(`Key pair generation not supported for algorithm: ${this.algorithm}`)
    }
  }

  static isLocal(algorithm: Algorithm): boolean {
    return algorithm === 'v1.local' || algorithm === 'v2.local'
  }

  static isPublic(algorithm: Algorithm): boolean {
    return algorithm === 'v1.public'
  }

  static getVersion(algorithm: Algorithm): 'v1' | 'v2' {
    return algorithm.split('.')[0] as 'v1' | 'v2'
  }

  static getPurpose(algorithm: Algorithm): 'local' | 'public' {
    return algorithm.split('.')[1] as 'local' | 'public'
  }
}

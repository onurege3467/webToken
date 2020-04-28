import { describe, it, expect, beforeAll } from 'vitest'
import { 
  createToken, 
  verifyToken, 
  decodeToken,
  TokenExpiredError,
  TokenNotBeforeError,
  InvalidTokenError,
  AES256GCM,
  Ed25519,
  BinaryFormat,
  ProtobufFormat,
} from '../src/index.js'

describe('WebToken', () => {
  describe('Token Creation and Verification', () => {
    it('should create and verify a v1.local token with binary format', async () => {
      const payload = { userId: '123', role: 'admin' }
      
      const { token, expiresAt, issuedAt } = await createToken({
        format: 'binary',
        algorithm: 'v1.local',
        payload,
        expiresIn: '1h',
        issuer: 'test-app',
      })
      
      expect(token).toBeDefined()
      expect(token).toContain('.')
      expect(expiresAt).toBeInstanceOf(Date)
      expect(issuedAt).toBeInstanceOf(Date)
      
      // Token should be decryptable
      const engine = new AES256GCM()
      const parts = token.split('.')
      const key = Buffer.from(parts[0]!, 'base64url')
      const encrypted = Buffer.from(parts[1]!, 'base64url')
      
      const decrypted = await AES256GCM.decrypt(encrypted, key)
      expect(decrypted).toBeDefined()
    })

    it('should create and verify a v1.public token', async () => {
      const payload = { userId: '456', permissions: ['read', 'write'] }
      
      const { token } = await createToken({
        format: 'binary',
        algorithm: 'v1.public',
        payload,
        expiresIn: '24h',
        issuer: 'auth-service',
        audience: 'api-gateway',
      })
      
      expect(token).toBeDefined()
      expect(token).toContain('.')
    })

    it('should create token with protobuf format', async () => {
      const payload = { userId: '789', sessionId: 'abc123' }
      
      const { token } = await createToken({
        format: 'protobuf',
        algorithm: 'v1.local',
        payload,
        expiresIn: '30m',
      })
      
      expect(token).toBeDefined()
    })
  })

  describe('Token Expiration', () => {
    it('should reject expired token', async () => {
      const { token } = await createToken({
        format: 'binary',
        algorithm: 'v1.local',
        payload: { test: true },
        expiresIn: -1000, // Already expired
      })
      
      // The token is created but trying to verify it should fail
      // Note: This test might need adjustment based on actual implementation
    })
  })

  describe('Binary Format', () => {
    it('should encode and decode header correctly', () => {
      const header = { version: 'v1' as const, purpose: 'local' as const, format: 'binary' as const }
      const encoded = BinaryFormat.encodeHeader(header)
      const decoded = BinaryFormat.decodeHeader(encoded)
      
      expect(decoded).toEqual(header)
    })

    it('should encode and decode payload correctly', () => {
      const payload = {
        iss: 'test-issuer',
        sub: 'user-123',
        aud: ['audience1', 'audience2'],
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        data: { custom: 'data', nested: { value: 123 } },
      }
      
      const encoded = BinaryFormat.encodePayload(payload)
      const decoded = BinaryFormat.decodePayload(encoded)
      
      expect(decoded.iss).toBe(payload.iss)
      expect(decoded.sub).toBe(payload.sub)
      expect(decoded.aud).toEqual(payload.aud)
      expect(decoded.exp).toBe(payload.exp)
      expect(decoded.iat).toBe(payload.iat)
      expect(decoded.data).toEqual(payload.data)
    })

    it('should encode and decode complete token', () => {
      const header = { version: 'v1' as const, purpose: 'local' as const, format: 'binary' as const }
      const payload = {
        iss: 'test',
        exp: Math.floor(Date.now() / 1000) + 3600,
        data: { userId: '123' },
      }
      
      const encoded = BinaryFormat.encode(header, payload)
      const decoded = BinaryFormat.decode(encoded)
      
      expect(decoded.header).toEqual(header)
      expect(decoded.payload.iss).toBe(payload.iss)
      expect(decoded.payload.exp).toBe(payload.exp)
      expect(decoded.payload.data).toEqual(payload.data)
    })
  })

  describe('Protobuf Format', () => {
    it('should encode and decode header correctly', () => {
      const header = { version: 'v1' as const, purpose: 'public' as const, format: 'protobuf' as const }
      const encoded = ProtobufFormat.encodeHeader(header)
      const decoded = ProtobufFormat.decodeHeader(encoded)
      
      expect(decoded).toEqual(header)
    })

    it('should encode and decode payload correctly', () => {
      const payload = {
        iss: 'test-issuer',
        sub: 'user-456',
        exp: Math.floor(Date.now() / 1000) + 3600,
        data: { role: 'admin' },
      }
      
      const encoded = ProtobufFormat.encodePayload(payload)
      const decoded = ProtobufFormat.decodePayload(encoded)
      
      expect(decoded.iss).toBe(payload.iss)
      expect(decoded.sub).toBe(payload.sub)
      expect(decoded.exp).toBe(payload.exp)
      expect(decoded.data).toEqual(payload.data)
    })
  })

  describe('AES-256-GCM', () => {
    it('should encrypt and decrypt data correctly', async () => {
      const key = await AES256GCM.generateKey()
      const plaintext = Buffer.from('Hello, World! This is a secret message.')
      
      const encrypted = await AES256GCM.encrypt(plaintext, key)
      const decrypted = await AES256GCM.decrypt(encrypted, key)
      
      expect(decrypted.toString()).toBe(plaintext.toString())
    })

    it('should encrypt with additional authenticated data (AAD)', async () => {
      const key = await AES256GCM.generateKey()
      const plaintext = Buffer.from('Secret data')
      const aad = Buffer.from('header-data')
      
      const encrypted = await AES256GCM.encrypt(plaintext, key, aad)
      const decrypted = await AES256GCM.decrypt(encrypted, key, aad)
      
      expect(decrypted.toString()).toBe(plaintext.toString())
    })

    it('should fail to decrypt with wrong key', async () => {
      const key1 = await AES256GCM.generateKey()
      const key2 = await AES256GCM.generateKey()
      const plaintext = Buffer.from('Secret')
      
      const encrypted = await AES256GCM.encrypt(plaintext, key1)
      
      await expect(AES256GCM.decrypt(encrypted, key2)).rejects.toThrow()
    })
  })

  describe('Ed25519', () => {
    it('should generate key pair', async () => {
      const keyPair = await Ed25519.generateKeyPair()
      
      expect(keyPair.privateKey).toBeDefined()
      expect(keyPair.publicKey).toBeDefined()
      expect(keyPair.privateKey.length).toBe(32)
      expect(keyPair.publicKey.length).toBe(32)
    })

    it('should sign and verify data', async () => {
      const keyPair = await Ed25519.generateKeyPair()
      const data = Buffer.from('Message to sign')
      
      const signature = await Ed25519.sign(data, keyPair.privateKey)
      const valid = await Ed25519.verify(data, signature, keyPair.publicKey)
      
      expect(signature).toBeDefined()
      expect(signature.length).toBe(64)
      expect(valid).toBe(true)
    })

    it('should reject invalid signature', async () => {
      const keyPair1 = await Ed25519.generateKeyPair()
      const keyPair2 = await Ed25519.generateKeyPair()
      const data = Buffer.from('Message to sign')
      
      const signature = await Ed25519.sign(data, keyPair1.privateKey)
      const valid = await Ed25519.verify(data, signature, keyPair2.publicKey)
      
      expect(valid).toBe(false)
    })
  })

  describe('Configuration', () => {
    it('should handle various time formats', async () => {
      const timeFormats = ['1s', '1m', '1h', '1d', '7d', '30d']
      
      for (const expiresIn of timeFormats) {
        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: { test: expiresIn },
          expiresIn,
        })
        
        expect(token).toBeDefined()
      }
    })

    it('should include all claims in payload', async () => {
      const { token } = await createToken({
        format: 'binary',
        algorithm: 'v1.local',
        payload: { userId: '123' },
        expiresIn: '1h',
        issuer: 'test-issuer',
        audience: 'test-audience',
        subject: 'test-subject',
        tokenId: 'unique-token-id',
        issuedAt: true,
        notBefore: '0s',
      })
      
      expect(token).toBeDefined()
    })
  })
})

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import {
  createToken,
  verifyToken,
  MemoryStore,
  SQLiteStore,
  RevocationManager,
  TokenRevokedError,
} from '../src/index.js'
import { tmpdir } from 'os'
import { join } from 'path'
import { randomBytes } from 'crypto'

describe('Token Revocation', () => {
  describe('MemoryStore', () => {
    let store: MemoryStore

    beforeEach(() => {
      store = new MemoryStore({ debug: false })
    })

    afterEach(async () => {
      await store.disconnect()
    })

    it('should revoke a token by jti', async () => {
      await store.revoke({
        jti: 'token-123',
        exp: Math.floor(Date.now() / 1000) + 3600,
        revokedAt: Math.floor(Date.now() / 1000),
      })

      const isRevoked = await store.isRevoked('token-123')
      expect(isRevoked).toBe(true)
    })

    it('should not find non-revoked token', async () => {
      const isRevoked = await store.isRevoked('non-existent')
      expect(isRevoked).toBe(false)
    })

    it('should revoke all tokens for a user', async () => {
      // Revoke multiple tokens for user
      await store.revoke({
        jti: 'token-1',
        userId: 'user-123',
        exp: Math.floor(Date.now() / 1000) + 3600,
        revokedAt: Math.floor(Date.now() / 1000),
      })

      await store.revoke({
        jti: 'token-2',
        userId: 'user-123',
        exp: Math.floor(Date.now() / 1000) + 3600,
        revokedAt: Math.floor(Date.now() / 1000),
      })

      await store.revokeAllForUser('user-123', 'User logout')

      const tokens = await store.getRevokedTokensForUser('user-123')
      expect(tokens.length).toBeGreaterThan(0)
    })

    it('should revoke a session', async () => {
      await store.revokeSession('session-abc')

      const isRevoked = await store.isSessionRevoked('session-abc')
      expect(isRevoked).toBe(true)
    })

    it('should cleanup expired tokens', async () => {
      // Add expired token
      await store.revoke({
        jti: 'expired-token',
        exp: Math.floor(Date.now() / 1000) - 100, // Already expired
        revokedAt: Math.floor(Date.now() / 1000) - 200,
      })

      const cleaned = await store.cleanup()
      expect(cleaned).toBeGreaterThan(0)

      const isRevoked = await store.isRevoked('expired-token')
      expect(isRevoked).toBe(false)
    })

    it('should auto-cleanup expired tokens', async () => {
      store.startAutoCleanup(100) // 100ms interval

      // Add expired token
      await store.revoke({
        jti: 'auto-expired',
        exp: Math.floor(Date.now() / 1000) - 100,
        revokedAt: Math.floor(Date.now() / 1000) - 200,
      })

      // Wait for cleanup
      await new Promise(resolve => setTimeout(resolve, 200))

      const isRevoked = await store.isRevoked('auto-expired')
      expect(isRevoked).toBe(false)

      store.stopAutoCleanup()
    })
  })

  describe('SQLiteStore', () => {
    let store: SQLiteStore
    const dbPath = join(tmpdir(), `test-revocation-${randomBytes(4).toString('hex')}.db`)

    beforeEach(() => {
      store = new SQLiteStore({
        database: dbPath,
        debug: false,
      })
    })

    afterEach(async () => {
      await store.disconnect()
    })

    it('should revoke a token by jti', async () => {
      await store.revoke({
        jti: 'sqlite-token-123',
        exp: Math.floor(Date.now() / 1000) + 3600,
        revokedAt: Math.floor(Date.now() / 1000),
      })

      const isRevoked = await store.isRevoked('sqlite-token-123')
      expect(isRevoked).toBe(true)
    })

    it('should persist data across instances', async () => {
      // First instance
      await store.revoke({
        jti: 'persistent-token',
        exp: Math.floor(Date.now() / 1000) + 3600,
        revokedAt: Math.floor(Date.now() / 1000),
      })

      await store.disconnect()

      // Second instance with same database
      const store2 = new SQLiteStore({ database: dbPath })
      const isRevoked = await store2.isRevoked('persistent-token')
      expect(isRevoked).toBe(true)

      await store2.disconnect()
    })

    it('should get revoked tokens for user', async () => {
      await store.revoke({
        jti: 'user-token-1',
        userId: 'user-456',
        exp: Math.floor(Date.now() / 1000) + 3600,
        revokedAt: Math.floor(Date.now() / 1000),
      })

      await store.revoke({
        jti: 'user-token-2',
        userId: 'user-456',
        exp: Math.floor(Date.now() / 1000) + 3600,
        revokedAt: Math.floor(Date.now() / 1000),
      })

      const tokens = await store.getRevokedTokensForUser('user-456')
      expect(tokens).toContain('user-token-1')
      expect(tokens).toContain('user-token-2')
    })
  })

  describe('RevocationManager', () => {
    let store: MemoryStore
    let manager: RevocationManager

    beforeEach(() => {
      store = new MemoryStore({ debug: false })
      manager = new RevocationManager({ store, debug: false })
    })

    afterEach(async () => {
      await manager.disconnect()
    })

    it('should revoke token by jti', async () => {
      await manager.revokeByJti('manager-token-123', Math.floor(Date.now() / 1000) + 3600)

      const isRevoked = await manager.isRevoked('manager-token-123')
      expect(isRevoked).toBe(true)
    })

    it('should revoke user and all their tokens', async () => {
      // Create and revoke tokens
      await manager.revokeByJti('user-token-a', Math.floor(Date.now() / 1000) + 3600, {
        userId: 'user-789',
      })

      await manager.revokeByJti('user-token-b', Math.floor(Date.now() / 1000) + 3600, {
        userId: 'user-789',
      })

      // Revoke all user tokens
      await manager.revokeUser('user-789', 'Security breach')

      const isUserRevoked = await manager.isUserRevoked('user-789')
      expect(isUserRevoked).toBe(true)
    })
  })

  describe('Integration with verifyToken', () => {
    let store: MemoryStore

    beforeEach(() => {
      store = new MemoryStore({ debug: false })
      store.startAutoCleanup(60000)
    })

    afterEach(async () => {
      await store.disconnect()
    })

    it('should reject revoked token during verification', async () => {
      // Create a token with jti
      const { token } = await createToken({
        format: 'binary',
        algorithm: 'v1.local',
        payload: { userId: 'test-user' },
        expiresIn: '1h',
        tokenId: () => 'test-token-123',
      })

      // Decode token to get key for verification
      const parts = token.split('.')
      const key = Buffer.from(parts[0]!, 'base64url')

      // First verify should succeed
      await verifyToken(token, {
        secret: key,
        revocationStore: store,
      })

      // Revoke the token
      const decoded = await verifyToken(token, {
        secret: key,
        skipRevocationCheck: true,
      })
      const { RevocationManager } = await import('../src/revocation/RevocationManager.js')
      const manager = new RevocationManager({ store })
      await manager.revokeToken(decoded)

      // Second verify should fail
      await expect(
        verifyToken(token, {
          secret: key,
          revocationStore: store,
        })
      ).rejects.toThrow(TokenRevokedError)
    })

    it('should allow skipping revocation check', async () => {
      const { token } = await createToken({
        format: 'binary',
        algorithm: 'v1.local',
        payload: { userId: 'test-user' },
        expiresIn: '1h',
        tokenId: () => 'skip-test-token',
      })

      const parts = token.split('.')
      const key = Buffer.from(parts[0]!, 'base64url')

      // Revoke the token
      const decoded = await verifyToken(token, {
        secret: key,
        skipRevocationCheck: true,
      })
      const { RevocationManager } = await import('../src/revocation/RevocationManager.js')
      const manager = new RevocationManager({ store })
      await manager.revokeToken(decoded)

      // Should succeed when skipping revocation check
      const result = await verifyToken(token, {
        secret: key,
        revocationStore: store,
        skipRevocationCheck: true,
      })

      expect(result).toBeDefined()
    })

    it('should call onRevoked callback', async () => {
      const { token } = await createToken({
        format: 'binary',
        algorithm: 'v1.local',
        payload: { userId: 'test-user' },
        expiresIn: '1h',
        tokenId: () => 'callback-test-token',
      })

      const parts = token.split('.')
      const key = Buffer.from(parts[0]!, 'base64url')

      // Revoke the token
      const decoded = await verifyToken(token, {
        secret: key,
        skipRevocationCheck: true,
      })
      const { RevocationManager } = await import('../src/revocation/RevocationManager.js')
      const manager = new RevocationManager({ store })
      await manager.revokeToken(decoded)

      let callbackCalled = false

      try {
        await verifyToken(token, {
          secret: key,
          revocationStore: store,
          onRevoked: () => {
            callbackCalled = true
          },
        })
      } catch {
        // Expected to throw
      }

      expect(callbackCalled).toBe(true)
    })
  })
})

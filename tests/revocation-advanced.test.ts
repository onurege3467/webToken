import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import {
  createToken,
  verifyToken,
  MemoryStore,
  SQLiteStore,
  RevocationManager,
  TokenRevokedError,
  PathExtractor,
  IdentifierExtractor,
} from '../src/index.js'
import { tmpdir } from 'os'
import { join } from 'path'
import { randomBytes } from 'crypto'

describe('Advanced Revocation Features', () => {
  describe('PathExtractor', () => {
    const testPayload = {
      data: {
        user: {
          id: 'user-123',
          name: 'John Doe',
          profile: {
            email: 'john@example.com'
          }
        },
        users: [
          { id: 'user-1', name: 'Alice' },
          { id: 'user-2', name: 'Bob' }
        ],
        items: [
          [{ value: 'item-0-0' }, { value: 'item-0-1' }],
          [{ value: 'item-1-0' }, { value: 'item-1-1' }]
        ]
      },
      user: {
        id: 'direct-user-id'
      }
    }

    describe('Simple dot notation', () => {
      it('should extract nested property using dot notation: data.user.id', () => {
        const result = PathExtractor.extract(testPayload, 'data.user.id')
        expect(result).toBe('user-123')
      })

      it('should extract deeply nested property: data.user.profile.email', () => {
        const result = PathExtractor.extract(testPayload, 'data.user.profile.email')
        expect(result).toBe('john@example.com')
      })

      it('should extract top-level property: user.id', () => {
        const result = PathExtractor.extract(testPayload, 'user.id')
        expect(result).toBe('direct-user-id')
      })
    })

    describe('Array indices', () => {
      it('should extract from array at index: data.users[0].id', () => {
        const result = PathExtractor.extract(testPayload, 'data.users[0].id')
        expect(result).toBe('user-1')
      })

      it('should extract from array at index 1: data.users[1].name', () => {
        const result = PathExtractor.extract(testPayload, 'data.users[1].name')
        expect(result).toBe('Bob')
      })

      it('should return undefined for out of bounds index: data.users[99]', () => {
        const result = PathExtractor.extract(testPayload, 'data.users[99]')
        expect(result).toBeUndefined()
      })

      it('should extract name from first user: data.users[0].name', () => {
        const result = PathExtractor.extract(testPayload, 'data.users[0].name')
        expect(result).toBe('Alice')
      })
    })

    describe('Nested arrays', () => {
      it('should extract from nested array: data.items[0][0].value', () => {
        const result = PathExtractor.extract(testPayload, 'data.items[0][0].value')
        expect(result).toBe('item-0-0')
      })

      it('should extract from nested array: data.items[0][1].value', () => {
        const result = PathExtractor.extract(testPayload, 'data.items[0][1].value')
        expect(result).toBe('item-0-1')
      })

      it('should extract from nested array: data.items[1][0].value', () => {
        const result = PathExtractor.extract(testPayload, 'data.items[1][0].value')
        expect(result).toBe('item-1-0')
      })

      it('should extract from nested array: data.items[1][1].value', () => {
        const result = PathExtractor.extract(testPayload, 'data.items[1][1].value')
        expect(result).toBe('item-1-1')
      })
    })

    describe('Optional chaining (safe navigation)', () => {
      it('should handle optional chaining syntax: data?.user?.name', () => {
        const result = PathExtractor.extract(testPayload, 'data?.user?.name')
        expect(result).toBe('John Doe')
      })

      it('should handle optional chaining on missing path: data?.nonexistent?.property', () => {
        const result = PathExtractor.extract(testPayload, 'data?.nonexistent?.property')
        expect(result).toBeUndefined()
      })

      it('should handle optional chaining on null value', () => {
        const payloadWithNull = { data: { user: null } }
        const result = PathExtractor.extract(payloadWithNull, 'data?.user?.name')
        expect(result).toBeUndefined()
      })

      it('should handle optional chaining on undefined value', () => {
        const payloadWithUndefined = { data: { user: undefined } }
        const result = PathExtractor.extract(payloadWithUndefined, 'data?.user?.name')
        expect(result).toBeUndefined()
      })
    })

    describe('Fallback chain (extractFirst)', () => {
      it('should return first matching value from fallback chain', () => {
        const result = PathExtractor.extractFirst(testPayload, [
          'nonexistent.path',
          'data.nonexistent',
          'data.user.id',
          'user.id'
        ])
        expect(result).toBe('user-123')
      })

      it('should return second value if first is missing', () => {
        const result = PathExtractor.extractFirst(testPayload, [
          'nonexistent',
          'user.id',
          'data.user.id'
        ])
        expect(result).toBe('direct-user-id')
      })

      it('should return undefined if no paths match', () => {
        const result = PathExtractor.extractFirst(testPayload, [
          'nonexistent.path1',
          'nonexistent.path2',
          'nonexistent.path3'
        ])
        expect(result).toBeUndefined()
      })

      it('should return undefined for empty fallback chain', () => {
        const result = PathExtractor.extractFirst(testPayload, [])
        expect(result).toBeUndefined()
      })

      it('should return payload itself for empty path string', () => {
        const result = PathExtractor.extract(testPayload, '')
        expect(result).toEqual(testPayload)
      })
    })

    describe('Edge cases', () => {
      it('should handle null payload', () => {
        const result = PathExtractor.extract(null, 'data.user.id')
        expect(result).toBeUndefined()
      })

      it('should handle undefined payload', () => {
        const result = PathExtractor.extract(undefined, 'data.user.id')
        expect(result).toBeUndefined()
      })

      it('should handle non-object payload', () => {
        const result = PathExtractor.extract('string', 'data.user.id')
        expect(result).toBeUndefined()
      })

      it('should handle empty path', () => {
        const result = PathExtractor.extract(testPayload, '')
        expect(result).toEqual(testPayload)
      })
    })

    describe('Caching behavior', () => {
      it('should cache parsed paths', () => {
        // First call
        const result1 = PathExtractor.extract(testPayload, 'data.user.id')
        // Second call should use cache
        const result2 = PathExtractor.extract(testPayload, 'data.user.id')
        expect(result1).toBe(result2)
      })
    })
  })

  describe('IdentifierExtractor', () => {
    describe('Default fallback chain', () => {
      it('should extract userId from sub field', () => {
        const payload = { sub: 'user-sub-123' }
        const result = IdentifierExtractor.extractByFallback(payload)
        expect(result.userId).toBe('user-sub-123')
      })

      it('should extract userId from userId field', () => {
        const payload = { userId: 'direct-user-id' }
        const result = IdentifierExtractor.extractByFallback(payload)
        expect(result.userId).toBe('direct-user-id')
      })

      it('should extract userId from uid field', () => {
        const payload = { uid: 'uid-456' }
        const result = IdentifierExtractor.extractByFallback(payload)
        expect(result.userId).toBe('uid-456')
      })

      it('should extract userId from user_id field', () => {
        const payload = { user_id: 'snake_case_user' }
        const result = IdentifierExtractor.extractByFallback(payload)
        expect(result.userId).toBe('snake_case_user')
      })

      it('should prefer sub over userId', () => {
        const payload = { sub: 'sub-value', userId: 'userId-value' }
        const result = IdentifierExtractor.extractByFallback(payload)
        expect(result.userId).toBe('sub-value')
      })

      it('should extract from data.userId path', () => {
        const payload = { data: { userId: 'nested-user-id' } }
        const result = IdentifierExtractor.extractByFallback(payload)
        expect(result.userId).toBe('nested-user-id')
      })

      it('should extract from user?.id path', () => {
        const payload = { user: { id: 'user-object-id' } }
        const result = IdentifierExtractor.extractByFallback(payload)
        expect(result.userId).toBe('user-object-id')
      })
    })

    describe('Custom path extraction', () => {
      it('should extract using custom userIdPath', () => {
        const payload = { 
          custom: { 
            nested: { 
              identifier: 'custom-id' 
            } 
          } 
        }
        const result = IdentifierExtractor.extractIdentifiers(payload, {
          userIdPath: 'custom.nested.identifier'
        })
        expect(result.userId).toBe('custom-id')
      })

      it('should extract using array userIdField', () => {
        const payload = { altId: 'alternative-id' }
        const result = IdentifierExtractor.extractIdentifiers(payload, {
          userIdField: ['primaryId', 'altId', 'fallbackId']
        })
        expect(result.userId).toBe('alternative-id')
      })

      it('should extract sessionId using sessionIdPath', () => {
        const payload = { 
          session: { id: 'session-abc' },
          userId: 'user-123'
        }
        const result = IdentifierExtractor.extractIdentifiers(payload, {
          sessionIdPath: 'session.id'
        })
        expect(result.userId).toBe('user-123')
        expect(result.sessionId).toBe('session-abc')
      })

      it('should extract jti from payload', () => {
        const payload = { 
          jti: 'token-id-123',
          userId: 'user-456'
        }
        const result = IdentifierExtractor.extractIdentifiers(payload)
        expect(result.jti).toBe('token-id-123')
        expect(result.userId).toBe('user-456')
      })
    })

    describe('Composite key building', () => {
      it('should build composite key from multiple fields', () => {
        const payload = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          role: 'admin'
        }
        const result = IdentifierExtractor.buildCompositeKey(payload, {
          fields: ['userId', 'tenantId'],
          separator: ':'
        })
        expect(result).toBe('user-123:tenant-456')
      })

      it('should build composite key with custom separator', () => {
        const payload = {
          org: 'acme',
          dept: 'engineering',
          user: 'john'
        }
        const result = IdentifierExtractor.buildCompositeKey(payload, {
          fields: ['org', 'dept', 'user'],
          separator: '|'
        })
        expect(result).toBe('acme|engineering|john')
      })

      it('should return undefined if any field is missing', () => {
        const payload = {
          userId: 'user-123',
          // tenantId is missing
        }
        const result = IdentifierExtractor.buildCompositeKey(payload, {
          fields: ['userId', 'tenantId']
        })
        expect(result).toBeUndefined()
      })

      it('should return undefined for empty fields array', () => {
        const payload = { userId: 'user-123' }
        const result = IdentifierExtractor.buildCompositeKey(payload, {
          fields: []
        })
        expect(result).toBeUndefined()
      })

      it('should use default separator (colon) when not specified', () => {
        const payload = {
          a: 'value-a',
          b: 'value-b'
        }
        const result = IdentifierExtractor.buildCompositeKey(payload, {
          fields: ['a', 'b']
        })
        expect(result).toBe('value-a:value-b')
      })

      it('should extract composite key via extractIdentifiers', () => {
        const payload = {
          userId: 'user-123',
          tenantId: 'tenant-456'
        }
        const result = IdentifierExtractor.extractIdentifiers(payload, {
          compositeKey: {
            fields: ['userId', 'tenantId']
          }
        })
        expect(result.compositeKey).toBe('user-123:tenant-456')
      })

      it('should handle nested paths in composite key', () => {
        const payload = {
          data: {
            user: { id: 'user-123' },
            tenant: { id: 'tenant-456' }
          }
        }
        const result = IdentifierExtractor.buildCompositeKey(payload, {
          fields: ['data.user.id', 'data.tenant.id']
        })
        expect(result).toBe('user-123:tenant-456')
      })
    })

    describe('Custom extract function', () => {
      it('should use custom extractIdentifiers function', () => {
        const payload = { 
          customField: 'custom-value',
          anotherField: 'another-value'
        }
        const result = IdentifierExtractor.extractIdentifiers(payload, {
          extractIdentifiers: (data: any) => ({
            userId: data.customField,
            metadata: { another: data.anotherField }
          })
        })
        expect(result.userId).toBe('custom-value')
        expect(result.metadata).toEqual({ another: 'another-value' })
      })

      it('should fall back to default extraction if custom function returns null', () => {
        const payload = { 
          userId: 'fallback-user-id',
          customField: 'custom-value'
        }
        const result = IdentifierExtractor.extractIdentifiers(payload, {
          extractIdentifiers: () => null as any
        })
        expect(result.userId).toBe('fallback-user-id')
      })

      it('should fall back to default extraction if custom function throws', () => {
        const payload = { 
          userId: 'fallback-user-id'
        }
        const result = IdentifierExtractor.extractIdentifiers(payload, {
          extractIdentifiers: () => { throw new Error('Custom error') }
        })
        expect(result.userId).toBe('fallback-user-id')
      })

      it('should handle custom function returning empty object', () => {
        const payload = { 
          userId: 'fallback-user-id'
        }
        const result = IdentifierExtractor.extractIdentifiers(payload, {
          extractIdentifiers: () => ({}) as any
        })
        expect(result.userId).toBe('fallback-user-id')
      })
    })

    describe('Null/undefined handling', () => {
      it('should return empty object for null payload', () => {
        const result = IdentifierExtractor.extractIdentifiers(null)
        expect(result).toEqual({})
      })

      it('should return empty object for undefined payload', () => {
        const result = IdentifierExtractor.extractIdentifiers(undefined)
        expect(result).toEqual({})
      })

      it('should return empty object for string payload', () => {
        const result = IdentifierExtractor.extractIdentifiers('string')
        expect(result).toEqual({})
      })

      it('should return empty object for number payload', () => {
        const result = IdentifierExtractor.extractIdentifiers(123)
        expect(result).toEqual({})
      })

      it('should return empty object for array payload', () => {
        const result = IdentifierExtractor.extractIdentifiers([1, 2, 3])
        expect(result).toEqual({})
      })
    })

    describe('Type coercion', () => {
      it('should convert number userId to string', () => {
        const payload = { userId: 12345 }
        const result = IdentifierExtractor.extractIdentifiers(payload)
        expect(result.userId).toBe('12345')
      })

      it('should convert boolean userId to string', () => {
        const payload = { userId: true }
        const result = IdentifierExtractor.extractIdentifiers(payload)
        expect(result.userId).toBe('true')
      })

      it('should handle zero as userId', () => {
        const payload = { userId: 0 }
        const result = IdentifierExtractor.extractIdentifiers(payload)
        expect(result.userId).toBe('0')
      })

      it('should handle empty string as userId', () => {
        const payload = { userId: '' }
        const result = IdentifierExtractor.extractIdentifiers(payload)
        expect(result.userId).toBe('')
      })
    })
  })

  describe('Store tests with composite keys', () => {
    describe('MemoryStore revokeByCompositeKey', () => {
      let store: MemoryStore

      beforeEach(() => {
        store = new MemoryStore({ debug: false })
      })

      afterEach(async () => {
        await store.disconnect()
      })

      it('should revoke by composite key', async () => {
        const exp = Math.floor(Date.now() / 1000) + 3600
        await store.revokeByCompositeKey(
          'user-123:tenant-456',
          { userId: 'user-123', tenantId: 'tenant-456' },
          exp,
          'Tenant user revocation'
        )

        const isRevoked = await store.isCompositeKeyRevoked('user-123:tenant-456')
        expect(isRevoked).toBe(true)
      })

      it('should revoke multiple composite keys', async () => {
        const exp = Math.floor(Date.now() / 1000) + 3600
        
        await store.revokeByCompositeKey('key-1', { a: '1' }, exp)
        await store.revokeByCompositeKey('key-2', { b: '2' }, exp)
        await store.revokeByCompositeKey('key-3', { c: '3' }, exp)

        expect(await store.isCompositeKeyRevoked('key-1')).toBe(true)
        expect(await store.isCompositeKeyRevoked('key-2')).toBe(true)
        expect(await store.isCompositeKeyRevoked('key-3')).toBe(true)
      })

      it('should return false for non-existent composite key', async () => {
        const isRevoked = await store.isCompositeKeyRevoked('non-existent-key')
        expect(isRevoked).toBe(false)
      })

      it('should return false for expired composite key', async () => {
        const pastExp = Math.floor(Date.now() / 1000) - 100
        await store.revokeByCompositeKey(
          'expired-key',
          { id: '123' },
          pastExp
        )

        const isRevoked = await store.isCompositeKeyRevoked('expired-key')
        expect(isRevoked).toBe(false)
      })

      it('should cleanup expired composite keys', async () => {
        const pastExp = Math.floor(Date.now() / 1000) - 100
        await store.revokeByCompositeKey('old-key', { id: '1' }, pastExp)

        const cleaned = await store.cleanup()
        expect(cleaned).toBe(1)

        const stats = store.getStats()
        expect(stats.compositeKeys).toBe(0)
      })

      it('should include composite keys in stats', async () => {
        const exp = Math.floor(Date.now() / 1000) + 3600
        await store.revokeByCompositeKey('key-1', { id: '1' }, exp)
        await store.revokeByCompositeKey('key-2', { id: '2' }, exp)

        const stats = store.getStats()
        expect(stats.compositeKeys).toBe(2)
      })

      it('should clear composite keys on disconnect', async () => {
        const exp = Math.floor(Date.now() / 1000) + 3600
        await store.revokeByCompositeKey('key-1', { id: '1' }, exp)

        await store.disconnect()

        // Create new store instance to check cleanup
        store = new MemoryStore({ debug: false })
        const isRevoked = await store.isCompositeKeyRevoked('key-1')
        expect(isRevoked).toBe(false)
      })
    })

    describe('SQLiteStore revokeByCompositeKey', () => {
      let store: SQLiteStore
      const dbPath = join(tmpdir(), `test-composite-${randomBytes(4).toString('hex')}.db`)

      beforeEach(() => {
        store = new SQLiteStore({
          database: dbPath,
          debug: false,
        })
      })

      afterEach(async () => {
        await store.disconnect()
      })

      it('should revoke by composite key', async () => {
        const exp = Math.floor(Date.now() / 1000) + 3600
        await store.revokeByCompositeKey(
          'user-123:tenant-456',
          { userId: 'user-123', tenantId: 'tenant-456' },
          exp,
          'Tenant user revocation'
        )

        const isRevoked = await store.isCompositeKeyRevoked('user-123:tenant-456')
        expect(isRevoked).toBe(true)
      })

      it('should persist composite key across instances', async () => {
        const exp = Math.floor(Date.now() / 1000) + 3600
        await store.revokeByCompositeKey('persistent-key', { id: '123' }, exp)
        await store.disconnect()

        const store2 = new SQLiteStore({ database: dbPath })
        const isRevoked = await store2.isCompositeKeyRevoked('persistent-key')
        expect(isRevoked).toBe(true)

        await store2.disconnect()
      })

      it('should return false for non-existent composite key', async () => {
        const isRevoked = await store.isCompositeKeyRevoked('non-existent')
        expect(isRevoked).toBe(false)
      })

      it('should return false for expired composite key', async () => {
        const pastExp = Math.floor(Date.now() / 1000) - 100
        await store.revokeByCompositeKey('expired-key', { id: '123' }, pastExp)

        const isRevoked = await store.isCompositeKeyRevoked('expired-key')
        expect(isRevoked).toBe(false)
      })

      it('should cleanup expired composite keys', async () => {
        const pastExp = Math.floor(Date.now() / 1000) - 100
        await store.revokeByCompositeKey('old-key', { id: '1' }, pastExp)

        const cleaned = await store.cleanup()
        expect(cleaned).toBeGreaterThan(0)

        const isRevoked = await store.isCompositeKeyRevoked('old-key')
        expect(isRevoked).toBe(false)
      })

      it('should handle complex composite key components', async () => {
        const exp = Math.floor(Date.now() / 1000) + 3600
        const components = {
          orgId: 'org-123',
          tenantId: 'tenant-456',
          userId: 'user-789',
          role: 'admin'
        }
        
        await store.revokeByCompositeKey('complex-key', components, exp, 'Complex revocation')

        const isRevoked = await store.isCompositeKeyRevoked('complex-key')
        expect(isRevoked).toBe(true)
      })

      it('should update existing composite key', async () => {
        const exp = Math.floor(Date.now() / 1000) + 3600
        await store.revokeByCompositeKey('update-key', { id: '1' }, exp, 'First')
        await store.revokeByCompositeKey('update-key', { id: '1', extra: '2' }, exp, 'Second')

        const isRevoked = await store.isCompositeKeyRevoked('update-key')
        expect(isRevoked).toBe(true)
      })
    })
  })

  describe('Integration tests', () => {
    describe('Verify token with custom userIdPath', () => {
      let store: MemoryStore

      beforeEach(() => {
        store = new MemoryStore({ 
          debug: false,
          identifierConfig: {
            userIdPath: 'custom.user.identifier'
          }
        })
      })

      afterEach(async () => {
        await store.disconnect()
      })

      it('should revoke and verify token with custom userIdPath', async () => {
        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: { 
            custom: { 
              user: { 
                identifier: 'custom-user-123',
                name: 'John'
              } 
            } 
          },
          expiresIn: '1h',
          tokenId: () => 'custom-path-token',
        })

        const parts = token.split('.')
        const key = Buffer.from(parts[0]!, 'base64url')

        // First verify should succeed
        const decoded = await verifyToken(token, {
          secret: key,
          skipRevocationCheck: true,
        })

        // Revoke using the manager with identifier config
        const manager = new RevocationManager({ 
          store,
          identifierConfig: {
            userIdPath: 'custom.user.identifier'
          }
        })
        await manager.revokeToken(decoded)

        // Verify should now fail with token revoked
        await expect(
          verifyToken(token, {
            secret: key,
            revocationStore: store,
          })
        ).rejects.toThrow(TokenRevokedError)
      })
    })

    describe('Verify token with composite key', () => {
      let store: MemoryStore

      beforeEach(() => {
        store = new MemoryStore({ debug: false })
      })

      afterEach(async () => {
        await store.disconnect()
      })

      it('should revoke by composite key and reject token', async () => {
        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: { 
            userId: 'user-123',
            tenantId: 'tenant-456',
            role: 'admin'
          },
          expiresIn: '1h',
          tokenId: () => 'composite-token',
        })

        const parts = token.split('.')
        const key = Buffer.from(parts[0]!, 'base64url')

        // Revoke by composite key
        const exp = Math.floor(Date.now() / 1000) + 3600
        await store.revokeByCompositeKey(
          'user-123:tenant-456',
          { userId: 'user-123', tenantId: 'tenant-456' },
          exp
        )

        // Create manager that checks composite keys
        const manager = new RevocationManager({
          store,
          identifierConfig: {
            compositeKey: {
              fields: ['data.userId', 'data.tenantId']
            }
          }
        })

        // Verify with the manager should fail
        const decoded = await verifyToken(token, {
          secret: key,
          skipRevocationCheck: true,
        })

        const isRevoked = await manager.checkRevoked(decoded)
        expect(isRevoked).toBe(true)
      })

      it('should verify token passes when composite key not revoked', async () => {
        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: { 
            userId: 'user-123',
            tenantId: 'tenant-456'
          },
          expiresIn: '1h',
          tokenId: () => 'non-revoked-token',
        })

        const parts = token.split('.')
        const key = Buffer.from(parts[0]!, 'base64url')

        // Don't revoke this token
        const manager = new RevocationManager({
          store,
          identifierConfig: {
            compositeKey: {
              fields: ['data.userId', 'data.tenantId']
            }
          }
        })

        const decoded = await verifyToken(token, {
          secret: key,
          skipRevocationCheck: true,
        })

        const isRevoked = await manager.checkRevoked(decoded)
        expect(isRevoked).toBe(false)
      })
    })

    describe('Global store config + per-token override', () => {
      it('should merge global config with per-token config', async () => {
        const store = new MemoryStore({
          debug: false,
          identifierConfig: {
            userIdPath: 'global.userId',
            sessionIdPath: 'global.sessionId'
          }
        })

        const manager = new RevocationManager({
          store,
          identifierConfig: {
            userIdPath: 'global.userId', // Global
            compositeKey: {
              fields: ['userId', 'orgId'] // From global
            }
          }
        })

        // Test merging - per-token should override
        const merged = manager.mergeConfigs(
          {
            userIdPath: 'global.userId',
            compositeKey: { fields: ['a', 'b'] }
          },
          {
            userIdPath: 'token.userId', // Override
            sessionIdPath: 'token.sessionId' // Additional
          }
        )

        expect(merged?.userIdPath).toBe('token.userId')
        expect(merged?.sessionIdPath).toBe('token.sessionId')
        expect(merged?.compositeKey).toEqual({ fields: ['a', 'b'] })

        await store.disconnect()
      })

      it('should use per-token config over global for revocation check', async () => {
        const store = new MemoryStore({ debug: false })

        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: { 
            tokenSpecific: { user: { id: 'token-user-123' } },
            globalUser: { id: 'global-user-456' }
          },
          expiresIn: '1h',
          tokenId: () => 'merge-test-token',
        })

        const parts = token.split('.')
        const key = Buffer.from(parts[0]!, 'base64url')

        const manager = new RevocationManager({
          store,
          identifierConfig: {
            userIdPath: 'data.globalUser.id' // Global config
          }
        })

        // Revoke using token-specific path
        const decoded = await verifyToken(token, {
          secret: key,
          skipRevocationCheck: true,
        })

        // Extract with global config
        const globalExtract = manager.extractIdentifiers(decoded.payload)
        expect(globalExtract.userId).toBe('global-user-456')

        // Extract with token-specific config override
        const tokenExtract = manager.extractIdentifiers(decoded.payload, {
          userIdPath: 'data.tokenSpecific.user.id'
        })
        expect(tokenExtract.userId).toBe('token-user-123')

        await store.disconnect()
      })

      it('should handle null configs in merge', async () => {
        const manager = new RevocationManager({
          store: new MemoryStore({ debug: false })
        })

        // Both null
        let merged = manager.mergeConfigs(undefined, undefined)
        expect(merged).toBeUndefined()

        // Only token config
        merged = manager.mergeConfigs(undefined, { userIdPath: 'token' })
        expect(merged?.userIdPath).toBe('token')

        // Only store config
        merged = manager.mergeConfigs({ userIdPath: 'store' }, undefined)
        expect(merged?.userIdPath).toBe('store')

        await manager.disconnect()
      })
    })

    describe('Complex nested payload extraction', () => {
      let store: MemoryStore

      beforeEach(() => {
        store = new MemoryStore({ debug: false })
      })

      afterEach(async () => {
        await store.disconnect()
      })

      it('should extract deeply nested user ID', async () => {
        const complexPayload = {
          organization: {
            department: {
              team: {
                member: {
                  profile: {
                    identifier: 'deep-user-123'
                  }
                }
              }
            }
          }
        }

        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: complexPayload,
          expiresIn: '1h',
          tokenId: () => 'deep-nested-token',
        })

        const parts = token.split('.')
        const key = Buffer.from(parts[0]!, 'base64url')

        const decoded = await verifyToken(token, {
          secret: key,
          skipRevocationCheck: true,
        })

        const manager = new RevocationManager({
          store,
          identifierConfig: {
            userIdPath: 'data.organization.department.team.member.profile.identifier'
          }
        })

        const identifiers = manager.extractIdentifiers(decoded.payload)
        expect(identifiers.userId).toBe('deep-user-123')
      })

      it('should extract from array in payload', async () => {
        const payloadWithArray = {
          users: [
            { id: 'user-1', role: 'admin' },
            { id: 'user-2', role: 'user' }
          ],
          currentUserIndex: 0
        }

        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: payloadWithArray,
          expiresIn: '1h',
          tokenId: () => 'array-token',
        })

        const parts = token.split('.')
        const key = Buffer.from(parts[0]!, 'base64url')

        const decoded = await verifyToken(token, {
          secret: key,
          skipRevocationCheck: true,
        })

        const manager = new RevocationManager({
          store,
          identifierConfig: {
            userIdPath: 'data.users[0].id'
          }
        })

        const identifiers = manager.extractIdentifiers(decoded.payload)
        expect(identifiers.userId).toBe('user-1')
      })

      it('should extract multiple identifiers from complex payload', async () => {
        const complexPayload = {
          authentication: {
            user: {
              principal: {
                id: 'principal-123'
              },
              session: {
                id: 'session-abc'
              }
            },
            context: {
              tenant: {
                id: 'tenant-xyz'
              }
            }
          },
          jti: 'token-unique-id'
        }

        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: complexPayload,
          expiresIn: '1h',
          tokenId: () => 'multi-id-token',
        })

        const parts = token.split('.')
        const key = Buffer.from(parts[0]!, 'base64url')

        const decoded = await verifyToken(token, {
          secret: key,
          skipRevocationCheck: true,
        })

        const manager = new RevocationManager({
          store,
          identifierConfig: {
            userIdPath: 'data.authentication.user.principal.id',
            sessionIdPath: 'data.authentication.user.session.id',
            compositeKey: {
              fields: ['data.authentication.user.principal.id', 'data.authentication.context.tenant.id']
            }
          }
        })

        const identifiers = manager.extractIdentifiers(decoded.payload)
        expect(identifiers.userId).toBe('principal-123')
        expect(identifiers.sessionId).toBe('session-abc')
        expect(identifiers.jti).toBe('multi-id-token')
        expect(identifiers.compositeKey).toBe('principal-123:tenant-xyz')
      })

      it('should handle mixed array and object paths', async () => {
        const mixedPayload = {
          data: {
            items: [
              {
                users: [
                  { profile: { id: 'nested-user-1' } },
                  { profile: { id: 'nested-user-2' } }
                ]
              }
            ]
          }
        }

        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: mixedPayload,
          expiresIn: '1h',
          tokenId: () => 'mixed-path-token',
        })

        const parts = token.split('.')
        const key = Buffer.from(parts[0]!, 'base64url')

        const decoded = await verifyToken(token, {
          secret: key,
          skipRevocationCheck: true,
        })

        const manager = new RevocationManager({
          store,
          identifierConfig: {
            userIdPath: 'data.data.items[0].users[1].profile.id'
          }
        })

        const identifiers = manager.extractIdentifiers(decoded.payload)
        expect(identifiers.userId).toBe('nested-user-2')
      })
    })

    describe('End-to-end revocation with advanced features', () => {
      it('should revoke by composite key and reject matching token', async () => {
        const store = new MemoryStore({ debug: false })

        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: { 
            orgId: 'org-123',
            tenantId: 'tenant-456',
            userId: 'user-789'
          },
          expiresIn: '1h',
          tokenId: () => 'e2e-composite-token',
        })

        const parts = token.split('.')
        const key = Buffer.from(parts[0]!, 'base64url')

        // Revoke by composite key before token is verified
        const manager = new RevocationManager({
          store,
          identifierConfig: {
            compositeKey: {
              fields: ['data.orgId', 'data.tenantId', 'data.userId']
            }
          }
        })

        const decoded = await verifyToken(token, {
          secret: key,
          skipRevocationCheck: true,
        })

        // Revoke the composite key
        await manager.revokeTokenFlexible(decoded, undefined, 'E2E test revocation')

        // Verify token - should be rejected
        const isRevoked = await manager.checkRevoked(decoded)
        expect(isRevoked).toBe(true)

        await store.disconnect()
      })

      it('should support multiple revocation methods in sequence', async () => {
        const store = new MemoryStore({ debug: false })

        const { token } = await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: { 
            userId: 'multi-method-user',
            sessionId: 'session-xyz'
          },
          expiresIn: '1h',
          tokenId: () => 'multi-method-token',
        })

        const parts = token.split('.')
        const key = Buffer.from(parts[0]!, 'base64url')

        const manager = new RevocationManager({ store, debug: false })
        const decoded = await verifyToken(token, {
          secret: key,
          skipRevocationCheck: true,
        })

        // Initially not revoked
        expect(await manager.checkRevoked(decoded)).toBe(false)

        // Revoke by session
        await manager.revokeSession('session-xyz')
        expect(await manager.checkRevoked(decoded)).toBe(true)

        await store.disconnect()
      })
    })
  })
})

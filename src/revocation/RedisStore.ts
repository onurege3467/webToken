/**
 * Redis-based revocation store implementation
 * Best for distributed systems with native TTL support
 */

import { RevocationStore, RevocationIdentifier, RedisStoreConfig } from './types.js'
import type { IdentifierConfig } from '../types/identifiers.js'

interface RedisClient {
  status?: string
  connect(): Promise<void>
  setex(key: string, seconds: number, value: string): Promise<string>
  get(key: string): Promise<string | null>
  del(...keys: string[]): Promise<number>
  sadd(key: string, ...members: string[]): Promise<number>
  smembers(key: string): Promise<string[]>
  srem(key: string, ...members: string[]): Promise<number>
  sismember(key: string, member: string): Promise<number>
  expire(key: string, seconds: number): Promise<number>
  ttl(key: string): Promise<number>
  keys(pattern: string): Promise<string[]>
  pipeline(): RedisPipeline
  hset(key: string, field: string, value: string): Promise<number>
  hmset(key: string, values: Record<string, string>): Promise<string>
  hgetall(key: string): Promise<Record<string, string>>
  hexists(key: string, field: string): Promise<number>
  quit(): Promise<void>
}

interface RedisPipeline {
  setex(key: string, seconds: number, value: string): RedisPipeline
  sadd(key: string, member: string): RedisPipeline
  expire(key: string, seconds: number): RedisPipeline
  del(key: string): RedisPipeline
  hset(key: string, field: string, value: string): RedisPipeline
  hmset(key: string, values: Record<string, string>): RedisPipeline
  exec(): Promise<any[]>
}

export class RedisStore extends RevocationStore {
  protected declare config: RedisStoreConfig
  private client: RedisClient | null = null
  private Redis: any = null
  identifierConfig?: IdentifierConfig

  constructor(config: RedisStoreConfig = {}) {
    super(config)
    this.config = config
    this.identifierConfig = config.identifierConfig
  }

  private async initialize(): Promise<void> {
    if (this.client) return

    if (this.config.client) {
      this.client = this.config.client
      return
    }

    // Dynamic import Redis
    if (!this.Redis) {
      try {
        const ioredis = await import('ioredis')
        this.Redis = ioredis.default || ioredis.Redis || ioredis
      } catch {
        throw new Error(
          'Redis is not installed. Please install ioredis: npm install ioredis'
        )
      }
    }

    if (this.config.url) {
      this.client = new this.Redis(this.config.url)
    } else {
      this.client = new this.Redis({
        host: this.config.host || 'localhost',
        port: this.config.port || 6379,
        password: this.config.password,
        db: this.config.db || 0,
        lazyConnect: true,
      })
    }
  }

  private getKey(type: string, id: string): string {
    const prefix = this.config.keyPrefix || 'webtoken:revoke:'
    return `${prefix}${type}:${id}`
  }

  private calculateTTL(exp: number): number {
    const now = Math.floor(Date.now() / 1000)
    const ttl = exp - now
    return Math.max(ttl, 1)
  }

  private async ensureConnected(): Promise<void> {
    await this.initialize()
    if (!this.client!.status || this.client!.status === 'wait') {
      await this.client!.connect()
    }
  }

  async revoke(identifier: RevocationIdentifier): Promise<void> {
    await this.ensureConnected()

    if (!this.hasValidJti(identifier)) {
      throw new Error('Cannot revoke token without jti')
    }

    const ttl = this.calculateTTL(identifier.exp)
    const key = this.getKey('jti', identifier.jti)

    const data = JSON.stringify({
      userId: identifier.userId,
      sessionId: identifier.sessionId,
      revokedAt: identifier.revokedAt,
      reason: identifier.reason,
    })

    const pipeline = this.client!.pipeline()

    pipeline.setex(key, ttl, data)

    if (identifier.userId) {
      const userKey = this.getKey('user', identifier.userId)
      pipeline.sadd(userKey, identifier.jti)
      pipeline.expire(userKey, ttl)
    }

    if (identifier.sessionId) {
      const sessionKey = this.getKey('session', identifier.sessionId)
      pipeline.setex(sessionKey, ttl, identifier.jti)
    }

    await pipeline.exec()

    if (this.config.debug) {
      console.log(`[WebToken] Revoked token in Redis: ${identifier.jti} (TTL: ${ttl}s)`)
    }
  }

  async isRevoked(jti: string): Promise<boolean> {
    await this.ensureConnected()

    const key = this.getKey('jti', jti)
    const exists = await this.client!.get(key)

    return exists !== null
  }

  async getRevokedTokensForUser(userId: string): Promise<string[]> {
    await this.ensureConnected()

    const userKey = this.getKey('user', userId)
    const jtis = await this.client!.smembers(userKey)

    const validJtis: string[] = []

    for (const jti of jtis) {
      const tokenKey = this.getKey('jti', jti)
      const ttl = await this.client!.ttl(tokenKey)

      if (ttl > 0) {
        validJtis.push(jti)
      } else {
        await this.client!.srem(userKey, jti)
      }
    }

    return validJtis
  }

  async revokeAllForUser(userId: string, reason?: string): Promise<void> {
    await this.ensureConnected()

    const jtis = await this.getRevokedTokensForUser(userId)
    const now = Math.floor(Date.now() / 1000)

    for (const jti of jtis) {
      const key = this.getKey('jti', jti)
      const existing = await this.client!.get(key)

      if (existing) {
        const data = JSON.parse(existing)
        data.revokedAt = now
        data.reason = reason || 'User revoked'

        const ttl = await this.client!.ttl(key)
        if (ttl > 0) {
          await this.client!.setex(key, ttl, JSON.stringify(data))
        }
      }
    }

    const userKey = this.getKey('user', 'revoked')
    await this.client!.sadd(userKey, userId)

    if (this.config.debug) {
      console.log(`[WebToken] Revoked ${jtis.length} tokens for user: ${userId}`)
    }
  }

  async revokeSession(sessionId: string, reason?: string): Promise<void> {
    await this.ensureConnected()

    const sessionKey = this.getKey('session', sessionId)
    const jti = await this.client!.get(sessionKey)

    if (jti) {
      await this.revoke({
        jti,
        sessionId,
        exp: Math.floor(Date.now() / 1000) + 86400,
        revokedAt: Math.floor(Date.now() / 1000),
        reason: reason || 'Session revoked',
      })
    } else {
      await this.client!.setex(sessionKey, 86400, 'revoked')
    }

    if (this.config.debug) {
      console.log(`[WebToken] Revoked session in Redis: ${sessionId}`)
    }
  }

  async isSessionRevoked(sessionId: string): Promise<boolean> {
    await this.ensureConnected()

    const sessionKey = this.getKey('session', sessionId)
    const exists = await this.client!.get(sessionKey)

    return exists !== null
  }

  async isUserRevoked(userId: string): Promise<boolean> {
    await this.ensureConnected()

    const userKey = this.getKey('user', 'revoked')
    const isRevoked = await this.client!.sismember(userKey, userId)

    return isRevoked === 1
  }

  async revokeByCompositeKey(key: string, components: Record<string, string>, exp: number, reason?: string): Promise<void> {
    await this.ensureConnected()

    const ttl = this.calculateTTL(exp)
    const compositeKey = this.getKey('composite', key)

    const data: Record<string, string> = {
      revokedAt: String(Math.floor(Date.now() / 1000)),
      exp: String(exp),
      ...components,
    }

    if (reason) {
      data.reason = reason
    }

    const pipeline = this.client!.pipeline()
    
    pipeline.hmset(compositeKey, data)
    pipeline.expire(compositeKey, ttl)

    await pipeline.exec()

    if (this.config.debug) {
      console.log(`[WebToken] Revoked composite key in Redis: ${key} (TTL: ${ttl}s)`)
    }
  }

  async isCompositeKeyRevoked(key: string): Promise<boolean> {
    await this.ensureConnected()

    const compositeKey = this.getKey('composite', key)
    const exists = await this.client!.hexists(compositeKey, 'revokedAt')

    return exists === 1
  }

  async cleanup(): Promise<number> {
    await this.ensureConnected()

    let cleaned = 0
    const userKeys = await this.client!.keys(this.getKey('user', '*'))

    for (const userKey of userKeys) {
      const jtis = await this.client!.smembers(userKey)

      for (const jti of jtis) {
        const tokenKey = this.getKey('jti', jti)
        const exists = await this.client!.get(tokenKey)

        if (!exists) {
          await this.client!.srem(userKey, jti)
          cleaned++
        }
      }
    }

    if (this.config.debug && cleaned > 0) {
      console.log(`[WebToken] RedisStore cleaned ${cleaned} orphaned references`)
    }

    return cleaned
  }

  async disconnect(): Promise<void> {
    this.stopAutoCleanup()

    if (this.client) {
      try {
        await this.client.quit()

        if (this.config.debug) {
          console.log('[WebToken] RedisStore disconnected')
        }
      } catch (error) {
        if (this.config.debug) {
          console.error('[WebToken] Redis disconnect error:', error)
        }
      }
      this.client = null
    }
  }

  getClient(): RedisClient | null {
    return this.client
  }
}

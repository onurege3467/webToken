/**
 * In-memory revocation store implementation
 * Best for single-server applications with ephemeral data
 */

import { RevocationStore, RevocationIdentifier, RevocationStoreConfig } from './types.js'

interface RevokedEntry extends RevocationIdentifier {
  /** User ID for batch lookup */
  userId?: string
  /** Session ID for session lookup */
  sessionId?: string
  /** Composite key for composite lookup */
  compositeKey?: string
}

interface CompositeKeyEntry {
  key: string
  components: Record<string, string>
  exp: number
  revokedAt: number
  reason?: string
}

export class MemoryStore extends RevocationStore {
  private revokedTokens: Map<string, RevokedEntry> = new Map()
  private userTokens: Map<string, Set<string>> = new Map() // userId -> Set<jti>
  private revokedSessions: Set<string> = new Set()
  private compositeKeys: Map<string, CompositeKeyEntry> = new Map()

  constructor(config: RevocationStoreConfig = {}) {
    super(config)
    this.identifierConfig = config.identifierConfig
  }

  /**
   * Revoke a token by its identifier
   */
  async revoke(identifier: RevocationIdentifier): Promise<void> {
    if (!this.hasValidJti(identifier)) {
      throw new Error('Cannot revoke token without jti')
    }

    const entry: RevokedEntry = {
      ...identifier,
      userId: identifier.userId,
      sessionId: identifier.sessionId,
    }

    // Store by JTI
    this.revokedTokens.set(identifier.jti, entry)

    // Store in user index if userId exists
    if (identifier.userId) {
      if (!this.userTokens.has(identifier.userId)) {
        this.userTokens.set(identifier.userId, new Set())
      }
      this.userTokens.get(identifier.userId)!.add(identifier.jti)
    }

    // Store session if sessionId exists
    if (identifier.sessionId) {
      this.revokedSessions.add(identifier.sessionId)
    }

    if (this.config.debug) {
      console.log(`[WebToken] Revoked token: ${identifier.jti}`)
    }
  }

  /**
   * Check if a token is revoked by jti
   */
  async isRevoked(jti: string): Promise<boolean> {
    const entry = this.revokedTokens.get(jti)
    
    if (!entry) {
      return false
    }

    // Check if expired (should be cleaned up, but double-check)
    const now = Math.floor(Date.now() / 1000)
    if (entry.exp < now) {
      // Auto-remove expired entry
      this.revokedTokens.delete(jti)
      return false
    }

    return true
  }

  /**
   * Get all revoked tokens for a user
   */
  async getRevokedTokensForUser(userId: string): Promise<string[]> {
    const jtis = this.userTokens.get(userId)
    if (!jtis) {
      return []
    }

    // Filter out expired tokens
    const now = Math.floor(Date.now() / 1000)
    const validJtis: string[] = []

    for (const jti of jtis) {
      const entry = this.revokedTokens.get(jti)
      if (entry && entry.exp >= now) {
        validJtis.push(jti)
      } else {
        // Clean up expired reference
        jtis.delete(jti)
      }
    }

    return validJtis
  }

  /**
   * Revoke all tokens for a user
   * Note: This only revokes tokens that are already tracked.
   * Future tokens from this user will need to be rejected at application level.
   */
  async revokeAllForUser(userId: string, reason?: string): Promise<void> {
    const jtis = this.userTokens.get(userId)
    const now = Math.floor(Date.now() / 1000)

    if (!jtis) {
      // Create a marker to indicate all user tokens should be revoked
      this.userTokens.set(userId, new Set(['*']))
    } else {
      // Update existing tokens
      for (const jti of jtis) {
        if (jti === '*') continue // Skip marker
        
        const entry = this.revokedTokens.get(jti)
        if (entry) {
          entry.revokedAt = now
          entry.reason = reason || 'User revoked'
        }
      }
      
      // Add marker for future tokens
      jtis.add('*')
    }

    if (this.config.debug) {
      console.log(`[WebToken] Revoked all tokens for user: ${userId}`)
    }
  }

  /**
   * Revoke a session
   */
  async revokeSession(sessionId: string, reason?: string): Promise<void> {
    this.revokedSessions.add(sessionId)

    // Also revoke any tokens associated with this session
    for (const [, entry] of this.revokedTokens) {
      if (entry.sessionId === sessionId) {
        entry.revokedAt = Math.floor(Date.now() / 1000)
        entry.reason = reason || 'Session revoked'
      }
    }

    if (this.config.debug) {
      console.log(`[WebToken] Revoked session: ${sessionId}`)
    }
  }

  /**
   * Check if a session is revoked
   */
  async isSessionRevoked(sessionId: string): Promise<boolean> {
    return this.revokedSessions.has(sessionId)
  }

  /**
   * Check if a user's all tokens should be rejected
   */
  async isUserRevoked(userId: string): Promise<boolean> {
    const jtis = this.userTokens.get(userId)
    return jtis?.has('*') || false
  }

  /**
   * Revoke by composite key
   */
  async revokeByCompositeKey(key: string, components: Record<string, string>, exp: number, reason?: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000)
    
    const entry: CompositeKeyEntry = {
      key,
      components,
      exp,
      revokedAt: now,
      reason,
    }

    this.compositeKeys.set(key, entry)

    if (this.config.debug) {
      console.log(`[WebToken] Revoked composite key: ${key}`)
    }
  }

  /**
   * Check if a composite key is revoked
   */
  async isCompositeKeyRevoked(key: string): Promise<boolean> {
    const entry = this.compositeKeys.get(key)
    
    if (!entry) {
      return false
    }

    // Check if expired (should be cleaned up, but double-check)
    const now = Math.floor(Date.now() / 1000)
    if (entry.exp < now) {
      // Auto-remove expired entry
      this.compositeKeys.delete(key)
      return false
    }

    return true
  }

  /**
   * Manual cleanup of expired entries
   */
  async cleanup(): Promise<number> {
    const now = Math.floor(Date.now() / 1000)
    let cleaned = 0

    // Clean revoked tokens
    for (const [jti, entry] of this.revokedTokens) {
      if (entry.exp < now) {
        this.revokedTokens.delete(jti)
        cleaned++

        // Remove from user index
        if (entry.userId && this.userTokens.has(entry.userId)) {
          this.userTokens.get(entry.userId)!.delete(jti)
        }
      }
    }

    // Clean composite keys
    for (const [key, entry] of this.compositeKeys) {
      if (entry.exp < now) {
        this.compositeKeys.delete(key)
        cleaned++
      }
    }

    // Clean empty user entries
    for (const [userId, jtis] of this.userTokens) {
      if (jtis.size === 0 || (jtis.size === 1 && jtis.has('*'))) {
        // Keep entries with '*' marker, but clean truly empty ones
        if (jtis.size === 0) {
          this.userTokens.delete(userId)
        }
      }
    }

    if (this.config.debug && cleaned > 0) {
      console.log(`[WebToken] MemoryStore cleaned ${cleaned} expired entries`)
    }

    return cleaned
  }

  /**
   * Disconnect (clear all data)
   */
  async disconnect(): Promise<void> {
    this.stopAutoCleanup()
    this.revokedTokens.clear()
    this.userTokens.clear()
    this.revokedSessions.clear()
    this.compositeKeys.clear()

    if (this.config.debug) {
      console.log('[WebToken] MemoryStore disconnected')
    }
  }

  /**
   * Get store statistics
   */
  getStats(): { tokens: number; users: number; sessions: number; compositeKeys: number } {
    return {
      tokens: this.revokedTokens.size,
      users: this.userTokens.size,
      sessions: this.revokedSessions.size,
      compositeKeys: this.compositeKeys.size,
    }
  }
}

/**
 * Token revocation types and interfaces
 */

import type { DecodedToken } from '../types/index.js'
import type { IdentifierConfig } from '../types/identifiers.js'

/**
 * Revocation identifier with all possible fields
 */
export interface RevocationIdentifier {
  /** Token ID (jti claim) */
  jti: string
  /** User ID (from payload.data or sub claim) */
  userId?: string
  /** Session ID (from payload.data.sessionId) */
  sessionId?: string
  /** Token expiration timestamp (for TTL) */
  exp: number
  /** Revocation timestamp */
  revokedAt: number
  /** Optional reason for revocation */
  reason?: string
}

/**
 * Configuration for revocation stores
 */
export interface RevocationStoreConfig {
  /** Auto cleanup interval in milliseconds */
  autoCleanupInterval?: number
  /** Prefix for keys (Redis) */
  keyPrefix?: string
  /** Enable debug logging */
  debug?: boolean
  /** Identifier configuration for extracting tokens */
  identifierConfig?: IdentifierConfig
}

/**
 * Redis store specific configuration
 */
export interface RedisStoreConfig extends RevocationStoreConfig {
  /** Redis host */
  host?: string
  /** Redis port */
  port?: number
  /** Redis password */
  password?: string
  /** Redis database number */
  db?: number
  /** Redis connection URL (overrides host/port) */
  url?: string
  /** Existing Redis client instance */
  client?: any
}

/**
 * SQLite store specific configuration
 */
export interface SQLiteStoreConfig extends RevocationStoreConfig {
  /** Database file path */
  database?: string
  /** Use in-memory database */
  memory?: boolean
  /** Existing database connection */
  connection?: any
}

/**
 * Abstract base class for revocation stores
 */
export abstract class RevocationStore {
  protected config: RevocationStoreConfig
  protected cleanupTimer?: NodeJS.Timeout
  /** Identifier configuration for extracting tokens */
  protected identifierConfig?: IdentifierConfig

  constructor(config: RevocationStoreConfig = {}) {
    this.config = {
      autoCleanupInterval: 60000, // 60 seconds default
      keyPrefix: 'webtoken:revoke:',
      debug: false,
      ...config,
    }
    this.identifierConfig = config.identifierConfig
  }

  /**
   * Revoke a token by its identifier
   */
  abstract revoke(identifier: RevocationIdentifier): Promise<void>

  /**
   * Check if a token is revoked by jti
   */
  abstract isRevoked(jti: string): Promise<boolean>

  /**
   * Get all revoked tokens for a user
   */
  abstract getRevokedTokensForUser(userId: string): Promise<string[]> // Returns JTIs

  /**
   * Revoke all tokens for a user
   */
  abstract revokeAllForUser(userId: string, reason?: string): Promise<void>

  /**
   * Revoke a session
   */
  abstract revokeSession(sessionId: string, reason?: string): Promise<void>

  /**
   * Check if a session is revoked
   */
  abstract isSessionRevoked(sessionId: string): Promise<boolean>

  /**
   * Check if a user's all tokens should be rejected
   */
  abstract isUserRevoked(userId: string): Promise<boolean>

  /**
   * Revoke by composite key
   */
  abstract revokeByCompositeKey(key: string, components: Record<string, string>, exp: number, reason?: string): Promise<void>

  /**
   * Check if a composite key is revoked
   */
  abstract isCompositeKeyRevoked(key: string): Promise<boolean>

  /**
   * Manual cleanup of expired entries
   */
  abstract cleanup(): Promise<number> // Returns count of cleaned entries

  /**
   * Start automatic cleanup at intervals
   */
  startAutoCleanup(intervalMs?: number): void {
    const interval = intervalMs || this.config.autoCleanupInterval
    
    if (!interval || interval <= 0) {
      return
    }

    this.stopAutoCleanup() // Clear existing timer

    this.cleanupTimer = setInterval(async () => {
      try {
        const cleaned = await this.cleanup()
        if (this.config.debug && cleaned > 0) {
          console.log(`[WebToken] Cleanup removed ${cleaned} expired entries`)
        }
      } catch (error) {
        if (this.config.debug) {
          console.error('[WebToken] Cleanup error:', error)
        }
      }
    }, interval)

    if (this.config.debug) {
      console.log(`[WebToken] Auto-cleanup started with ${interval}ms interval`)
    }
  }

  /**
   * Stop automatic cleanup
   */
  stopAutoCleanup(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer)
      this.cleanupTimer = undefined
      
      if (this.config.debug) {
        console.log('[WebToken] Auto-cleanup stopped')
      }
    }
  }

  /**
   * Disconnect from store (cleanup resources)
   */
  abstract disconnect(): Promise<void>

  /**
   * Extract revocation identifier from decoded token
   */
  static extractIdentifier(token: DecodedToken, reason?: string): RevocationIdentifier {
    const payload = token.payload
    const now = Math.floor(Date.now() / 1000)

    return {
      jti: payload.jti || '',
      userId: payload.sub || (payload.data && typeof payload.data === 'object' ? (payload.data as any).userId : undefined),
      sessionId: payload.data && typeof payload.data === 'object' ? (payload.data as any).sessionId : undefined,
      exp: payload.exp || now + 3600, // Default 1 hour if not set
      revokedAt: now,
      reason,
    }
  }

  /**
   * Check if identifier has valid jti
   */
  protected hasValidJti(identifier: RevocationIdentifier): boolean {
    return !!identifier.jti && identifier.jti.length > 0
  }
}

/**
 * Error thrown when token is revoked
 */
export class TokenRevokedError extends Error {
  constructor(
    public jti: string,
    public revokedAt: Date,
    public reason?: string,
    public revokedIdentifierType?: 'jti' | 'user' | 'session' | 'composite',
    public revokedIdentifierValue?: string
  ) {
    super(`Token has been revoked${reason ? `: ${reason}` : ''}`)
    this.name = 'TokenRevokedError'
  }
}

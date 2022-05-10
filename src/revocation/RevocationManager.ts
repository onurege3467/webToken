/**
 * High-level revocation manager with convenient API
 */

import { RevocationStore, RevocationIdentifier } from './types.js'
import type { DecodedToken } from '../types/index.js'
import { IdentifierExtractor } from './IdentifierExtractor.js'
import type { ExtractedIdentifiers, IdentifierConfig } from '../types/identifiers.js'

export interface RevocationManagerConfig {
  store: RevocationStore
  /** Throw error on revocation check fail (default: true) */
  throwOnRevoked?: boolean
  /** Enable debug logging */
  debug?: boolean
  /** Identifier configuration for flexible extraction */
  identifierConfig?: IdentifierConfig
}

export class RevocationManager {
  private store: RevocationStore
  private config: RevocationManagerConfig

  constructor(config: RevocationManagerConfig) {
    this.store = config.store
    this.config = {
      throwOnRevoked: true,
      debug: false,
      ...config,
    }

    if (this.config.debug) {
      console.log('[WebToken] RevocationManager initialized')
    }
  }

  /**
   * Revoke a token
   */
  async revokeToken(
    token: string | DecodedToken,
    reason?: string
  ): Promise<void> {
    let identifier: RevocationIdentifier

    if (typeof token === 'string') {
      // If string, we need to decode it first (without verification)
      // This is safe as we're just extracting the jti
      const { decodeToken } = await import('../core/Token.js')
      try {
        const decoded = decodeToken(token)
        identifier = RevocationStore.extractIdentifier(decoded, reason)
      } catch (error) {
        throw new Error(`Failed to decode token for revocation: ${(error as Error).message}`)
      }
    } else {
      identifier = RevocationStore.extractIdentifier(token, reason)
    }

    if (!identifier.jti) {
      throw new Error('Cannot revoke token without jti claim')
    }

    await this.store.revoke(identifier)

    if (this.config.debug) {
      console.log(`[WebToken] Token revoked: ${identifier.jti}${reason ? ` (${reason})` : ''}`)
    }
  }

  /**
   * Revoke a token by JTI directly
   */
  async revokeByJti(
    jti: string,
    exp: number,
    options?: { userId?: string; sessionId?: string; reason?: string }
  ): Promise<void> {
    const identifier: RevocationIdentifier = {
      jti,
      userId: options?.userId,
      sessionId: options?.sessionId,
      exp,
      revokedAt: Math.floor(Date.now() / 1000),
      reason: options?.reason,
    }

    await this.store.revoke(identifier)

    if (this.config.debug) {
      console.log(`[WebToken] Token revoked by JTI: ${jti}`)
    }
  }

  /**
   * Revoke by composite key components
   */
  async revokeByCompositeKey(
    components: string[],
    exp: number,
    reason?: string
  ): Promise<void> {
    const compositeKey = components.join(':')
    const identifier: RevocationIdentifier = {
      jti: compositeKey,
      exp,
      revokedAt: Math.floor(Date.now() / 1000),
      reason,
    }

    await this.store.revoke(identifier)

    if (this.config.debug) {
      console.log(`[WebToken] Token revoked by composite key: ${compositeKey}${reason ? ` (${reason})` : ''}`)
    }
  }

  /**
   * Revoke a token with flexible identifier extraction
   */
  async revokeTokenFlexible(
    token: string | DecodedToken,
    config?: IdentifierConfig,
    reason?: string
  ): Promise<void> {
    let payload: any
    let exp: number | undefined

    if (typeof token === 'string') {
      const { decodeToken } = await import('../core/Token.js')
      try {
        const decoded = decodeToken(token)
        payload = decoded.payload
        exp = decoded.payload.exp
      } catch (error) {
        throw new Error(`Failed to decode token for revocation: ${(error as Error).message}`)
      }
    } else {
      payload = token.payload
      exp = token.payload.exp
    }

    const mergedConfig = this.mergeConfigs(this.config.identifierConfig, config)
    const identifiers = IdentifierExtractor.extractIdentifiers(payload, mergedConfig)

    // Try to revoke by composite key first if available
    if (identifiers.compositeKey && exp) {
      await this.revokeByCompositeKey(
        [identifiers.compositeKey],
        exp,
        reason
      )
      return
    }

    // Then try JTI
    if (identifiers.jti && exp) {
      await this.revokeByJti(
        identifiers.jti,
        exp,
        {
          userId: identifiers.userId,
          sessionId: identifiers.sessionId,
          reason
        }
      )
      return
    }

    // Fall back to user/session revocation if available
    if (identifiers.userId) {
      await this.revokeUser(identifiers.userId, reason)
      return
    }

    if (identifiers.sessionId) {
      await this.revokeSession(identifiers.sessionId, reason)
      return
    }

    throw new Error('Cannot revoke token: no valid identifiers found')
  }

  /**
   * Revoke all tokens for a user
   */
  async revokeUser(userId: string, reason?: string): Promise<void> {
    await this.store.revokeAllForUser(userId, reason)

    if (this.config.debug) {
      console.log(`[WebToken] All tokens revoked for user: ${userId}${reason ? ` (${reason})` : ''}`)
    }
  }

  /**
   * Revoke a session
   */
  async revokeSession(sessionId: string, reason?: string): Promise<void> {
    await this.store.revokeSession(sessionId, reason)

    if (this.config.debug) {
      console.log(`[WebToken] Session revoked: ${sessionId}${reason ? ` (${reason})` : ''}`)
    }
  }

  /**
   * Check if a token is revoked during verification
   * This is called automatically by verifyToken
   */
  async checkRevoked(token: DecodedToken, tokenConfig?: IdentifierConfig): Promise<boolean> {
    // Get token-specific config from token payload if available
    const payloadConfig = (token.payload as any).identifierConfig as IdentifierConfig | undefined
    // Merge configs: store config -> payload config -> explicit tokenConfig
    let mergedConfig = this.mergeConfigs(this.config.identifierConfig, payloadConfig)
    mergedConfig = this.mergeConfigs(mergedConfig, tokenConfig)
    
    // Use IdentifierExtractor to extract all identifiers
    const identifiers = IdentifierExtractor.extractIdentifiers(token.payload, mergedConfig)

    // Check if token is revoked by JTI
    if (identifiers.jti) {
      const isRevoked = await this.store.isRevoked(identifiers.jti)
      if (isRevoked) {
        if (this.config.debug) {
          console.log(`[WebToken] Token revoked (jti): ${identifiers.jti}`)
        }
        return true
      }
    }

    // Check if token is revoked by composite key
    if (identifiers.compositeKey) {
      // First check via store's isRevoked (in case it's stored as a regular token)
      const isRevoked = await this.store.isRevoked(identifiers.compositeKey)
      if (isRevoked) {
        if (this.config.debug) {
          console.log(`[WebToken] Token revoked (composite key): ${identifiers.compositeKey}`)
        }
        return true
      }
      // Also check via isCompositeKeyRevoked if available
      if ('isCompositeKeyRevoked' in this.store) {
        const isCompositeRevoked = await (this.store as any).isCompositeKeyRevoked(identifiers.compositeKey)
        if (isCompositeRevoked) {
          if (this.config.debug) {
            console.log(`[WebToken] Token revoked (composite key): ${identifiers.compositeKey}`)
          }
          return true
        }
      }
    }

    // Check if user is revoked
    if (identifiers.userId) {
      const isUserRevoked = await this.isUserRevoked(identifiers.userId)
      if (isUserRevoked) {
        if (this.config.debug) {
          console.log(`[WebToken] User revoked: ${identifiers.userId}`)
        }
        return true
      }
    }

    // Check if session is revoked
    if (identifiers.sessionId) {
      const isSessionRevoked = await this.store.isSessionRevoked(identifiers.sessionId)
      if (isSessionRevoked) {
        if (this.config.debug) {
          console.log(`[WebToken] Session revoked: ${identifiers.sessionId}`)
        }
        return true
      }
    }

    return false
  }

  /**
   * Check if a specific token is revoked
   */
  async isRevoked(jti: string): Promise<boolean> {
    return this.store.isRevoked(jti)
  }

  /**
   * Check if a user is revoked
   */
  async isUserRevoked(userId: string): Promise<boolean> {
    return this.store.isUserRevoked(userId)
  }

  /**
   * Check if a session is revoked
   */
  async isSessionRevoked(sessionId: string): Promise<boolean> {
    return this.store.isSessionRevoked(sessionId)
  }

  /**
   * Get all revoked tokens for a user
   */
  async getRevokedTokensForUser(userId: string): Promise<string[]> {
    return this.store.getRevokedTokensForUser(userId)
  }

  /**
   * Start automatic cleanup
   */
  startAutoCleanup(intervalMs?: number): void {
    this.store.startAutoCleanup(intervalMs)
  }

  /**
   * Stop automatic cleanup
   */
  stopAutoCleanup(): void {
    this.store.stopAutoCleanup()
  }

  /**
   * Manual cleanup
   */
  async cleanup(): Promise<number> {
    return this.store.cleanup()
  }

  /**
   * Disconnect and cleanup resources
   */
  async disconnect(): Promise<void> {
    await this.store.disconnect()

    if (this.config.debug) {
      console.log('[WebToken] RevocationManager disconnected')
    }
  }

  /**
   * Get the underlying store
   */
  getStore(): RevocationStore {
    return this.store
  }

  /**
   * Extract identifiers from a token payload using IdentifierExtractor
   */
  extractIdentifiers(payload: unknown, config?: IdentifierConfig): ExtractedIdentifiers {
    const mergedConfig = this.mergeConfigs(this.config.identifierConfig, config)
    return IdentifierExtractor.extractIdentifiers(payload, mergedConfig)
  }

  /**
   * Merge global config with per-token config
   * Per-token config takes precedence
   */
  mergeConfigs(
    storeConfig?: IdentifierConfig,
    tokenConfig?: IdentifierConfig
  ): IdentifierConfig | undefined {
    if (!storeConfig && !tokenConfig) {
      return undefined
    }

    if (!storeConfig) {
      return tokenConfig
    }

    if (!tokenConfig) {
      return storeConfig
    }

    return {
      userIdField: tokenConfig.userIdField ?? storeConfig.userIdField,
      userIdPath: tokenConfig.userIdPath ?? storeConfig.userIdPath,
      sessionIdPath: tokenConfig.sessionIdPath ?? storeConfig.sessionIdPath,
      compositeKey: tokenConfig.compositeKey ?? storeConfig.compositeKey,
      fallbackChain: tokenConfig.fallbackChain ?? storeConfig.fallbackChain,
      extractIdentifiers: tokenConfig.extractIdentifiers ?? storeConfig.extractIdentifiers,
    }
  }
}

/**
 * Create a revocation manager with the given store
 */
export function createRevocationManager(
  store: RevocationStore,
  options?: { throwOnRevoked?: boolean; debug?: boolean; identifierConfig?: IdentifierConfig }
): RevocationManager {
  return new RevocationManager({
    store,
    ...options,
  })
}

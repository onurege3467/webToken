/**
 * Identifier extraction utility for token payloads
 */

import { PathExtractor } from '../utils/PathExtractor.js'
import type {
  IdentifierConfig,
  ExtractedIdentifiers,
  CompositeKeyConfig,
} from '../types/identifiers.js'

/**
 * Default fallback chain for identifier extraction
 * Priority order for locating user identifiers in token payloads
 */
const DEFAULT_FALLBACK_CHAIN = [
  'sub',
  'userId',
  'uid',
  'user_id',
  'accountId',
  'memberId',
  'id',
  'data.userId',
  'data.uid',
  'data.user_id',
  'data.accountId',
  'data.id',
  'user?.id',
  'account?.userId',
]

/**
 * Extract identifiers from a token payload
 */
export class IdentifierExtractor {
  /**
   * Main extraction method that extracts all identifiers from a payload
   * Uses config paths first, then falls back to default chain
   */
  static extractIdentifiers(
    payload: unknown,
    config?: IdentifierConfig
  ): ExtractedIdentifiers {
    const identifiers: ExtractedIdentifiers = {}

    if (!payload || typeof payload !== 'object') {
      return identifiers
    }

    // Use custom extraction function if provided
    if (config?.extractIdentifiers) {
      try {
        const result = config.extractIdentifiers(payload)
        if (result && typeof result === 'object' && Object.keys(result).length > 0) {
          // If custom function returns valid identifiers, use them
          const hasValidIdentifier = result.userId || result.jti || result.sessionId || result.compositeKey
          if (hasValidIdentifier) {
            return { ...result }
          }
          // If empty result, fall through to default extraction
        }
      } catch (error) {
        // Continue with fallback methods
      }
    }

    // Extract user ID using configured path or fallback chain
    const userId = this.extractUserId(payload, config)
    if (userId !== undefined && userId !== null) {
      identifiers.userId = String(userId)
    }

    // Extract session ID using configured path or fallback chain
    const sessionId = this.extractSessionId(payload, config)
    if (sessionId !== undefined && sessionId !== null) {
      identifiers.sessionId = String(sessionId)
    }

    // Extract JTI (JWT ID) from payload
    const jti = PathExtractor.extract(payload, 'jti')
    if (jti !== undefined && jti !== null) {
      identifiers.jti = String(jti)
    }

    // Build composite key if configured
    if (config?.compositeKey) {
      identifiers.compositeKey = this.buildCompositeKey(payload, config.compositeKey)
    }

    return identifiers
  }

  /**
   * Extract a value from a payload using a specific path
   * Supports dot notation, array indices, and optional chaining
   */
  static extractByPath(payload: unknown, path: string): unknown {
    return PathExtractor.extract(payload, path)
  }

  /**
   * Extract identifiers using the fallback chain
   * Falls through the priority list until a value is found
   */
  static extractByFallback(
    payload: unknown,
    config?: IdentifierConfig
  ): ExtractedIdentifiers {
    const identifiers: ExtractedIdentifiers = {}

    if (!payload || typeof payload !== 'object') {
      return identifiers
    }

    // Determine which fallback chain to use
    const fallbackChain = config?.fallbackChain ?? DEFAULT_FALLBACK_CHAIN

    // Try each path in the fallback chain
    for (const path of fallbackChain) {
      const value = this.extractByPath(payload, path)
      if (value !== undefined && value !== null) {
        identifiers.userId = String(value)
        break
      }
    }

    return identifiers
  }

  /**
   * Build a composite key from multiple fields
   * Concatenates field values with a separator
   */
  static buildCompositeKey(
    payload: unknown,
    config: CompositeKeyConfig
  ): string | undefined {
    if (!payload || typeof payload !== 'object') {
      return undefined
    }

    if (!config.fields || config.fields.length === 0) {
      return undefined
    }

    const separator = config.separator ?? ':'
    const values: string[] = []

    for (const field of config.fields) {
      const value = this.extractByPath(payload, field)
      if (value !== undefined && value !== null) {
        values.push(String(value))
      } else {
        // If any field is missing, return undefined
        return undefined
      }
    }

    return values.join(separator)
  }

  /**
   * Private helper to extract user ID
   * Tries configured path first, then fallback chain
   */
  private static extractUserId(
    payload: unknown,
    config?: IdentifierConfig
  ): unknown {
    // Try configured path first
    if (config?.userIdPath) {
      const value = this.extractByPath(payload, config.userIdPath)
      if (value !== undefined && value !== null) {
        return value
      }
      // If userIdPath is configured but returns undefined, still fall through to default chain
    }

    // Try userIdField (string or array of strings)
    if (config?.userIdField) {
      const fields = Array.isArray(config.userIdField)
        ? config.userIdField
        : [config.userIdField]

      for (const field of fields) {
        const value = this.extractByPath(payload, field)
        if (value !== undefined && value !== null) {
          return value
        }
      }
    }

    // Fall back to default chain
    const fallbackResult = this.extractByFallback(payload, config)
    return fallbackResult.userId
  }

  /**
   * Private helper to extract session ID
   * Tries configured path first, then default session fields
   */
  private static extractSessionId(
    payload: unknown,
    config?: IdentifierConfig
  ): unknown {
    // Try configured path first
    if (config?.sessionIdPath) {
      const value = this.extractByPath(payload, config.sessionIdPath)
      if (value !== undefined && value !== null) {
        return value
      }
    }

    // Try default session fields
    const sessionFields = ['sessionId', 'session_id', 'sid', 'session', 'data.sessionId', 'data.sid']
    for (const field of sessionFields) {
      const value = this.extractByPath(payload, field)
      if (value !== undefined && value !== null) {
        return value
      }
    }

    return undefined
  }
}

export default IdentifierExtractor

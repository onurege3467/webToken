/**
 * Configuration management and validation
 */

import type { WebTokenConfig, TokenPayload, Algorithm, TokenFormat, TimeValue } from '../types/index.js'
import { parseTimeValue } from '../utils/index.js'

export interface ValidatedConfig<TPayload = Record<string, unknown>> extends WebTokenConfig<TPayload> {
  performance: Required<NonNullable<WebTokenConfig<TPayload>['performance']>>
  security: Required<NonNullable<WebTokenConfig<TPayload>['security']>>
}

export const DEFAULT_PERFORMANCE = {
  useBufferPool: true,
  maxPayloadSize: 10 * 1024 * 1024, // 10MB
  cacheValidations: false,
} as const

export const DEFAULT_SECURITY = {
  requireExpiration: true,
  maxClockSkew: 60, // 60 seconds
  allowedAlgorithms: ['v1.local', 'v1.public', 'v2.local'] as Algorithm[],
} as const

export class Config {
  /**
   * Validate and normalize configuration
   */
  static validate<TPayload>(config: WebTokenConfig<TPayload>): ValidatedConfig<TPayload> {
    // Validate required fields
    if (!config.algorithm) {
      throw new Error('Algorithm is required')
    }
    
    if (!config.format) {
      throw new Error('Format is required')
    }
    
    if (!config.expiresIn) {
      throw new Error('ExpiresIn is required')
    }
    
    // Validate algorithm
    const validAlgorithms: Algorithm[] = ['v1.local', 'v1.public', 'v2.local']
    if (!validAlgorithms.includes(config.algorithm)) {
      throw new Error(`Invalid algorithm: ${config.algorithm}. Must be one of: ${validAlgorithms.join(', ')}`)
    }
    
    // Validate format
    const validFormats: TokenFormat[] = ['binary', 'protobuf']
    if (!validFormats.includes(config.format)) {
      throw new Error(`Invalid format: ${config.format}. Must be one of: ${validFormats.join(', ')}`)
    }
    
    // Validate payload
    if (config.payload === undefined || config.payload === null) {
      throw new Error('Payload is required')
    }
    
    // Merge with defaults
    return {
      ...config,
      performance: {
        ...DEFAULT_PERFORMANCE,
        ...config.performance,
      },
      security: {
        ...DEFAULT_SECURITY,
        ...config.security,
      },
    }
  }

  /**
   * Build token payload from config
   */
  static buildPayload<TPayload>(config: ValidatedConfig<TPayload>): TokenPayload<TPayload> {
    const payload: TokenPayload<TPayload> = {
      data: config.payload,
    }
    
    // Set issuer
    if (config.issuer) {
      payload.iss = config.issuer
    }
    
    // Set subject
    if (config.subject) {
      payload.sub = config.subject
    }
    
    // Set audience
    if (config.audience) {
      payload.aud = config.audience
    }
    
    // Set issued at
    if (config.issuedAt === true) {
      payload.iat = Math.floor(Date.now() / 1000)
    } else if (config.issuedAt !== false && config.issuedAt !== undefined) {
      payload.iat = Math.floor(parseTimeValue(config.issuedAt) / 1000)
    }
    
    // Set not before
    if (config.notBefore) {
      const nbfValue = parseTimeValue(config.notBefore)
      payload.nbf = Math.floor(nbfValue / 1000)
    }
    
    // Set expiration
    const expiresInMs = parseTimeValue(config.expiresIn)
    const now = Date.now()
    payload.exp = Math.floor((now + expiresInMs) / 1000)
    
    // Set token ID
    if (config.tokenId) {
      payload.jti = typeof config.tokenId === 'function' 
        ? config.tokenId() 
        : config.tokenId
    }
    
    return payload
  }

  /**
   * Parse time value to milliseconds
   */
  static parseTime(value: TimeValue): number {
    return parseTimeValue(value)
  }
}

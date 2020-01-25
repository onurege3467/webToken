/**
 * Core Token class - main API for creating and verifying tokens
 */

import type { 
  WebTokenConfig, 
  VerifyOptions, 
  DecodedToken, 
  TokenResult,
  TokenHeader,
  TokenPayload
} from '../types/index.js'
import { 
  WebTokenError,
  TokenExpiredError,
  TokenNotBeforeError,
  InvalidTokenError,
  InvalidSignatureError,
  AlgorithmMismatchError,
  TokenRevokedError
} from '../types/index.js'
import type { IdentifierConfig } from '../types/identifiers.js'
import { Config } from '../config/index.js'
import { Encoder } from '../formats/index.js'
import { CryptoEngine } from '../algorithms/index.js'
import { base64UrlEncode, base64UrlDecode, getCurrentTimestamp } from '../utils/index.js'
import { IdentifierExtractor } from '../revocation/IdentifierExtractor.js'

export class Token {
  /**
   * Create a new token
   */
  static async create<TPayload = Record<string, unknown>>(
    config: WebTokenConfig<TPayload>
  ): Promise<TokenResult> {
    // Validate and normalize config
    const validatedConfig = Config.validate(config)
    
    // Build payload
    const payload = Config.buildPayload(validatedConfig)
    
    // Build header
    const header: TokenHeader = {
      version: CryptoEngine.getVersion(validatedConfig.algorithm),
      purpose: CryptoEngine.getPurpose(validatedConfig.algorithm),
      format: validatedConfig.format,
    }
    
    // Encode header and payload
    const encoded = Encoder.encode(header, payload as TokenPayload<Record<string, unknown>>, validatedConfig.format)
    
    // Encrypt or sign based on algorithm
    let token: string
    
    if (CryptoEngine.isLocal(validatedConfig.algorithm)) {
      // Symmetric encryption
      const engine = new CryptoEngine(validatedConfig.algorithm)
      const key = await engine.generateKey()
      const encrypted = await engine.encrypt(encoded, key)
      
      // Token format: base64url(key) + "." + base64url(encrypted)
      token = `${base64UrlEncode(key)}.${base64UrlEncode(encrypted)}`
    } else {
      // Asymmetric signing
      const engine = new CryptoEngine(validatedConfig.algorithm)
      const keyPair = await engine.generateKeyPair()
      const signature = await engine.sign(encoded, keyPair.privateKey)
      
      // Token format: base64url(encoded) + "." + base64url(signature)
      token = `${base64UrlEncode(encoded)}.${base64UrlEncode(signature)}`
    }
    
    return {
      token,
      expiresAt: new Date(payload.exp! * 1000),
      issuedAt: new Date(payload.iat! * 1000),
    }
  }

  /**
   * Verify and decode a token
   */
  static async verify<TPayload = Record<string, unknown>>(
    token: string,
    options: VerifyOptions
  ): Promise<DecodedToken<TPayload>> {
    try {
      const parts = token.split('.')
      
      if (parts.length !== 2) {
        throw new InvalidTokenError('Invalid token format')
      }
      
      const part1 = base64UrlDecode(parts[0]!)
      const part2 = base64UrlDecode(parts[1]!)
      
      let header: TokenHeader
      let payload: TokenPayload
      
      // Check if user provided a secret (for local tokens) or public key (for public tokens)
      if (options.secret) {
        // User provided a secret, treat as local token
        const secret = typeof options.secret === 'string' 
          ? Buffer.from(options.secret, 'utf8')
          : options.secret
          
        const engine = new CryptoEngine('v1.local')
        const decrypted = await engine.decrypt(part2, secret)
        const decoded = Encoder.decode(decrypted, 'binary')
        header = decoded.header
        payload = decoded.payload
      } else if (options.publicKey) {
        // User provided a public key, treat as public token
        const decoded = Encoder.decode(part1, 'binary')
        header = decoded.header
        payload = decoded.payload
        
        // Verify signature
        const publicKey = typeof options.publicKey === 'string'
          ? Buffer.from(options.publicKey, 'base64')
          : options.publicKey
        const engine = new CryptoEngine('v1.public')
        const valid = await engine.verify(part1, part2, publicKey)
        if (!valid) {
          throw new InvalidSignatureError()
        }
      } else {
        // Try to auto-detect: check if part1 looks like an encoded payload
        try {
          // Try as public token first (encoded data in part1)
          const decoded = Encoder.decode(part1, 'binary')
          header = decoded.header
          payload = decoded.payload
          
          // Can't verify without a public key
          throw new InvalidTokenError('Public key required to verify signed tokens')
        } catch (error) {
          if (error instanceof InvalidTokenError) {
            throw error
          }
          // Try as local token (key in part1, encrypted in part2)
          throw new InvalidTokenError('Secret key required to decrypt encrypted tokens')
        }
      }
      
      // Validate algorithm if specified
      if (options.algorithms && options.algorithms.length > 0) {
        const tokenAlgorithm = `${header.version}.${header.purpose}` as 'v1.local' | 'v1.public' | 'v2.local'
        if (!options.algorithms.includes(tokenAlgorithm)) {
          throw new AlgorithmMismatchError(options.algorithms[0]!, tokenAlgorithm)
        }
      }
      
      // Validate issuer if specified
      if (options.issuer) {
        const issuers = Array.isArray(options.issuer) ? options.issuer : [options.issuer]
        if (!payload.iss || !issuers.includes(payload.iss)) {
          throw new InvalidTokenError('Invalid issuer')
        }
      }
      
      // Validate audience if specified
      if (options.audience) {
        const audiences = Array.isArray(options.audience) ? options.audience : [options.audience]
        const tokenAudiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
        const hasMatch = tokenAudiences.some(aud => aud && audiences.includes(aud))
        if (!hasMatch) {
          throw new InvalidTokenError('Invalid audience')
        }
      }
      
      // Validate expiration
      if (payload.exp) {
        const now = getCurrentTimestamp()
        const tolerance = options.clockTolerance || 0
        if (now > payload.exp + tolerance) {
          throw new TokenExpiredError(new Date(payload.exp * 1000))
        }
      }
      
      // Validate not before
      if (payload.nbf) {
        const now = getCurrentTimestamp()
        const tolerance = options.clockTolerance || 0
        if (now < payload.nbf - tolerance) {
          throw new TokenNotBeforeError(new Date(payload.nbf * 1000))
        }
      }
      
      // Validate max age if specified
      if (options.maxAge && payload.iat) {
        const maxAgeSeconds = Config.parseTime(options.maxAge) / 1000
        const now = getCurrentTimestamp()
        if (now > payload.iat + maxAgeSeconds) {
          throw new TokenExpiredError(new Date((payload.iat + maxAgeSeconds) * 1000))
        }
      }

      // Check revocation if store provided
      if (options.revocationStore && !options.skipRevocationCheck) {
        const decodedToken: DecodedToken<TPayload> = {
          header,
          payload: payload as TokenPayload<TPayload>,
          signature: part2,
          raw: {
            header: Buffer.from(JSON.stringify(header)),
            payload: Buffer.from(JSON.stringify(payload)),
            signature: part2,
          },
        }

        const { RevocationManager } = await import('../revocation/RevocationManager.js')
        const manager = new RevocationManager({ store: options.revocationStore })
        
        // Get store config from revocation store if available
        const storeConfig = (options.revocationStore as any).identifierConfig as IdentifierConfig | undefined
        
        // Merge store config with per-token config if both exist
        const mergedConfig = Token.mergeIdentifierConfigs(storeConfig, options.identifierConfig)
        
        // Extract identifiers using IdentifierExtractor
        const identifiers = IdentifierExtractor.extractIdentifiers(payload, mergedConfig)
        
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const isRevoked = await manager.checkRevoked(decodedToken as DecodedToken<any>)

        if (isRevoked) {
          if (options.onRevoked) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            options.onRevoked(decodedToken as DecodedToken<any>)
          }
          
          // Find which identifier was revoked for better error message
          const identifierType = identifiers.compositeKey ? 'composite' : 
                                 identifiers.jti ? 'jti' : 
                                 identifiers.userId ? 'user' : 
                                 identifiers.sessionId ? 'session' : 'unknown'
          const identifierValue = identifiers.compositeKey || 
                                  identifiers.jti || 
                                  identifiers.userId || 
                                  identifiers.sessionId || 
                                  'unknown'
          
          throw new TokenRevokedError(
            payload.jti || 'unknown',
            new Date(),
            `Token has been revoked (${identifierType}: ${identifierValue})`
          )
        }
      }

      return {
        header,
        payload: payload as TokenPayload<TPayload>,
        signature: part2,
        raw: {
          header: Buffer.from(JSON.stringify(header)),
          payload: Buffer.from(JSON.stringify(payload)),
          signature: part2,
        },
      }
    } catch (error) {
      if (error instanceof WebTokenError) {
        throw error
      }
      throw new InvalidTokenError(`Token verification failed: ${(error as Error).message}`)
    }
  }

  /**
   * Merge global/store config with per-token config
   * Per-token config takes precedence
   */
  private static mergeIdentifierConfigs(
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

  /**
   * Decode a token without verification (unsafe)
   * Only use this for debugging, always verify tokens in production
   */
  static decode<TPayload = Record<string, unknown>>(token: string): DecodedToken<TPayload> {
    try {
      const parts = token.split('.')
      
      if (parts.length !== 2) {
        throw new InvalidTokenError('Invalid token format')
      }
      
      const part1 = base64UrlDecode(parts[0]!)
      const part2 = base64UrlDecode(parts[1]!)
      
      // Try to decode without decryption
      let decoded: { header: TokenHeader; payload: TokenPayload }
      
      try {
        // Try as public token
        decoded = Encoder.decode(part1, 'binary')
      } catch {
        // Can't decode encrypted tokens without the key
        throw new InvalidTokenError('Cannot decode encrypted tokens without the decryption key')
      }
      
      return {
        header: decoded.header,
        payload: decoded.payload as TokenPayload<TPayload>,
        signature: part2,
        raw: {
          header: Buffer.from(JSON.stringify(decoded.header)),
          payload: Buffer.from(JSON.stringify(decoded.payload)),
          signature: part2,
        },
      }
    } catch (error) {
      throw new InvalidTokenError(`Token decode failed: ${(error as Error).message}`)
    }
  }

  /**
   * Generate a secure token ID
   */
  static generateTokenId(): string {
    return `${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 11)}`
  }
}

// Export main functions for convenience
export async function createToken<TPayload = Record<string, unknown>>(
  config: WebTokenConfig<TPayload>
): Promise<TokenResult> {
  return Token.create(config)
}

export async function verifyToken<TPayload = Record<string, unknown>>(
  token: string,
  options: VerifyOptions
): Promise<DecodedToken<TPayload>> {
  return Token.verify(token, options)
}

export function decodeToken<TPayload = Record<string, unknown>>(token: string): DecodedToken<TPayload> {
  return Token.decode(token)
}

// Re-export all types
export * from '../types/index.js'

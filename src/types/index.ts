/**
 * Core types and interfaces for @onurege3467/webtoken
 * Provides type-safe token operations with full TypeScript support
 */

export type Algorithm = 'v1.local' | 'v1.public' | 'v2.local'
export type TokenFormat = 'binary' | 'protobuf'
export type TimeValue = number | string

export interface TokenHeader {
  version: 'v1' | 'v2'
  purpose: 'local' | 'public'
  format: TokenFormat
}

export interface TokenPayload<T = Record<string, unknown>> {
  iss?: string
  sub?: string
  aud?: string | string[]
  exp?: number
  nbf?: number
  iat?: number
  jti?: string
  data?: T
}

export interface WebTokenConfig<TPayload = Record<string, unknown>> {
  format: TokenFormat
  algorithm: Algorithm
  expiresIn: TimeValue
  notBefore?: TimeValue
  issuedAt?: boolean | TimeValue
  issuer?: string
  audience?: string | string[]
  subject?: string
  tokenId?: string | (() => string)
  payload: TPayload
  performance?: {
    useBufferPool?: boolean
    maxPayloadSize?: number
    cacheValidations?: boolean
  }
  security?: {
    requireExpiration?: boolean
    maxClockSkew?: number
    allowedAlgorithms?: Algorithm[]
  }
}

export interface VerifyOptions {
  secret?: string | Buffer
  publicKey?: string | Buffer
  algorithms?: Algorithm[]
  issuer?: string | string[]
  audience?: string | string[]
  clockTolerance?: number
  maxAge?: TimeValue
  
  // Revocation options
  revocationStore?: import('../revocation/types.js').RevocationStore
  skipRevocationCheck?: boolean
  onRevoked?: (token: DecodedToken) => void
  identifierConfig?: import('../types/identifiers.js').IdentifierConfig
}

export interface DecodedToken<TPayload = Record<string, unknown>> {
  header: TokenHeader
  payload: TokenPayload<TPayload>
  signature: Buffer
  raw: {
    header: Buffer
    payload: Buffer
    signature: Buffer
  }
}

export interface TokenResult {
  token: string
  expiresAt: Date
  issuedAt: Date
}

export type EncodedToken = string

export interface CryptoKeyPair {
  publicKey: Buffer
  privateKey: Buffer
}

export interface ICryptoEngine {
  encrypt(data: Buffer, key: Buffer, aad?: Buffer): Promise<Buffer>
  decrypt(data: Buffer, key: Buffer, aad?: Buffer): Promise<Buffer>
  sign(data: Buffer, privateKey: Buffer): Promise<Buffer>
  verify(data: Buffer, signature: Buffer, publicKey: Buffer): Promise<boolean>
  generateKey(): Promise<Buffer>
  generateKeyPair?(): Promise<CryptoKeyPair>
}

export interface IEncoder {
  encode(header: TokenHeader, payload: TokenPayload, format: TokenFormat): Buffer
  decode(data: Buffer, format: TokenFormat): { header: TokenHeader; payload: TokenPayload }
  getEncodedSize(payload: TokenPayload): number
}

export class WebTokenError extends Error {
  constructor(message: string, public code: string) {
    super(message)
    this.name = 'WebTokenError'
  }
}

export class TokenExpiredError extends WebTokenError {
  constructor(public expiredAt: Date) {
    super('Token has expired', 'TOKEN_EXPIRED')
    this.name = 'TokenExpiredError'
  }
}

export class TokenNotBeforeError extends WebTokenError {
  constructor(public notBefore: Date) {
    super('Token not active yet', 'TOKEN_NOT_BEFORE')
    this.name = 'TokenNotBeforeError'
  }
}

export class InvalidTokenError extends WebTokenError {
  constructor(message: string) {
    super(message, 'INVALID_TOKEN')
    this.name = 'InvalidTokenError'
  }
}

export class InvalidSignatureError extends WebTokenError {
  constructor() {
    super('Invalid token signature', 'INVALID_SIGNATURE')
    this.name = 'InvalidSignatureError'
  }
}

export class AlgorithmMismatchError extends WebTokenError {
  constructor(expected: Algorithm, received: Algorithm) {
    super(`Algorithm mismatch: expected ${expected}, received ${received}`, 'ALGORITHM_MISMATCH')
    this.name = 'AlgorithmMismatchError'
  }
}

export class TokenRevokedError extends WebTokenError {
  constructor(
    public jti: string,
    public revokedAt: Date,
    public reason?: string,
    public revokedIdentifierType?: 'jti' | 'user' | 'session' | 'composite',
    public revokedIdentifierValue?: string
  ) {
    super(`Token has been revoked${reason ? `: ${reason}` : ''}`, 'TOKEN_REVOKED')
    this.name = 'TokenRevokedError'
  }
}

// Export identifier types
export type {
  IdentifierConfig,
  CompositeKeyConfig,
  ExtractedIdentifiers,
  IdentifierExtractionResult,
} from './identifiers.js'

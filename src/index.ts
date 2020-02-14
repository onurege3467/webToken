/**
 * @onurege3467/webtoken
 * High-performance, secure, and type-safe alternative to JWT
 * 
 * Features:
 * - Encrypted payloads (not just base64 encoded like JWT)
 * - TypeScript support with full auto-complete
 * - Multiple formats: binary (fastest) and protobuf (compatible)
 * - Algorithms: AES-256-GCM (v1.local) and Ed25519 (v1.public)
 * - Zero dependencies (optional protobufjs for protobuf format)
 * - Optimized for Node.js 20+
 * 
 * @example
 * ```typescript
 * import { createToken, verifyToken } from '@onurege3467/webtoken'
 * 
 * // Create a token
 * const { token } = await createToken({
 *   format: 'binary',
 *   algorithm: 'v1.local',
 *   payload: { userId: '123', role: 'admin' },
 *   expiresIn: '1h',
 *   issuer: 'my-app'
 * })
 * 
 * // Verify a token
 * const decoded = await verifyToken(token, {
 *   secret: 'your-secret-key'
 * })
 * ```
 */

// Main API
export {
  Token,
  createToken,
  verifyToken,
  decodeToken,
} from './core/Token.js'

// Types
export type {
  Algorithm,
  TokenFormat,
  TokenHeader,
  TokenPayload,
  WebTokenConfig,
  VerifyOptions,
  DecodedToken,
  TokenResult,
  EncodedToken,
  CryptoKeyPair,
  ICryptoEngine,
  IEncoder,
  TimeValue,
  IdentifierConfig,
  CompositeKeyConfig,
  ExtractedIdentifiers,
  IdentifierExtractionResult,
} from './types/index.js'

// Errors
export {
  WebTokenError,
  TokenExpiredError,
  TokenNotBeforeError,
  InvalidTokenError,
  InvalidSignatureError,
  AlgorithmMismatchError,
  TokenRevokedError,
} from './types/index.js'

// Algorithms
export {
  AES256GCM,
  Ed25519,
  CryptoEngine,
  type Ed25519KeyPair,
} from './algorithms/index.js'

// Formats
export {
  BinaryFormat,
  ProtobufFormat,
  Encoder,
} from './formats/index.js'

// Config
export {
  Config,
  DEFAULT_PERFORMANCE,
  DEFAULT_SECURITY,
  type ValidatedConfig,
} from './config/index.js'

// Utils
export {
  generateRandomBytes,
  base64UrlEncode,
  base64UrlDecode,
  base64Encode,
  base64Decode,
  secureCompare,
  parseTimeValue,
  getCurrentTimestamp,
  sha256,
  concatBuffers,
  isValidUtf8,
  stringToBuffer,
  bufferToString,
} from './utils/index.js'

// Path Extractor
export {
  PathExtractor,
} from './utils/PathExtractor.js'

// Revocation
export {
  RevocationStore,
  RevocationIdentifier,
  RevocationStoreConfig,
  RedisStoreConfig,
  SQLiteStoreConfig,
  MemoryStore,
  RedisStore,
  SQLiteStore,
  RevocationManager,
  createRevocationManager,
  IdentifierExtractor,
} from './revocation/index.js'

// Version
export const VERSION = '1.0.0'

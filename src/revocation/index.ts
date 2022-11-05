/**
 * Token revocation system for @onurege3467/webtoken
 * 
 * Provides multiple storage backends:
 * - MemoryStore: In-memory storage for single-server apps
 * - RedisStore: Distributed storage with native TTL
 * - SQLiteStore: Persistent file-based storage
 */

// Types
export {
  RevocationStore,
  RevocationIdentifier,
  RevocationStoreConfig,
  RedisStoreConfig,
  SQLiteStoreConfig,
  TokenRevokedError,
} from './types.js'

// Stores
export { MemoryStore } from './MemoryStore.js'
export { RedisStore } from './RedisStore.js'
export { SQLiteStore } from './SQLiteStore.js'

// Manager
export {
  RevocationManager,
  RevocationManagerConfig,
  createRevocationManager,
} from './RevocationManager.js'

// Identifier Extraction
export { IdentifierExtractor } from './IdentifierExtractor.js'

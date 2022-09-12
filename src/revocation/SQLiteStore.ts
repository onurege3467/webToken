/**
 * SQLite-based revocation store implementation
 * Best for single-server applications with persistent storage
 */

import { RevocationStore, RevocationIdentifier, SQLiteStoreConfig } from './types.js'

interface DatabaseInstance {
  prepare(sql: string): Statement
  exec(sql: string): void
  close(): void
}

interface Statement {
  run(...params: any[]): { changes: number; lastInsertRowid: number }
  get(...params: any[]): any
  all(...params: any[]): any[]
}

export class SQLiteStore extends RevocationStore {
  protected declare config: SQLiteStoreConfig
  private db: DatabaseInstance | null = null
  private initialized = false
  private Database: any = null

  constructor(config: SQLiteStoreConfig = {}) {
    super(config)
    this.config = {
      database: './webtoken-revocations.db',
      memory: false,
      ...config,
    }
  }

  private async initialize(): Promise<void> {
    if (this.initialized) return

    if (this.config.connection) {
      this.db = this.config.connection
      this.createTables()
      this.initialized = true
      return
    }

    // Dynamic import better-sqlite3
    if (!this.Database) {
      try {
        const sqlite = await import('better-sqlite3')
        this.Database = sqlite.default || sqlite
      } catch {
        throw new Error(
          'better-sqlite3 is not installed. Please install it: npm install better-sqlite3'
        )
      }
    }

    if (this.config.memory) {
      this.db = new this.Database(':memory:')
    } else {
      this.db = new this.Database(this.config.database!)
    }

    this.createTables()
    this.initialized = true

    if (this.config.debug) {
      console.log(`[WebToken] SQLiteStore initialized: ${this.config.memory ? ':memory:' : this.config.database}`)
    }
  }

  private createTables(): void {
    if (!this.db) return

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS revoked_tokens (
        jti TEXT PRIMARY KEY,
        user_id TEXT,
        session_id TEXT,
        composite_key TEXT,
        identifiers_json TEXT,
        exp INTEGER NOT NULL,
        revoked_at INTEGER NOT NULL,
        reason TEXT
      )
    `)

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS revoked_users (
        user_id TEXT PRIMARY KEY,
        revoked_at INTEGER NOT NULL,
        reason TEXT
      )
    `)

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS revoked_sessions (
        session_id TEXT PRIMARY KEY,
        jti TEXT,
        revoked_at INTEGER NOT NULL,
        reason TEXT
      )
    `)

    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON revoked_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_tokens_session_id ON revoked_tokens(session_id);
      CREATE INDEX IF NOT EXISTS idx_tokens_exp ON revoked_tokens(exp);
      CREATE INDEX IF NOT EXISTS idx_composite_key ON revoked_tokens(composite_key);
    `)
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initialize()
    }
    if (!this.db) {
      throw new Error('SQLiteStore not initialized')
    }
  }

  async revoke(identifier: RevocationIdentifier): Promise<void> {
    await this.ensureInitialized()

    if (!this.hasValidJti(identifier)) {
      throw new Error('Cannot revoke token without jti')
    }

    const stmt = this.db!.prepare(`
      INSERT OR REPLACE INTO revoked_tokens 
      (jti, user_id, session_id, exp, revoked_at, reason, identifiers_json) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)

    const identifiersJson = identifier.userId || identifier.sessionId 
      ? JSON.stringify({ userId: identifier.userId, sessionId: identifier.sessionId })
      : null

    stmt.run(
      identifier.jti,
      identifier.userId || null,
      identifier.sessionId || null,
      identifier.exp,
      identifier.revokedAt,
      identifier.reason || null,
      identifiersJson
    )

    if (identifier.sessionId) {
      const sessionStmt = this.db!.prepare(`
        INSERT OR REPLACE INTO revoked_sessions 
        (session_id, jti, revoked_at, reason) 
        VALUES (?, ?, ?, ?)
      `)

      sessionStmt.run(
        identifier.sessionId,
        identifier.jti,
        identifier.revokedAt,
        identifier.reason || null
      )
    }

    if (this.config.debug) {
      console.log(`[WebToken] Revoked token in SQLite: ${identifier.jti}`)
    }
  }

  async revokeByCompositeKey(
    key: string,
    components: Record<string, string>,
    exp: number,
    reason?: string
  ): Promise<void> {
    await this.ensureInitialized()

    const now = Math.floor(Date.now() / 1000)
    const identifiersJson = JSON.stringify(components)

    const stmt = this.db!.prepare(`
      INSERT OR REPLACE INTO revoked_tokens 
      (jti, composite_key, identifiers_json, exp, revoked_at, reason) 
      VALUES (?, ?, ?, ?, ?, ?)
    `)

    stmt.run(
      key,
      key,
      identifiersJson,
      exp,
      now,
      reason || null
    )

    if (this.config.debug) {
      console.log(`[WebToken] Revoked by composite key in SQLite: ${key}`)
    }
  }

  async isRevoked(jti: string): Promise<boolean> {
    await this.ensureInitialized()

    const stmt = this.db!.prepare(`
      SELECT 1 FROM revoked_tokens 
      WHERE jti = ? AND exp > ?
    `)

    const now = Math.floor(Date.now() / 1000)
    const result = stmt.get(jti, now)

    return result !== undefined
  }

  async isCompositeKeyRevoked(key: string): Promise<boolean> {
    await this.ensureInitialized()

    const stmt = this.db!.prepare(`
      SELECT 1 FROM revoked_tokens 
      WHERE composite_key = ? AND exp > ?
    `)

    const now = Math.floor(Date.now() / 1000)
    const result = stmt.get(key, now)

    return result !== undefined
  }

  async getRevokedTokensForUser(userId: string): Promise<string[]> {
    await this.ensureInitialized()

    const stmt = this.db!.prepare(`
      SELECT jti FROM revoked_tokens 
      WHERE user_id = ? AND exp > ?
    `)

    const now = Math.floor(Date.now() / 1000)
    const results = stmt.all(userId, now)

    return results.map((row: any) => row.jti)
  }

  async revokeAllForUser(userId: string, reason?: string): Promise<void> {
    await this.ensureInitialized()

    const now = Math.floor(Date.now() / 1000)

    const updateStmt = this.db!.prepare(`
      UPDATE revoked_tokens 
      SET revoked_at = ?, reason = ?
      WHERE user_id = ? AND exp > ?
    `)

    updateStmt.run(now, reason || 'User revoked', userId, now)

    const userStmt = this.db!.prepare(`
      INSERT OR REPLACE INTO revoked_users 
      (user_id, revoked_at, reason) 
      VALUES (?, ?, ?)
    `)

    userStmt.run(userId, now, reason || 'User revoked')

    if (this.config.debug) {
      console.log(`[WebToken] Revoked all tokens for user: ${userId}`)
    }
  }

  async revokeSession(sessionId: string, reason?: string): Promise<void> {
    await this.ensureInitialized()

    const now = Math.floor(Date.now() / 1000)

    const findStmt = this.db!.prepare(`
      SELECT jti FROM revoked_tokens 
      WHERE session_id = ? AND exp > ?
    `)

    const result = findStmt.get(sessionId, now)

    const insertStmt = this.db!.prepare(`
      INSERT OR REPLACE INTO revoked_sessions 
      (session_id, jti, revoked_at, reason) 
      VALUES (?, ?, ?, ?)
    `)

    insertStmt.run(sessionId, result?.jti || null, now, reason || null)

    if (this.config.debug) {
      console.log(`[WebToken] Revoked session in SQLite: ${sessionId}`)
    }
  }

  async isSessionRevoked(sessionId: string): Promise<boolean> {
    await this.ensureInitialized()

    const stmt = this.db!.prepare(`
      SELECT 1 FROM revoked_sessions 
      WHERE session_id = ?
    `)

    const result = stmt.get(sessionId)
    return result !== undefined
  }

  async isUserRevoked(userId: string): Promise<boolean> {
    await this.ensureInitialized()

    const stmt = this.db!.prepare(`
      SELECT 1 FROM revoked_users 
      WHERE user_id = ?
    `)

    const result = stmt.get(userId)
    return result !== undefined
  }

  async cleanup(): Promise<number> {
    await this.ensureInitialized()

    const now = Math.floor(Date.now() / 1000)

    const tokensStmt = this.db!.prepare(`
      DELETE FROM revoked_tokens WHERE exp < ?
    `)
    const tokensResult = tokensStmt.run(now)

    const sessionsStmt = this.db!.prepare(`
      DELETE FROM revoked_sessions 
      WHERE jti NOT IN (
        SELECT jti FROM revoked_tokens WHERE exp > ?
      ) AND jti IS NOT NULL
    `)
    sessionsStmt.run(now)

    const totalCleaned = tokensResult.changes

    if (this.config.debug && totalCleaned > 0) {
      console.log(`[WebToken] SQLiteStore cleaned ${totalCleaned} expired entries`)
    }

    return totalCleaned
  }

  async disconnect(): Promise<void> {
    this.stopAutoCleanup()

    if (this.db && !this.config.connection) {
      this.db.close()
      this.db = null
      this.initialized = false

      if (this.config.debug) {
        console.log('[WebToken] SQLiteStore disconnected')
      }
    }
  }

  getStats(): { tokens: number; users: number; sessions: number } {
    if (!this.db) {
      return { tokens: 0, users: 0, sessions: 0 }
    }

    const tokensStmt = this.db.prepare('SELECT COUNT(*) as count FROM revoked_tokens')
    const usersStmt = this.db.prepare('SELECT COUNT(*) as count FROM revoked_users')
    const sessionsStmt = this.db.prepare('SELECT COUNT(*) as count FROM revoked_sessions')

    return {
      tokens: tokensStmt.get().count,
      users: usersStmt.get().count,
      sessions: sessionsStmt.get().count,
    }
  }

  getDatabase(): DatabaseInstance | null {
    return this.db
  }
}

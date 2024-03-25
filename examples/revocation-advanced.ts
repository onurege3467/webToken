/**
 * Advanced Revocation Examples
 * 
 * This file demonstrates advanced identifier extraction patterns for token revocation.
 * These examples cover real-world scenarios including nested paths, composite keys,
 * custom extractors, and fallback chains.
 */

import {
  createToken,
  verifyToken,
  RevocationManager,
  MemoryStore,
  IdentifierConfig,
  ExtractedIdentifiers,
} from '@onurege3467/webtoken'

async function examples() {
  console.log('=== Advanced Revocation Examples ===\n')

  // ============================================================================
  // Example 1: Nested Path Extraction
  // ============================================================================
  // Use case: Extract user ID from deeply nested organization structure
  // Path: payload.data.organization.members[0].userId
  // This is common in enterprise apps where users belong to organizations
  // ============================================================================
  console.log('1. Nested Path Extraction')
  console.log('   Extracting userId from: payload.data.organization.members[0].userId\n')

  const nestedPayload = {
    organization: {
      id: 'org-123',
      name: 'Acme Corp',
      members: [
        { userId: 'user-456', role: 'admin', permissions: ['all'] },
        { userId: 'user-789', role: 'member', permissions: ['read'] },
      ],
    },
  }

  const nestedConfig: IdentifierConfig = {
    // Extract the first member's userId from the organization
    userIdPath: 'data.organization.members[0].userId',
  }

  const { token: nestedToken } = await createToken({
    format: 'binary',
    algorithm: 'v1.local',
    payload: nestedPayload,
    expiresIn: '1h',
  })

  console.log('   Created token with nested payload')
  console.log('   Extracted userId would be: user-456 (first member)\n')

  // ============================================================================
  // Example 2: Composite Key (Tenant + User)
  // ============================================================================
  // Use case: Multi-tenant SaaS application where you need to revoke
  // all tokens for a specific user within a specific tenant
  // Key format: tenantId:userId (e.g., "acme-corp:user-123")
  // ============================================================================
  console.log('2. Composite Key (Tenant + User)')
  console.log('   Multi-tenant scenario: tenantId:userId\n')

  const tenantPayload = {
    tenantId: 'acme-corp',
    userId: 'user-123',
    subscription: 'enterprise',
  }

  const compositeConfig: IdentifierConfig = {
    compositeKey: {
      fields: ['data.tenantId', 'data.userId'],
      separator: ':',
    },
  }

  const { token: compositeToken } = await createToken({
    format: 'binary',
    algorithm: 'v1.local',
    payload: tenantPayload,
    expiresIn: '1h',
  })

  console.log('   Tenant ID: acme-corp')
  console.log('   User ID: user-123')
  console.log('   Composite key: acme-corp:user-123')
  console.log('   This allows revoking all tokens for user-123 in acme-corp tenant\n')

  // ============================================================================
  // Example 3: Global Config with Token-Level Override
  // ============================================================================
  // Use case: Set default extraction at the store level, but allow
  // individual tokens to override with their own configuration
  // ============================================================================
  console.log('3. Global Config with Token-Level Override')
  console.log('   Store-level default + token-level customization\n')

  // Global/store-level configuration
  const globalConfig: IdentifierConfig = {
    userIdPath: 'data.userId',
    sessionIdPath: 'data.sessionId',
  }

  // Create store with global config
  const store = new MemoryStore({
    identifierConfig: globalConfig,
  })

  const revocationManager = new RevocationManager({
    store,
    identifierConfig: globalConfig,
  })

  // Token 1: Uses global config (extracts data.userId)
  const token1Payload = {
    userId: 'global-user-1',
    sessionId: 'session-abc',
  }

  const { token: token1 } = await createToken({
    format: 'binary',
    algorithm: 'v1.local',
    payload: token1Payload,
    expiresIn: '1h',
  })

  console.log('   Token 1: Uses global config (data.userId)')
  console.log('   User ID extracted: global-user-1')

  // Token 2: Has its own config embedded in payload, overriding global
  const token2Payload = {
    accountId: 'override-user-2', // Different field name
    tenant: 'tenant-x',
  }

  const token2OverrideConfig: IdentifierConfig = {
    userIdPath: 'data.accountId', // Override: look at accountId instead
  }

  // Store the override config in the token payload (special field)
  const token2WithConfig = {
    ...token2Payload,
    identifierConfig: token2OverrideConfig,
  }

  const { token: token2 } = await createToken({
    format: 'binary',
    algorithm: 'v1.local',
    payload: token2WithConfig,
    expiresIn: '1h',
  })

  console.log('   Token 2: Has embedded config overriding global')
  console.log('   Global would look at: data.userId')
  console.log('   Override looks at: data.accountId')
  console.log('   User ID extracted: override-user-2\n')

  // ============================================================================
  // Example 4: Custom Extractor Function
  // ============================================================================
  // Use case: Complex business logic that can't be expressed with simple paths
  // Example: Priority-based extraction with validation rules
  // ============================================================================
  console.log('4. Custom Extractor Function')
  console.log('   Complex business logic for identifier extraction\n')

  const customPayload = {
    user: {
      primaryId: 'user-primary-123',
      legacyId: 'legacy-456',
      email: 'user@example.com',
    },
    session: {
      id: 'session-xyz',
      type: 'mobile', // 'mobile' | 'web' | 'api'
    },
    metadata: {
      trustScore: 85,
      mfaVerified: true,
    },
  }

  // Custom extractor with business logic:
  // 1. Use primary ID if MFA is verified and trust score > 80
  // 2. Otherwise fall back to legacy ID
  // 3. Include session type in composite key for mobile sessions
  const customExtractor = (payload: any): ExtractedIdentifiers => {
    const identifiers: ExtractedIdentifiers = {}

    // Business rule: Only extract if security criteria met
    if (payload.data?.metadata?.mfaVerified && payload.data?.metadata?.trustScore > 80) {
      identifiers.userId = payload.data.user.primaryId
      identifiers.metadata = {
        trustScore: payload.data.metadata.trustScore,
        mfaVerified: true,
      }
    } else {
      // Security criteria not met, use legacy identifier
      identifiers.userId = payload.data?.user?.legacyId
      identifiers.metadata = { securityLevel: 'low' }
    }

    // Business rule: For mobile sessions, create special composite key
    if (payload.data?.session?.type === 'mobile') {
      identifiers.compositeKey = `${identifiers.userId}:mobile:${payload.data.session.id}`
      identifiers.sessionId = payload.data.session.id
    } else {
      identifiers.sessionId = payload.data?.session?.id
    }

    return identifiers
  }

  const customConfig: IdentifierConfig = {
    extractIdentifiers: customExtractor,
  }

  const { token: customToken } = await createToken({
    format: 'binary',
    algorithm: 'v1.local',
    payload: customPayload,
    expiresIn: '1h',
  })

  console.log('   Custom extractor applies business logic:')
  console.log('   - Checks MFA verification and trust score')
  console.log('   - Uses primaryId if criteria met, else legacyId')
  console.log('   - Creates special composite key for mobile sessions')
  console.log('   In this case:')
  console.log('     MFA: verified, Trust: 85 → uses primaryId')
  console.log('     Session type: mobile → creates composite key')
  console.log('     Result: user-primary-123:mobile:session-xyz\n')

  // ============================================================================
  // Example 5: Fallback Chain Demonstration
  // ============================================================================
  // Use case: Support multiple field names across different token versions
  // or legacy systems that use different naming conventions
  // ============================================================================
  console.log('5. Fallback Chain Demonstration')
  console.log('   Multiple field names for backward compatibility\n')

  // Define fallback chain: try multiple paths in order
  const fallbackChain = [
    'data.userId', // Modern apps
    'data.sub', // OAuth/JWT style
    'data.uid', // Short form
    'data.user_id', // Snake case legacy
    'data.accountId', // Different naming
    'data.memberId', // Organization apps
    'data.id', // Generic fallback
    'sub', // Top-level JWT claim
  ]

  // Token with 'sub' field (OAuth style)
  const tokenOAuth = {
    sub: 'oauth-user-123',
    email: 'user@example.com',
  }

  // Token with 'user_id' field (legacy snake_case)
  const tokenLegacy = {
    user_id: 'legacy-user-456',
    email: 'legacy@example.com',
  }

  // Token with 'accountId' field (different naming)
  const tokenAccount = {
    accountId: 'account-user-789',
    email: 'account@example.com',
  }

  const fallbackConfig: IdentifierConfig = {
    fallbackChain,
  }

  console.log('   Fallback chain tries paths in order:')
  console.log('     1. data.userId')
  console.log('     2. data.sub')
  console.log('     3. data.uid')
  console.log('     4. data.user_id')
  console.log('     5. data.accountId')
  console.log('     6. data.memberId')
  console.log('     7. data.id')
  console.log('     8. sub\n')

  console.log('   Token OAuth style:')
  console.log('     Has: sub = oauth-user-123')
  console.log('     Tries data.userId → undefined')
  console.log('     Tries data.sub → undefined')
  console.log('     ...continues...')
  console.log('     Tries sub → oauth-user-123 ✓\n')

  console.log('   Token Legacy style:')
  console.log('     Has: user_id = legacy-user-456')
  console.log('     Tries data.userId → undefined')
  console.log('     Tries data.sub → undefined')
  console.log('     Tries data.uid → undefined')
  console.log('     Tries data.user_id → legacy-user-456 ✓\n')

  console.log('   Token Account style:')
  console.log('     Has: accountId = account-user-789')
  console.log('     Tries data.userId → undefined')
  console.log('     ...continues to data.accountId...')
  console.log('     Tries data.accountId → account-user-789 ✓\n')

  // ============================================================================
  // Example 6: Array Index Extraction
  // ============================================================================
  // Use case: Extract from specific position in arrays
  // Example: Get the current active session ID from sessions array
  // ============================================================================
  console.log('6. Array Index Extraction')
  console.log('   Extracting from arrays by index\n')

  const arrayPayload = {
    userId: 'user-999',
    sessions: [
      { id: 'session-001', device: 'iPhone', active: true },
      { id: 'session-002', device: 'Chrome', active: true },
      { id: 'session-003', device: 'Firefox', active: false },
    ],
    permissions: ['read', 'write', 'admin'],
  }

  // Config to extract the first session's ID
  const arrayConfig1: IdentifierConfig = {
    userIdPath: 'data.userId',
    sessionIdPath: 'data.sessions[0].id',
  }

  // Config to extract the second session's ID
  const arrayConfig2: IdentifierConfig = {
    userIdPath: 'data.userId',
    sessionIdPath: 'data.sessions[1].id',
  }

  const { token: arrayToken } = await createToken({
    format: 'binary',
    algorithm: 'v1.local',
    payload: arrayPayload,
    expiresIn: '1h',
  })

  console.log('   Sessions array:')
  console.log('     [0]: session-001 (iPhone)')
  console.log('     [1]: session-002 (Chrome)')
  console.log('     [2]: session-003 (Firefox)\n')

  console.log('   Config 1: sessionIdPath = "data.sessions[0].id"')
  console.log('   → Extracts: session-001\n')

  console.log('   Config 2: sessionIdPath = "data.sessions[1].id"')
  console.log('   → Extracts: session-002\n')

  // Demonstrate using array index in composite key
  const arrayCompositeConfig: IdentifierConfig = {
    compositeKey: {
      fields: ['data.userId', 'data.sessions[0].id'],
      separator: '@',
    },
  }

  console.log('   Composite key with array index:')
  console.log('   Fields: data.userId, data.sessions[0].id')
  console.log('   Separator: @')
  console.log('   → Composite key: user-999@session-001\n')

  // Cleanup
  await revocationManager.disconnect()

  console.log('=== Examples Complete ===')
  console.log('\nKey Takeaways:')
  console.log('  • Use nested paths for complex data structures')
  console.log('  • Composite keys enable multi-tenant revocation')
  console.log('  • Token-level configs can override store defaults')
  console.log('  • Custom extractors handle complex business logic')
  console.log('  • Fallback chains ensure backward compatibility')
  console.log('  • Array indices allow precise field extraction')
}

examples().catch(console.error)

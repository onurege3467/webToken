/**
 * Example usage of @onurege3467/webtoken
 */

import { createToken, verifyToken, decodeToken, AES256GCM, Ed25519 } from '@onurege3467/webtoken'

async function examples() {
  console.log('=== WebToken Examples ===\n')

  // Example 1: Create a simple encrypted token (v1.local)
  console.log('1. Creating encrypted token (v1.local)...')
  const { token: encryptedToken, expiresAt } = await createToken({
    format: 'binary',
    algorithm: 'v1.local',
    payload: {
      userId: 'user-123',
      role: 'admin',
      permissions: ['read', 'write', 'delete']
    },
    expiresIn: '1h',
    issuer: 'my-app',
    audience: 'api-service',
  })
  
  console.log('Token:', encryptedToken.substring(0, 50) + '...')
  console.log('Expires at:', expiresAt)
  console.log()

  // Example 2: Verify the encrypted token
  console.log('2. Verifying encrypted token...')
  // Note: For v1.local, you need to know the secret used to encrypt
  // In this case, we can't verify without the key that was generated
  console.log('Note: v1.local tokens require the secret key for verification')
  console.log()

  // Example 3: Create a signed token (v1.public)
  console.log('3. Creating signed token (v1.public)...')
  const { token: signedToken } = await createToken({
    format: 'binary',
    algorithm: 'v1.public',
    payload: {
      userId: 'user-456',
      sessionId: 'session-abc'
    },
    expiresIn: '24h',
    issuer: 'auth-service',
  })
  
  console.log('Signed Token:', signedToken.substring(0, 50) + '...')
  console.log()

  // Example 4: Using AES-256-GCM directly
  console.log('4. Using AES-256-GCM directly...')
  const key = await AES256GCM.generateKey()
  const plaintext = Buffer.from('Hello, Secret World!')
  
  const encrypted = await AES256GCM.encrypt(plaintext, key)
  const decrypted = await AES256GCM.decrypt(encrypted, key)
  
  console.log('Original:', plaintext.toString())
  console.log('Decrypted:', decrypted.toString())
  console.log('Match:', plaintext.toString() === decrypted.toString())
  console.log()

  // Example 5: Using Ed25519 directly
  console.log('5. Using Ed25519 directly...')
  const keyPair = await Ed25519.generateKeyPair()
  const message = Buffer.from('Message to sign')
  
  const signature = await Ed25519.sign(message, keyPair.privateKey)
  const isValid = await Ed25519.verify(message, signature, keyPair.publicKey)
  
  console.log('Message:', message.toString())
  console.log('Signature:', signature.toString('hex').substring(0, 40) + '...')
  console.log('Valid:', isValid)
  console.log()

  // Example 6: Create token with protobuf format
  console.log('6. Creating token with protobuf format...')
  const { token: protoToken } = await createToken({
    format: 'protobuf',
    algorithm: 'v1.local',
    payload: {
      userId: 'user-789',
      data: { nested: { value: 123 } }
    },
    expiresIn: '30m',
  })
  
  console.log('Protobuf Token:', protoToken.substring(0, 50) + '...')
  console.log()

  // Example 7: Different time formats
  console.log('7. Different time formats...')
  const timeFormats = ['1s', '1m', '1h', '1d', '7d']
  
  for (const expiresIn of timeFormats) {
    const { token } = await createToken({
      format: 'binary',
      algorithm: 'v1.local',
      payload: { test: expiresIn },
      expiresIn,
    })
    console.log(`  ${expiresIn}: ${token.substring(0, 30)}...`)
  }

  console.log('\n=== Examples Complete ===')
}

examples().catch(console.error)

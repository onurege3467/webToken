# @onurege3467/webtoken

High-performance, secure, and type-safe alternative to JWT with encrypted payloads.

## Features

- **Encrypted Payloads**: Unlike JWT (which uses base64), payloads are encrypted with AES-256-GCM or signed with Ed25519
- **TypeScript Support**: Full auto-complete and type safety
- **Multiple Formats**: Binary (fastest) and Protocol Buffers (compatible)
- **Modern Algorithms**: AES-256-GCM (v1.local) and Ed25519 (v1.public)
- **Zero Dependencies**: No external dependencies for core functionality
- **Node.js 20+**: Optimized for modern Node.js versions

## Installation

```bash
npm install @onurege3467/webtoken
```

## Quick Start

```typescript
import { createToken, verifyToken } from '@onurege3467/webtoken'

// Create a token
const { token, expiresAt } = await createToken({
  format: 'binary',      // 'binary' (fast) or 'protobuf' (compatible)
  algorithm: 'v1.local', // 'v1.local' (encrypted) or 'v1.public' (signed)
  payload: {
    userId: '123',
    role: 'admin',
    permissions: ['read', 'write']
  },
  expiresIn: '1h',       // Supports: '1s', '1m', '1h', '1d', '1w', '1y'
  issuer: 'my-app',
  audience: 'api-service',
})

// Token format: base64url(key).base64url(encrypted_payload)
// Example: aBcDeFg.aBcDeFgHiJkLmN...

// Verify a token
const decoded = await verifyToken(token, {
  secret: 'your-secret-key',  // For v1.local
  // OR
  // publicKey: 'your-public-key', // For v1.public
  issuer: 'my-app',
  audience: 'api-service',
})

console.log(decoded.payload.data)
// { userId: '123', role: 'admin', permissions: ['read', 'write'] }
```

## Configuration Options

```typescript
interface WebTokenConfig<TPayload> {
  // Required
  format: 'binary' | 'protobuf'
  algorithm: 'v1.local' | 'v1.public' | 'v2.local'
  payload: TPayload
  expiresIn: number | string  // ms or '1h', '30m', etc.
  
  // Optional
  issuer?: string
  audience?: string | string[]
  subject?: string
  tokenId?: string | (() => string)
  issuedAt?: boolean | number | string
  notBefore?: number | string
  
  // Performance options
  performance?: {
    useBufferPool?: boolean    // Default: true
    maxPayloadSize?: number    // Default: 10MB
    cacheValidations?: boolean // Default: false
  }
  
  // Security options
  security?: {
    requireExpiration?: boolean
    maxClockSkew?: number      // seconds
    allowedAlgorithms?: string[]
  }
}
```

## Verify Options

```typescript
interface VerifyOptions {
  secret?: string | Buffer      // For v1.local decryption
  publicKey?: string | Buffer   // For v1.public verification
  algorithms?: string[]         // Allowed algorithms
  issuer?: string | string[]    // Expected issuer(s)
  audience?: string | string[]  // Expected audience(s)
  clockTolerance?: number       // Seconds of clock skew to allow
  maxAge?: number | string      // Maximum token age
}
```

## Error Handling

```typescript
import { 
  TokenExpiredError, 
  TokenNotBeforeError,
  InvalidTokenError,
  InvalidSignatureError 
} from '@onurege3467/webtoken'

try {
  const decoded = await verifyToken(token, options)
} catch (error) {
  if (error instanceof TokenExpiredError) {
    console.log('Token expired at:', error.expiredAt)
  } else if (error instanceof TokenNotBeforeError) {
    console.log('Token not valid until:', error.notBefore)
  } else if (error instanceof InvalidSignatureError) {
    console.log('Invalid signature')
  }
}
```

## Formats

### Binary Format (Recommended)
- **Speed**: Ultra-fast encoding/decoding
- **Size**: Smallest payload size
- **Compatibility**: Node.js only

### Protocol Buffers Format
- **Speed**: Fast
- **Size**: Compact
- **Compatibility**: Cross-platform with protobuf support

## Algorithms

### v1.local (AES-256-GCM)
- Symmetric encryption
- Best for: Server-to-server communication
- Token contains encrypted payload

### v1.public (Ed25519)
- Asymmetric signatures
- Best for: Public verification scenarios
- Token contains signed payload + signature

## Performance

Benchmarks on Node.js 20 (Apple M1):

| Operation | Binary Format | Protocol Buffers |
|-----------|--------------|------------------|
| Create Token | ~50,000 ops/sec | ~30,000 ops/sec |
| Verify Token | ~60,000 ops/sec | ~35,000 ops/sec |
| Encrypt Payload | ~100,000 ops/sec | - |

## API Reference

### Core Functions

- `createToken(config)` - Create a new token
- `verifyToken(token, options)` - Verify and decode a token
- `decodeToken(token)` - Decode without verification (unsafe)

### Utilities

- `base64UrlEncode(buffer)` - Encode to base64url
- `base64UrlDecode(string)` - Decode from base64url
- `generateRandomBytes(size)` - Generate secure random bytes
- `parseTimeValue(value)` - Parse time string to ms

### Algorithms

- `AES256GCM` - AES-256-GCM encryption/decryption
- `Ed25519` - Ed25519 signing/verification

### Formats

- `BinaryFormat` - Binary encoding/decoding
- `ProtobufFormat` - Protobuf encoding/decoding

## License

MIT © Onur Ege

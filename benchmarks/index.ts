import Benchmark from 'benchmark'
import { createToken, BinaryFormat, AES256GCM } from '../src/index.js'

const suite = new Benchmark.Suite()

console.log('Running WebToken Benchmarks...\n')

// Test payload
const testPayload = {
  userId: 'user-123456',
  role: 'admin',
  permissions: ['read', 'write', 'delete'],
  metadata: {
    department: 'engineering',
    level: 5,
  },
}

// Create a token once for verification benchmarks
let testToken: string

async function setup() {
  const result = await createToken({
    format: 'binary',
    algorithm: 'v1.local',
    payload: testPayload,
    expiresIn: '1h',
    issuer: 'benchmark',
  })
  testToken = result.token
  
  // Add benchmarks
  suite
    .add('Create Token (binary, v1.local)', {
      defer: true,
      fn: async (deferred: any) => {
        await createToken({
          format: 'binary',
          algorithm: 'v1.local',
          payload: testPayload,
          expiresIn: '1h',
        })
        deferred.resolve()
      },
    })
    .add('Encode Payload (binary)', () => {
      BinaryFormat.encodePayload({
        data: testPayload,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      })
    })
    .add('AES-256-GCM Encrypt', {
      defer: true,
      fn: async (deferred: any) => {
        const key = await AES256GCM.generateKey()
        const data = Buffer.from(JSON.stringify(testPayload))
        await AES256GCM.encrypt(data, key)
        deferred.resolve()
      },
    })
    .on('cycle', (event: any) => {
      console.log(String(event.target))
    })
    .on('complete', function (this: any) {
      console.log('\nFastest is ' + this.filter('fastest').map('name'))
    })
    .run({ async: true })
}

setup().catch(console.error)

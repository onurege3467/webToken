/**
 * Type declarations for Web Crypto API types
 * These are needed for Node.js 20+ native crypto.subtle
 */

// Web Crypto API types
declare global {
  interface Crypto {
    subtle: SubtleCrypto
    getRandomValues<T extends ArrayBufferView | null>(array: T): T
  }

  interface SubtleCrypto {
    generateKey(
      algorithm: RsaHashedKeyGenParams | EcKeyGenParams | Ed25519KeyGenParams,
      extractable: boolean,
      keyUsages: KeyUsage[]
    ): Promise<CryptoKeyPair>
    generateKey(
      algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params,
      extractable: boolean,
      keyUsages: KeyUsage[]
    ): Promise<CryptoKey>
    importKey(
      format: 'raw' | 'pkcs8' | 'spki' | 'jwk',
      keyData: BufferSource | JsonWebKey,
      algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm | Ed25519KeyGenParams,
      extractable: boolean,
      keyUsages: KeyUsage[]
    ): Promise<CryptoKey>
    exportKey(format: 'raw' | 'pkcs8' | 'spki' | 'jwk', key: CryptoKey): Promise<ArrayBuffer>
    sign(
      algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams | Ed25519Params,
      key: CryptoKey,
      data: BufferSource
    ): Promise<ArrayBuffer>
    verify(
      algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams | Ed25519Params,
      key: CryptoKey,
      signature: BufferSource,
      data: BufferSource
    ): Promise<boolean>
    encrypt(
      algorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams,
      key: CryptoKey,
      data: BufferSource
    ): Promise<ArrayBuffer>
    decrypt(
      algorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams,
      key: CryptoKey,
      data: BufferSource
    ): Promise<ArrayBuffer>
    deriveBits(
      algorithm: AlgorithmIdentifier | EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params,
      baseKey: CryptoKey,
      length: number
    ): Promise<ArrayBuffer>
    deriveKey(
      algorithm: AlgorithmIdentifier | EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params,
      baseKey: CryptoKey,
      derivedKeyAlgorithm: AlgorithmIdentifier | AesDerivedKeyParams | HmacImportParams | HkdfParams | Pbkdf2Params,
      extractable: boolean,
      keyUsages: KeyUsage[]
    ): Promise<CryptoKey>
    wrapKey(
      format: 'raw' | 'pkcs8' | 'spki' | 'jwk',
      key: CryptoKey,
      wrappingKey: CryptoKey,
      wrapAlgorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams
    ): Promise<ArrayBuffer>
    unwrapKey(
      format: 'raw' | 'pkcs8' | 'spki' | 'jwk',
      wrappedKey: BufferSource,
      unwrappingKey: CryptoKey,
      unwrapAlgorithm: AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams,
      unwrappedKeyAlgorithm: AlgorithmIdentifier | AesDerivedKeyParams | HmacImportParams | HkdfParams | Pbkdf2Params,
      extractable: boolean,
      keyUsages: KeyUsage[]
    ): Promise<CryptoKey>
    digest(algorithm: AlgorithmIdentifier, data: BufferSource): Promise<ArrayBuffer>
  }

  interface CryptoKey {
    readonly algorithm: KeyAlgorithm
    readonly extractable: boolean
    readonly type: 'secret' | 'private' | 'public'
    readonly usages: KeyUsage[]
  }

  interface CryptoKeyPair {
    privateKey: CryptoKey
    publicKey: CryptoKey
  }

  interface Ed25519KeyGenParams {
    name: 'Ed25519'
  }

  interface Ed25519Params {
    name: 'Ed25519'
  }

  type KeyUsage = 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'deriveKey' | 'deriveBits' | 'wrapKey' | 'unwrapKey'

  interface Algorithm {
    name: string
  }

  interface KeyAlgorithm {
    name: string
  }

  interface AesKeyGenParams {
    name: 'AES-GCM' | 'AES-CTR' | 'AES-CBC' | 'AES-KW'
    length: number
  }

  interface AesGcmParams {
    name: 'AES-GCM'
    iv: BufferSource
    additionalData?: BufferSource
    tagLength?: number
  }

  interface HmacKeyGenParams {
    name: 'HMAC'
    hash: AlgorithmIdentifier
    length?: number
  }

  interface HmacImportParams {
    name: 'HMAC'
    hash: AlgorithmIdentifier
    length?: number
  }

  interface Pbkdf2Params {
    name: 'PBKDF2'
    salt: BufferSource
    iterations: number
    hash: AlgorithmIdentifier
  }

  interface AesDerivedKeyParams {
    name: 'AES-GCM' | 'AES-CTR' | 'AES-CBC' | 'AES-KW'
    length: number
  }

  interface RsaHashedKeyGenParams {
    name: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'RSA-OAEP'
    modulusLength: number
    publicExponent: Uint8Array
    hash: AlgorithmIdentifier
  }

  interface RsaHashedImportParams {
    name: 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'RSA-OAEP'
    hash: AlgorithmIdentifier
  }

  interface RsaPssParams {
    name: 'RSA-PSS'
    saltLength: number
  }

  interface RsaOaepParams {
    name: 'RSA-OAEP'
    label?: BufferSource
  }

  interface EcKeyGenParams {
    name: 'ECDSA' | 'ECDH'
    namedCurve: 'P-256' | 'P-384' | 'P-521'
  }

  interface EcKeyImportParams {
    name: 'ECDSA' | 'ECDH'
    namedCurve: 'P-256' | 'P-384' | 'P-521'
  }

  interface EcdsaParams {
    name: 'ECDSA'
    hash: AlgorithmIdentifier
  }

  interface EcdhKeyDeriveParams {
    name: 'ECDH'
    public: CryptoKey
  }

  interface HkdfParams {
    name: 'HKDF'
    hash: AlgorithmIdentifier
    salt: BufferSource
    info: BufferSource
  }

  interface AesCtrParams {
    name: 'AES-CTR'
    counter: BufferSource
    length: number
  }

  interface AesCbcParams {
    name: 'AES-CBC'
    iv: BufferSource
  }

  interface JsonWebKey {
    kty?: string
    use?: string
    key_ops?: string[]
    alg?: string
    ext?: boolean
    crv?: string
    x?: string
    y?: string
    d?: string
    n?: string
    e?: string
    p?: string
    q?: string
    dp?: string
    dq?: string
    qi?: string
    k?: string
  }

  type AlgorithmIdentifier = string | Algorithm
  type BufferSource = ArrayBufferView | ArrayBuffer
}

export {}

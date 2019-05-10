/**
 * Utility functions for buffer operations, encoding, and timing-safe comparisons
 */

import { randomBytes, createHash, timingSafeEqual } from 'crypto'

/**
 * Generate cryptographically secure random bytes
 */
export function generateRandomBytes(size: number): Buffer {
  return randomBytes(size)
}

/**
 * Encode buffer to Base64URL (JWT standard)
 */
export function base64UrlEncode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

/**
 * Decode Base64URL string to buffer
 */
export function base64UrlDecode(str: string): Buffer {
  // Add padding if needed
  const padding = 4 - (str.length % 4)
  if (padding !== 4) {
    str += '='.repeat(padding)
  }
  
  const base64 = str
    .replace(/-/g, '+')
    .replace(/_/g, '/')
  
  return Buffer.from(base64, 'base64')
}

/**
 * Encode buffer to standard Base64
 */
export function base64Encode(buffer: Buffer): string {
  return buffer.toString('base64')
}

/**
 * Decode Base64 string to buffer
 */
export function base64Decode(str: string): Buffer {
  return Buffer.from(str, 'base64')
}

/**
 * Timing-safe comparison of two buffers
 * Prevents timing attacks
 */
export function secureCompare(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false
  }
  return timingSafeEqual(a, b)
}

/**
 * Convert time string to milliseconds
 * Supports: '1s', '1m', '1h', '1d', '1w', '1y'
 */
export function parseTimeValue(value: TimeValue): number {
  if (typeof value === 'number') {
    return value
  }
  
  const match = value.match(/^(\d+)\s*([smhdwy])$/i)
  if (!match) {
    throw new Error(`Invalid time format: ${value}. Use format like '1h', '30m', '7d'`)
  }
  
  const [, num, unit] = match
  const multiplier: Record<string, number> = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
    w: 7 * 24 * 60 * 60 * 1000,
    y: 365 * 24 * 60 * 60 * 1000,
  }
  
  return parseInt(num, 10) * multiplier[unit.toLowerCase()]
}

/**
 * Get current timestamp in seconds (Unix epoch)
 */
export function getCurrentTimestamp(): number {
  return Math.floor(Date.now() / 1000)
}

/**
 * Create SHA-256 hash of data
 */
export function sha256(data: Buffer | string): Buffer {
  return createHash('sha256').update(data).digest()
}

/**
 * Concatenate multiple buffers efficiently
 */
export function concatBuffers(buffers: Buffer[]): Buffer {
  const totalLength = buffers.reduce((acc, buf) => acc + buf.length, 0)
  const result = Buffer.allocUnsafe(totalLength)
  let offset = 0
  
  for (const buf of buffers) {
    buf.copy(result, offset)
    offset += buf.length
  }
  
  return result
}

/**
 * Check if buffer is valid UTF-8
 */
export function isValidUtf8(buffer: Buffer): boolean {
  try {
    buffer.toString('utf8')
    return true
  } catch {
    return false
  }
}

/**
 * Convert string to buffer safely
 */
export function stringToBuffer(str: string, encoding: BufferEncoding = 'utf8'): Buffer {
  return Buffer.from(str, encoding)
}

/**
 * Convert buffer to string safely
 */
export function bufferToString(buffer: Buffer, encoding: BufferEncoding = 'utf8'): string {
  return buffer.toString(encoding)
}

// Re-export TimeValue type from types
export type TimeValue = number | string

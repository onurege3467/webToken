/**
 * Ultra-fast binary format encoder/decoder
 * Custom binary format optimized for speed and compactness
 */

import type { TokenHeader, TokenPayload } from '../types/index.js'

// Binary format constants
const HEADER_VERSION_OFFSET = 0
const HEADER_PURPOSE_OFFSET = 1
const HEADER_FORMAT_OFFSET = 2
const HEADER_SIZE = 3

// Type markers for payload fields
const MARKER_ISS = 0x01
const MARKER_SUB = 0x02
const MARKER_AUD = 0x03
const MARKER_EXP = 0x04
const MARKER_NBF = 0x05
const MARKER_IAT = 0x06
const MARKER_JTI = 0x07
const MARKER_DATA = 0x08
const MARKER_END = 0x00

export class BinaryFormat {
  /**
   * Encode header to binary format
   */
  static encodeHeader(header: TokenHeader): Buffer {
    const buffer = Buffer.allocUnsafe(HEADER_SIZE)
    
    // Version: 1 byte
    buffer[HEADER_VERSION_OFFSET] = header.version === 'v1' ? 0x01 : 0x02
    
    // Purpose: 1 byte
    buffer[HEADER_PURPOSE_OFFSET] = header.purpose === 'local' ? 0x01 : 0x02
    
    // Format: 1 byte
    buffer[HEADER_FORMAT_OFFSET] = header.format === 'binary' ? 0x01 : 0x02
    
    return buffer
  }

  /**
   * Decode header from binary format
   */
  static decodeHeader(buffer: Buffer): TokenHeader {
    if (buffer.length < HEADER_SIZE) {
      throw new Error('Invalid header: buffer too short')
    }
    
    const version = buffer[HEADER_VERSION_OFFSET] === 0x01 ? 'v1' : 'v2'
    const purpose = buffer[HEADER_PURPOSE_OFFSET] === 0x01 ? 'local' : 'public'
    const format = buffer[HEADER_FORMAT_OFFSET] === 0x01 ? 'binary' : 'protobuf'
    
    return { version, purpose, format } as TokenHeader
  }

  /**
   * Encode payload to binary format
   * Format: [marker] [length (2 bytes)] [data] ... [MARKER_END]
   */
  static encodePayload(payload: TokenPayload): Buffer {
    const chunks: Buffer[] = []
    
    if (payload.iss !== undefined) {
      const data = Buffer.from(payload.iss, 'utf8')
      const chunk = Buffer.allocUnsafe(3 + data.length)
      chunk[0] = MARKER_ISS
      chunk.writeUInt16BE(data.length, 1)
      data.copy(chunk, 3)
      chunks.push(chunk)
    }
    
    if (payload.sub !== undefined) {
      const data = Buffer.from(payload.sub, 'utf8')
      const chunk = Buffer.allocUnsafe(3 + data.length)
      chunk[0] = MARKER_SUB
      chunk.writeUInt16BE(data.length, 1)
      data.copy(chunk, 3)
      chunks.push(chunk)
    }
    
    if (payload.aud !== undefined) {
      const audStr = Array.isArray(payload.aud) ? payload.aud.join('\x00') : payload.aud
      const data = Buffer.from(audStr, 'utf8')
      const chunk = Buffer.allocUnsafe(3 + data.length)
      chunk[0] = MARKER_AUD
      chunk.writeUInt16BE(data.length, 1)
      data.copy(chunk, 3)
      chunks.push(chunk)
    }
    
    if (payload.exp !== undefined) {
      const chunk = Buffer.allocUnsafe(7)
      chunk[0] = MARKER_EXP
      chunk.writeUInt16BE(4, 1)
      chunk.writeUInt32BE(payload.exp, 3)
      chunks.push(chunk)
    }
    
    if (payload.nbf !== undefined) {
      const chunk = Buffer.allocUnsafe(7)
      chunk[0] = MARKER_NBF
      chunk.writeUInt16BE(4, 1)
      chunk.writeUInt32BE(payload.nbf, 3)
      chunks.push(chunk)
    }
    
    if (payload.iat !== undefined) {
      const chunk = Buffer.allocUnsafe(7)
      chunk[0] = MARKER_IAT
      chunk.writeUInt16BE(4, 1)
      chunk.writeUInt32BE(payload.iat, 3)
      chunks.push(chunk)
    }
    
    if (payload.jti !== undefined) {
      const data = Buffer.from(payload.jti, 'utf8')
      const chunk = Buffer.allocUnsafe(3 + data.length)
      chunk[0] = MARKER_JTI
      chunk.writeUInt16BE(data.length, 1)
      data.copy(chunk, 3)
      chunks.push(chunk)
    }
    
    if (payload.data !== undefined) {
      const data = Buffer.from(JSON.stringify(payload.data), 'utf8')
      const chunk = Buffer.allocUnsafe(3 + data.length)
      chunk[0] = MARKER_DATA
      chunk.writeUInt16BE(data.length, 1)
      data.copy(chunk, 3)
      chunks.push(chunk)
    }
    
    // Add end marker
    chunks.push(Buffer.from([MARKER_END]))
    
    return Buffer.concat(chunks)
  }

  /**
   * Decode payload from binary format
   */
  static decodePayload(buffer: Buffer): TokenPayload {
    const payload: TokenPayload = {}
    let offset = 0
    
    while (offset < buffer.length) {
      const marker = buffer[offset]
      
      if (marker === MARKER_END) {
        break
      }
      
      if (offset + 3 > buffer.length) {
        throw new Error('Invalid payload: truncated data')
      }
      
      const length = buffer.readUInt16BE(offset + 1)
      
      if (offset + 3 + length > buffer.length) {
        throw new Error('Invalid payload: data exceeds buffer')
      }
      
      const data = buffer.subarray(offset + 3, offset + 3 + length)
      
      switch (marker) {
        case MARKER_ISS:
          payload.iss = data.toString('utf8')
          break
        case MARKER_SUB:
          payload.sub = data.toString('utf8')
          break
        case MARKER_AUD:
          const audStr = data.toString('utf8')
          payload.aud = audStr.includes('\x00') ? audStr.split('\x00') : audStr
          break
        case MARKER_EXP:
          payload.exp = data.readUInt32BE(0)
          break
        case MARKER_NBF:
          payload.nbf = data.readUInt32BE(0)
          break
        case MARKER_IAT:
          payload.iat = data.readUInt32BE(0)
          break
        case MARKER_JTI:
          payload.jti = data.toString('utf8')
          break
        case MARKER_DATA:
          payload.data = JSON.parse(data.toString('utf8'))
          break
        default:
          // Unknown marker, skip
          break
      }
      
      offset += 3 + length
    }
    
    return payload
  }

  /**
   * Encode complete token (header + payload)
   */
  static encode(header: TokenHeader, payload: TokenPayload): Buffer {
    const headerBuffer = this.encodeHeader(header)
    const payloadBuffer = this.encodePayload(payload)
    
    // Format: [header size (2 bytes)] [header] [payload]
    const result = Buffer.allocUnsafe(2 + headerBuffer.length + payloadBuffer.length)
    result.writeUInt16BE(headerBuffer.length, 0)
    headerBuffer.copy(result, 2)
    payloadBuffer.copy(result, 2 + headerBuffer.length)
    
    return result
  }

  /**
   * Decode complete token
   */
  static decode(buffer: Buffer): { header: TokenHeader; payload: TokenPayload } {
    if (buffer.length < 2) {
      throw new Error('Invalid token: buffer too short')
    }
    
    const headerSize = buffer.readUInt16BE(0)
    
    if (buffer.length < 2 + headerSize) {
      throw new Error('Invalid token: header exceeds buffer')
    }
    
    const header = this.decodeHeader(buffer.subarray(2, 2 + headerSize))
    const payload = this.decodePayload(buffer.subarray(2 + headerSize))
    
    return { header, payload }
  }

  /**
   * Get size estimate for payload
   */
  static getEncodedSize(payload: TokenPayload): number {
    let size = HEADER_SIZE + 2 // header + size prefix
    
    if (payload.iss) size += 3 + Buffer.byteLength(payload.iss, 'utf8')
    if (payload.sub) size += 3 + Buffer.byteLength(payload.sub, 'utf8')
    if (payload.aud) {
      const audStr = Array.isArray(payload.aud) ? payload.aud.join('\x00') : payload.aud
      size += 3 + Buffer.byteLength(audStr, 'utf8')
    }
    if (payload.exp) size += 7
    if (payload.nbf) size += 7
    if (payload.iat) size += 7
    if (payload.jti) size += 3 + Buffer.byteLength(payload.jti, 'utf8')
    if (payload.data) size += 3 + Buffer.byteLength(JSON.stringify(payload.data), 'utf8')
    
    size += 1 // MARKER_END
    
    return size
  }
}

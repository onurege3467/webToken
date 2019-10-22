/**
 * Protocol Buffers format encoder/decoder
 * Optional format for maximum compatibility
 */

import type { TokenHeader, TokenPayload } from '../types/index.js'

// Simple protobuf-like encoding (simplified implementation)
// In production, use actual protobufjs library

const WIRE_TYPE_VARINT = 0
const WIRE_TYPE_LENGTH_DELIMITED = 2

// Field numbers
const FIELD_VERSION = 1
const FIELD_PURPOSE = 2
const FIELD_FORMAT = 3
const FIELD_ISS = 1
const FIELD_SUB = 2
const FIELD_AUD = 3
const FIELD_EXP = 4
const FIELD_NBF = 5
const FIELD_IAT = 6
const FIELD_JTI = 7
const FIELD_DATA = 8

export class ProtobufFormat {
  /**
   * Encode varint (variable-length integer)
   */
  private static encodeVarint(value: number): Buffer {
    const bytes: number[] = []
    
    while (value > 127) {
      bytes.push((value & 0x7f) | 0x80)
      value >>>= 7
    }
    
    bytes.push(value)
    return Buffer.from(bytes)
  }

  /**
   * Decode varint
   */
  private static decodeVarint(buffer: Buffer, offset: number): { value: number; bytesRead: number } {
    let value = 0
    let shift = 0
    let bytesRead = 0
    
    while (true) {
      if (offset + bytesRead >= buffer.length) {
        throw new Error('Invalid varint: buffer exhausted')
      }
      
      const byte = buffer[offset + bytesRead]
      value |= (byte & 0x7f) << shift
      bytesRead++
      
      if ((byte & 0x80) === 0) {
        break
      }
      
      shift += 7
      if (shift >= 32) {
        throw new Error('Invalid varint: too large')
      }
    }
    
    return { value, bytesRead }
  }

  /**
   * Encode field key (field number + wire type)
   */
  private static encodeFieldKey(fieldNumber: number, wireType: number): Buffer {
    return this.encodeVarint((fieldNumber << 3) | wireType)
  }

  /**
   * Encode string field
   */
  private static encodeStringField(fieldNumber: number, value: string): Buffer {
    const data = Buffer.from(value, 'utf8')
    const key = this.encodeFieldKey(fieldNumber, WIRE_TYPE_LENGTH_DELIMITED)
    const length = this.encodeVarint(data.length)
    return Buffer.concat([key, length, data])
  }

  /**
   * Encode uint32 field
   */
  private static encodeUint32Field(fieldNumber: number, value: number): Buffer {
    const key = this.encodeFieldKey(fieldNumber, WIRE_TYPE_VARINT)
    const data = this.encodeVarint(value)
    return Buffer.concat([key, data])
  }

  /**
   * Encode header to protobuf format
   */
  static encodeHeader(header: TokenHeader): Buffer {
    const chunks: Buffer[] = []
    
    // Version: enum -> varint
    const versionValue = header.version === 'v1' ? 1 : 2
    chunks.push(this.encodeUint32Field(FIELD_VERSION, versionValue))
    
    // Purpose: enum -> varint
    const purposeValue = header.purpose === 'local' ? 1 : 2
    chunks.push(this.encodeUint32Field(FIELD_PURPOSE, purposeValue))
    
    // Format: enum -> varint
    const formatValue = header.format === 'binary' ? 1 : 2
    chunks.push(this.encodeUint32Field(FIELD_FORMAT, formatValue))
    
    return Buffer.concat(chunks)
  }

  /**
   * Decode header from protobuf format
   */
  static decodeHeader(buffer: Buffer): TokenHeader {
    const header: Partial<TokenHeader> = {}
    let offset = 0
    
    while (offset < buffer.length) {
      const { value: key, bytesRead: keyBytes } = this.decodeVarint(buffer, offset)
      offset += keyBytes
      
      const fieldNumber = key >> 3
      const wireType = key & 0x07
      
      switch (fieldNumber) {
        case FIELD_VERSION:
          if (wireType === WIRE_TYPE_VARINT) {
            const { value, bytesRead } = this.decodeVarint(buffer, offset)
            header.version = value === 1 ? 'v1' : 'v2'
            offset += bytesRead
          }
          break
        case FIELD_PURPOSE:
          if (wireType === WIRE_TYPE_VARINT) {
            const { value, bytesRead } = this.decodeVarint(buffer, offset)
            header.purpose = value === 1 ? 'local' : 'public'
            offset += bytesRead
          }
          break
        case FIELD_FORMAT:
          if (wireType === WIRE_TYPE_VARINT) {
            const { value, bytesRead } = this.decodeVarint(buffer, offset)
            header.format = value === 1 ? 'binary' : 'protobuf'
            offset += bytesRead
          }
          break
        default:
          // Skip unknown field
          if (wireType === WIRE_TYPE_VARINT) {
            const { bytesRead } = this.decodeVarint(buffer, offset)
            offset += bytesRead
          } else if (wireType === WIRE_TYPE_LENGTH_DELIMITED) {
            const { value: length, bytesRead: lenBytes } = this.decodeVarint(buffer, offset)
            offset += lenBytes + length
          }
          break
      }
    }
    
    return header as TokenHeader
  }

  /**
   * Encode payload to protobuf format
   */
  static encodePayload(payload: TokenPayload): Buffer {
    const chunks: Buffer[] = []
    
    if (payload.iss !== undefined) {
      chunks.push(this.encodeStringField(FIELD_ISS, payload.iss))
    }
    
    if (payload.sub !== undefined) {
      chunks.push(this.encodeStringField(FIELD_SUB, payload.sub))
    }
    
    if (payload.aud !== undefined) {
      const audStr = Array.isArray(payload.aud) ? payload.aud.join('\x00') : payload.aud
      chunks.push(this.encodeStringField(FIELD_AUD, audStr))
    }
    
    if (payload.exp !== undefined) {
      chunks.push(this.encodeUint32Field(FIELD_EXP, payload.exp))
    }
    
    if (payload.nbf !== undefined) {
      chunks.push(this.encodeUint32Field(FIELD_NBF, payload.nbf))
    }
    
    if (payload.iat !== undefined) {
      chunks.push(this.encodeUint32Field(FIELD_IAT, payload.iat))
    }
    
    if (payload.jti !== undefined) {
      chunks.push(this.encodeStringField(FIELD_JTI, payload.jti))
    }
    
    if (payload.data !== undefined) {
      const dataStr = JSON.stringify(payload.data)
      chunks.push(this.encodeStringField(FIELD_DATA, dataStr))
    }
    
    return Buffer.concat(chunks)
  }

  /**
   * Decode payload from protobuf format
   */
  static decodePayload(buffer: Buffer): TokenPayload {
    const payload: TokenPayload = {}
    let offset = 0
    
    while (offset < buffer.length) {
      const { value: key, bytesRead: keyBytes } = this.decodeVarint(buffer, offset)
      offset += keyBytes
      
      const fieldNumber = key >> 3
      const wireType = key & 0x07
      
      switch (fieldNumber) {
        case FIELD_ISS:
          if (wireType === WIRE_TYPE_LENGTH_DELIMITED) {
            const { value: length, bytesRead: lenBytes } = this.decodeVarint(buffer, offset)
            offset += lenBytes
            payload.iss = buffer.subarray(offset, offset + length).toString('utf8')
            offset += length
          }
          break
        case FIELD_SUB:
          if (wireType === WIRE_TYPE_LENGTH_DELIMITED) {
            const { value: length, bytesRead: lenBytes } = this.decodeVarint(buffer, offset)
            offset += lenBytes
            payload.sub = buffer.subarray(offset, offset + length).toString('utf8')
            offset += length
          }
          break
        case FIELD_AUD:
          if (wireType === WIRE_TYPE_LENGTH_DELIMITED) {
            const { value: length, bytesRead: lenBytes } = this.decodeVarint(buffer, offset)
            offset += lenBytes
            const audStr = buffer.subarray(offset, offset + length).toString('utf8')
            payload.aud = audStr.includes('\x00') ? audStr.split('\x00') : audStr
            offset += length
          }
          break
        case FIELD_EXP:
          if (wireType === WIRE_TYPE_VARINT) {
            const { value, bytesRead } = this.decodeVarint(buffer, offset)
            payload.exp = value
            offset += bytesRead
          }
          break
        case FIELD_NBF:
          if (wireType === WIRE_TYPE_VARINT) {
            const { value, bytesRead } = this.decodeVarint(buffer, offset)
            payload.nbf = value
            offset += bytesRead
          }
          break
        case FIELD_IAT:
          if (wireType === WIRE_TYPE_VARINT) {
            const { value, bytesRead } = this.decodeVarint(buffer, offset)
            payload.iat = value
            offset += bytesRead
          }
          break
        case FIELD_JTI:
          if (wireType === WIRE_TYPE_LENGTH_DELIMITED) {
            const { value: length, bytesRead: lenBytes } = this.decodeVarint(buffer, offset)
            offset += lenBytes
            payload.jti = buffer.subarray(offset, offset + length).toString('utf8')
            offset += length
          }
          break
        case FIELD_DATA:
          if (wireType === WIRE_TYPE_LENGTH_DELIMITED) {
            const { value: length, bytesRead: lenBytes } = this.decodeVarint(buffer, offset)
            offset += lenBytes
            const dataStr = buffer.subarray(offset, offset + length).toString('utf8')
            payload.data = JSON.parse(dataStr)
            offset += length
          }
          break
        default:
          // Skip unknown field
          if (wireType === WIRE_TYPE_VARINT) {
            const { bytesRead } = this.decodeVarint(buffer, offset)
            offset += bytesRead
          } else if (wireType === WIRE_TYPE_LENGTH_DELIMITED) {
            const { value: length, bytesRead: lenBytes } = this.decodeVarint(buffer, offset)
            offset += lenBytes + length
          }
          break
      }
    }
    
    return payload
  }

  /**
   * Encode complete token (header + payload)
   */
  static encode(header: TokenHeader, payload: TokenPayload): Buffer {
    const headerBuffer = this.encodeHeader(header)
    const payloadBuffer = this.encodePayload(payload)
    
    // Format: [header length (varint)] [header] [payload length (varint)] [payload]
    const headerLen = this.encodeVarint(headerBuffer.length)
    const payloadLen = this.encodeVarint(payloadBuffer.length)
    
    return Buffer.concat([headerLen, headerBuffer, payloadLen, payloadBuffer])
  }

  /**
   * Decode complete token
   */
  static decode(buffer: Buffer): { header: TokenHeader; payload: TokenPayload } {
    let offset = 0
    
    // Decode header length
    const { value: headerLen, bytesRead: headerLenBytes } = this.decodeVarint(buffer, offset)
    offset += headerLenBytes
    
    if (offset + headerLen > buffer.length) {
      throw new Error('Invalid token: header exceeds buffer')
    }
    
    const header = this.decodeHeader(buffer.subarray(offset, offset + headerLen))
    offset += headerLen
    
    // Decode payload length
    const { value: payloadLen, bytesRead: payloadLenBytes } = this.decodeVarint(buffer, offset)
    offset += payloadLenBytes
    
    if (offset + payloadLen > buffer.length) {
      throw new Error('Invalid token: payload exceeds buffer')
    }
    
    const payload = this.decodePayload(buffer.subarray(offset, offset + payloadLen))
    
    return { header, payload }
  }

  /**
   * Get size estimate for payload
   */
  static getEncodedSize(payload: TokenPayload): number {
    let size = 10 // Approximate header size
    
    if (payload.iss) size += 2 + Buffer.byteLength(payload.iss, 'utf8')
    if (payload.sub) size += 2 + Buffer.byteLength(payload.sub, 'utf8')
    if (payload.aud) {
      const audStr = Array.isArray(payload.aud) ? payload.aud.join('\x00') : payload.aud
      size += 2 + Buffer.byteLength(audStr, 'utf8')
    }
    if (payload.exp) size += 5
    if (payload.nbf) size += 5
    if (payload.iat) size += 5
    if (payload.jti) size += 2 + Buffer.byteLength(payload.jti, 'utf8')
    if (payload.data) size += 2 + Buffer.byteLength(JSON.stringify(payload.data), 'utf8')
    
    return size
  }
}

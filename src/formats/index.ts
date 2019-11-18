/**
 * Encoder factory - selects appropriate encoder based on format
 */

import { BinaryFormat } from './BinaryFormat.js'
import { ProtobufFormat } from './ProtobufFormat.js'
import type { TokenHeader, TokenPayload, TokenFormat } from '../types/index.js'

export { BinaryFormat, ProtobufFormat }

export class Encoder {
  /**
   * Encode token based on format
   */
  static encode(header: TokenHeader, payload: TokenPayload, format: TokenFormat): Buffer {
    switch (format) {
      case 'binary':
        return BinaryFormat.encode(header, payload)
      case 'protobuf':
        return ProtobufFormat.encode(header, payload)
      default:
        throw new Error(`Unknown format: ${format}`)
    }
  }

  /**
   * Decode token based on format
   */
  static decode(data: Buffer, format: TokenFormat): { header: TokenHeader; payload: TokenPayload } {
    switch (format) {
      case 'binary':
        return BinaryFormat.decode(data)
      case 'protobuf':
        return ProtobufFormat.decode(data)
      default:
        throw new Error(`Unknown format: ${format}`)
    }
  }

  /**
   * Get encoded size estimate
   */
  static getEncodedSize(payload: TokenPayload, format: TokenFormat): number {
    switch (format) {
      case 'binary':
        return BinaryFormat.getEncodedSize(payload)
      case 'protobuf':
        return ProtobufFormat.getEncodedSize(payload)
      default:
        throw new Error(`Unknown format: ${format}`)
    }
  }

  /**
   * Auto-detect format from data
   */
  static detectFormat(data: Buffer): TokenFormat {
    // Try to parse as binary first
    try {
      BinaryFormat.decode(data)
      return 'binary'
    } catch {
      // Try protobuf
      try {
        ProtobufFormat.decode(data)
        return 'protobuf'
      } catch {
        throw new Error('Unable to detect token format')
      }
    }
  }
}

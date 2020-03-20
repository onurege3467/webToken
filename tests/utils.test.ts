import { describe, it, expect } from 'vitest'
import { base64UrlEncode, base64UrlDecode, parseTimeValue, secureCompare } from '../src/utils/index.js'

describe('Utils', () => {
  describe('Base64 URL', () => {
    it('should encode and decode correctly', () => {
      const original = Buffer.from('Hello World! +/=')
      const encoded = base64UrlEncode(original)
      const decoded = base64UrlDecode(encoded)
      
      expect(decoded.toString()).toBe(original.toString())
      expect(encoded).not.toContain('+')
      expect(encoded).not.toContain('/')
      expect(encoded).not.toContain('=')
    })

    it('should handle empty buffer', () => {
      const empty = Buffer.alloc(0)
      const encoded = base64UrlEncode(empty)
      const decoded = base64UrlDecode(encoded)
      
      expect(decoded.length).toBe(0)
    })
  })

  describe('Time Parsing', () => {
    it('should parse various time formats', () => {
      expect(parseTimeValue(1000)).toBe(1000)
      expect(parseTimeValue('1s')).toBe(1000)
      expect(parseTimeValue('1m')).toBe(60000)
      expect(parseTimeValue('1h')).toBe(3600000)
      expect(parseTimeValue('1d')).toBe(86400000)
      expect(parseTimeValue('1w')).toBe(604800000)
    })

    it('should handle spaces in time strings', () => {
      expect(parseTimeValue('1 s')).toBe(1000)
      expect(parseTimeValue('30 m')).toBe(1800000)
    })

    it('should throw on invalid format', () => {
      expect(() => parseTimeValue('invalid')).toThrow()
      expect(() => parseTimeValue('1x')).toThrow()
    })
  })

  describe('Secure Compare', () => {
    it('should compare equal buffers', () => {
      const a = Buffer.from('secret')
      const b = Buffer.from('secret')
      
      expect(secureCompare(a, b)).toBe(true)
    })

    it('should compare different buffers', () => {
      const a = Buffer.from('secret1')
      const b = Buffer.from('secret2')
      
      expect(secureCompare(a, b)).toBe(false)
    })

    it('should compare different length buffers', () => {
      const a = Buffer.from('secret')
      const b = Buffer.from('secret!')
      
      expect(secureCompare(a, b)).toBe(false)
    })
  })
})

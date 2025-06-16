import { base64UrlEncode, base64UrlDecode, parseExpiresIn } from './utils';
import { InvalidBase64UrlError, InvalidDurationError } from './errors';

describe('Base64Url Utilities', () => {
  describe('base64UrlEncode', () => {
    it('should encode string to base64url format', () => {
      const input = 'Hello, World!';
      const expected = 'SGVsbG8sIFdvcmxkIQ';
      expect(base64UrlEncode(input)).toBe(expected);
    });

    it('should encode Buffer to base64url format', () => {
      const input = Buffer.from('Hello, World!');
      const expected = 'SGVsbG8sIFdvcmxkIQ';
      expect(base64UrlEncode(input)).toBe(expected);
    });

    it('should handle empty string', () => {
      expect(base64UrlEncode('')).toBe('');
    });

    it('should handle special characters', () => {
      const input = 'Hello+World/123=';
      const expected = 'SGVsbG8rV29ybGQvMTIzPQ';
      expect(base64UrlEncode(input)).toBe(expected);
    });

    it('should handle Unicode characters', () => {
      const input = 'Hello, 世界!';
      const expected = 'SGVsbG8sIOS4lueVjCE';
      expect(base64UrlEncode(input)).toBe(expected);
    });
  });

  describe('base64UrlDecode', () => {
    it('should decode base64url string to Buffer', () => {
      const input = 'SGVsbG8sIFdvcmxkIQ';
      const expected = Buffer.from('Hello, World!');
      expect(base64UrlDecode(input)).toEqual(expected);
    });

    it('should handle padding', () => {
      const input = 'SGVsbG8';
      const expected = Buffer.from('Hello');
      expect(base64UrlDecode(input)).toEqual(expected);
    });

    it('should handle empty string', () => {
      expect(base64UrlDecode('')).toEqual(Buffer.from(''));
    });

    it('should handle special characters', () => {
      const input = 'SGVsbG8rV29ybGQvMTIzPQ';
      const expected = Buffer.from('Hello+World/123=');
      expect(base64UrlDecode(input)).toEqual(expected);
    });

    it('should handle Unicode characters', () => {
      const input = 'SGVsbG8sIOS4lueVjCE';
      const expected = Buffer.from('Hello, 世界!');
      expect(base64UrlDecode(input)).toEqual(expected);
    });

    it('should throw error for invalid base64url string', () => {
      expect(() => base64UrlDecode('invalid!@#')).toThrow(InvalidBase64UrlError);
    });
  });

  describe('roundtrip', () => {
    it('should encode and decode back to original string', () => {
      const original = 'Hello, World!';
      const encoded = base64UrlEncode(original);
      const decoded = base64UrlDecode(encoded).toString();
      expect(decoded).toBe(original);
    });

    it('should handle Unicode roundtrip', () => {
      const original = 'Hello, 世界!';
      const encoded = base64UrlEncode(original);
      const decoded = base64UrlDecode(encoded).toString();
      expect(decoded).toBe(original);
    });
  });
});

describe('Duration Parsing', () => {
  describe('parseExpiresIn', () => {
    it('should parse seconds', () => {
      expect(parseExpiresIn('30s')).toBe(30);
    });

    it('should parse minutes', () => {
      expect(parseExpiresIn('5m')).toBe(300);
    });

    it('should parse hours', () => {
      expect(parseExpiresIn('2h')).toBe(7200);
    });

    it('should handle numeric input', () => {
      expect(parseExpiresIn(60)).toBe(60);
    });

    it('should throw error for invalid format', () => {
      expect(() => parseExpiresIn('invalid')).toThrow(InvalidDurationError);
    });

    it('should throw error for invalid time unit', () => {
      expect(() => parseExpiresIn('1d')).toThrow(InvalidDurationError);
    });

    it('should throw error for non-string/non-number input', () => {
      expect(() => parseExpiresIn(null as any)).toThrow(InvalidDurationError);
    });
  });
}); 
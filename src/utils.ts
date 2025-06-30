import { InvalidBase64UrlError, MissingKeyError } from './errors';

/**
 * Encodes a Buffer or string to base64url format
 */
export function base64UrlEncode(input: Buffer | string): string {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decodes a base64url string to Buffer
 */
export function base64UrlDecode(input: string): Buffer {
  // Check if input contains only valid base64url characters
  if (!/^[A-Za-z0-9\-_]*$/.test(input)) {
    throw new InvalidBase64UrlError();
  }

  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
  return Buffer.from(padded, 'base64');
}

/**
 * Parses a duration string (e.g., '1h', '30m', '60s') or number to seconds
 */
export function parseExpiresIn(expiresIn: string | number): number {
  if (typeof expiresIn === 'number') {
    return expiresIn;
  }
  const match = expiresIn.match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error('Invalid expiresIn format');
  }
  const value = parseInt(match[1], 10);
  const unit = match[2];
  switch (unit) {
    case 's':
      return value;
    case 'm':
      return value * 60;
    case 'h':
      return value * 60 * 60;
    case 'd':
      return value * 24 * 60 * 60;
    default:
      throw new Error('Invalid expiresIn unit');
  }
}

/**
 * Validates if a key is a valid PEM-formatted key.
 * @param key - The key to validate (string or Buffer).
 * @param type - The expected key type ('private' or 'public').
 * @returns True if the key is valid.
 * @throws {MissingKeyError} If the key is not in a valid PEM format.
 */
export function validatePemKey(key: string | Buffer, type: 'private' | 'public'): boolean {
  const keyStr = key.toString('utf-8').trim();

  const startsWith =
    type === 'private' ? '-----BEGIN PRIVATE KEY-----' : '-----BEGIN PUBLIC KEY-----';
  const endsWith = type === 'private' ? '-----END PRIVATE KEY-----' : '-----END PUBLIC KEY-----';

  if (!keyStr.startsWith(startsWith) || !keyStr.endsWith(endsWith)) {
    throw new MissingKeyError(`Invalid ${type} key format. Expected a PEM-encoded key.`);
  }

  return true;
}

/**
 * Encodes a Buffer or string to base64url format
 */
export function base64UrlEncode(input: Buffer | string): string {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Decodes a base64url string to Buffer
 */
export function base64UrlDecode(input: string): Buffer {
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

  const match = expiresIn.match(/^(\d+)([smh])$/);
  if (!match) {
    throw new Error('Invalid expiresIn format. Use number of seconds or string like "1h", "30m", "60s"');
  }

  const [, value, unit] = match;
  const numValue = parseInt(value, 10);

  switch (unit) {
    case 's':
      return numValue;
    case 'm':
      return numValue * 60;
    case 'h':
      return numValue * 3600;
    default:
      throw new Error('Invalid time unit. Use s, m, or h');
  }
} 
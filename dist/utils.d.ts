/**
 * Encodes a Buffer or string to base64url format
 */
export declare function base64UrlEncode(input: Buffer | string): string;
/**
 * Decodes a base64url string to Buffer
 */
export declare function base64UrlDecode(input: string): Buffer;
/**
 * Parses a duration string (e.g., '1h', '30m', '60s') or number to seconds
 */
export declare function parseExpiresIn(expiresIn: string | number): number;

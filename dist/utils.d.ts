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
/**
 * Validates if a key is a valid PEM-formatted key.
 * @param key - The key to validate (string or Buffer).
 * @param type - The expected key type ('private' or 'public').
 * @returns True if the key is valid.
 * @throws {MissingKeyError} If the key is not in a valid PEM format.
 */
export declare function validatePemKey(key: string | Buffer, type: 'private' | 'public'): boolean;

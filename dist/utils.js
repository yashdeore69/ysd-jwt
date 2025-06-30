"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.base64UrlEncode = base64UrlEncode;
exports.base64UrlDecode = base64UrlDecode;
exports.parseExpiresIn = parseExpiresIn;
exports.validatePemKey = validatePemKey;
const errors_1 = require("./errors");
/**
 * Encodes a Buffer or string to base64url format
 */
function base64UrlEncode(input) {
    const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
/**
 * Decodes a base64url string to Buffer
 */
function base64UrlDecode(input) {
    // Check if input contains only valid base64url characters
    if (!/^[A-Za-z0-9\-_]*$/.test(input)) {
        throw new errors_1.InvalidBase64UrlError();
    }
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
    return Buffer.from(padded, 'base64');
}
/**
 * Parses a duration string (e.g., '1h', '30m', '60s') or number to seconds
 */
function parseExpiresIn(expiresIn) {
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
function validatePemKey(key, type) {
    const keyStr = key.toString('utf-8').trim();
    const startsWith = type === 'private' ? '-----BEGIN PRIVATE KEY-----' : '-----BEGIN PUBLIC KEY-----';
    const endsWith = type === 'private' ? '-----END PRIVATE KEY-----' : '-----END PUBLIC KEY-----';
    if (!keyStr.startsWith(startsWith) || !keyStr.endsWith(endsWith)) {
        throw new errors_1.MissingKeyError(`Invalid ${type} key format. Expected a PEM-encoded key.`);
    }
    return true;
}

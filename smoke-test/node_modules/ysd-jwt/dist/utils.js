"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.base64UrlEncode = base64UrlEncode;
exports.base64UrlDecode = base64UrlDecode;
exports.parseExpiresIn = parseExpiresIn;
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
    if (expiresIn == null || typeof expiresIn !== 'string') {
        throw new errors_1.InvalidDurationError('Invalid input type. Expected string or number');
    }
    const match = expiresIn.match(/^(\d+)([smh])$/);
    if (!match) {
        throw new errors_1.InvalidDurationError('Invalid expiresIn format. Use number of seconds or string like "1h", "30m", "60s"');
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
            throw new errors_1.InvalidDurationError('Invalid time unit. Use s, m, or h');
    }
}

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sign = sign;
const crypto_1 = require("crypto");
const utils_1 = require("./utils");
const utils_2 = require("./utils");
const errors_1 = require("./errors");
/**
 * Signs a JWT payload with the provided options
 * @param payload - The JWT payload to sign
 * @param options - Signing options including secret key and optional claims
 * @returns The signed JWT token
 * @throws {MissingKeyError} If secret/privateKey is missing or invalid
 * @throws {ClaimValidationError} If payload contains invalid claims
 */
function sign(payload, options) {
    const algorithm = options.algorithm || 'HS256';
    // Validate key based on algorithm
    if (algorithm === 'HS256') {
        if (!options.secret) {
            throw new errors_1.MissingKeyError('Secret is required for HS256 signing');
        }
        if (options.secret.length < 32) {
            throw new errors_1.MissingKeyError('Secret must be at least 32 characters long');
        }
    }
    else if (algorithm === 'RS256') {
        if (!options.privateKey) {
            throw new errors_1.MissingKeyError('Private key is required for RS256 signing');
        }
        (0, utils_1.validatePemKey)(options.privateKey, 'private');
    }
    // Validate payload
    if (typeof payload !== 'object' || payload === null) {
        throw new errors_1.ClaimValidationError('Payload must be a non-null object');
    }
    // Create header
    const header = {
        alg: algorithm,
        typ: 'JWT',
        ...options.header, // Allow custom header fields
    };
    // Prepare payload
    const now = Math.floor(Date.now() / 1000);
    const finalPayload = { ...payload };
    // Set standard claims
    finalPayload.iat = now;
    if (options.expiresIn) {
        finalPayload.exp = now + (0, utils_2.parseExpiresIn)(options.expiresIn);
    }
    if (options.notBefore) {
        finalPayload.nbf = now + (0, utils_2.parseExpiresIn)(options.notBefore);
    }
    if (options.issuer) {
        finalPayload.iss = options.issuer;
    }
    if (options.audience) {
        finalPayload.aud = options.audience;
    }
    if (options.jwtid) {
        finalPayload.jti = options.jwtid;
    }
    // Encode header and payload
    const encodedHeader = (0, utils_1.base64UrlEncode)(JSON.stringify(header));
    const encodedPayload = (0, utils_1.base64UrlEncode)(JSON.stringify(finalPayload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    // Create signature based on algorithm
    let signature;
    if (algorithm === 'HS256') {
        signature = (0, crypto_1.createHmac)('sha256', options.secret).update(signingInput).digest();
    }
    else if (algorithm === 'RS256') {
        signature = (0, crypto_1.createSign)('RSA-SHA256').update(signingInput).sign(options.privateKey);
    }
    else {
        throw new errors_1.ClaimValidationError(`Unsupported algorithm: ${algorithm}`);
    }
    // Return final token
    return `${encodedHeader}.${encodedPayload}.${(0, utils_1.base64UrlEncode)(signature)}`;
}

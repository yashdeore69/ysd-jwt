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
 * @throws {MissingKeyError} If secret is missing or too short
 * @throws {ClaimValidationError} If payload contains invalid claims
 */
function sign(payload, options) {
    // Validate secret
    if (!options.secret) {
        throw new errors_1.MissingKeyError('Secret is required for signing');
    }
    if (options.secret.length < 32) {
        throw new errors_1.MissingKeyError('Secret must be at least 32 characters long');
    }
    // Validate payload
    if (typeof payload !== 'object' || payload === null) {
        throw new errors_1.ClaimValidationError('Payload must be a non-null object');
    }
    // Create header
    const header = {
        alg: options.algorithm || 'HS256',
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
    // Map JWT alg to Node.js digest
    const algMap = {
        HS256: 'sha256',
        HS384: 'sha384',
        HS512: 'sha512',
    };
    const digestAlg = algMap[header.alg];
    if (!digestAlg) {
        throw new errors_1.ClaimValidationError(`Unsupported algorithm: ${header.alg}`);
    }
    // Create signature
    const signature = (0, crypto_1.createHmac)(digestAlg, options.secret)
        .update(`${encodedHeader}.${encodedPayload}`)
        .digest();
    // Return final token
    return `${encodedHeader}.${encodedPayload}.${(0, utils_1.base64UrlEncode)(signature)}`;
}

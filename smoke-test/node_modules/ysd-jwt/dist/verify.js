"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verify = verify;
const crypto_1 = require("crypto");
const utils_1 = require("./utils");
const errors_1 = require("./errors");
/**
 * Verifies a JWT token and returns its payload
 * @param token - The JWT token to verify
 * @param options - Verification options including secret key and optional claims
 * @returns The verified JWT payload
 * @throws {MissingKeyError} If secret is missing
 * @throws {MalformedTokenError} If token is malformed
 * @throws {InvalidSignatureError} If signature is invalid
 * @throws {TokenExpiredError} If token has expired
 * @throws {ClaimValidationError} If claims are invalid
 */
function verify(token, options) {
    // Validate secret
    if (!options.secret) {
        throw new errors_1.MissingKeyError('Secret is required for verification');
    }
    // Split token
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new errors_1.MalformedTokenError('Invalid token: expected 3 segments');
    }
    // Parse header
    let header;
    try {
        header = JSON.parse((0, utils_1.base64UrlDecode)(parts[0]).toString());
    }
    catch {
        throw new errors_1.MalformedTokenError('Invalid token header');
    }
    // Validate algorithm
    const supportedAlgorithms = ['HS256', 'HS384', 'HS512'];
    if (!supportedAlgorithms.includes(header.alg)) {
        throw new errors_1.InvalidSignatureError(`Unsupported algorithm: ${header.alg}`);
    }
    // Map JWT alg to Node.js digest
    const algMap = {
        HS256: 'sha256',
        HS384: 'sha384',
        HS512: 'sha512',
    };
    const digestAlg = algMap[header.alg];
    // Parse payload first to validate JSON
    let payload;
    try {
        payload = JSON.parse((0, utils_1.base64UrlDecode)(parts[1]).toString());
    }
    catch {
        throw new errors_1.MalformedTokenError('Invalid token payload');
    }
    // Verify signature
    const signature = (0, crypto_1.createHmac)(digestAlg, options.secret)
        .update(`${parts[0]}.${parts[1]}`)
        .digest();
    let providedSignature;
    try {
        providedSignature = (0, utils_1.base64UrlDecode)(parts[2]);
    }
    catch {
        throw new errors_1.MalformedTokenError('Invalid signature encoding');
    }
    // Compare signatures
    try {
        if (!(0, crypto_1.timingSafeEqual)(signature, providedSignature)) {
            throw new errors_1.InvalidSignatureError('Invalid signature');
        }
    }
    catch {
        throw new errors_1.InvalidSignatureError('Invalid signature');
    }
    // Validate claims
    const now = Math.floor(Date.now() / 1000);
    const clockTolerance = options.clockToleranceSec || 5;
    // Check expiration
    if (payload.exp && now - clockTolerance > payload.exp) {
        throw new errors_1.TokenExpiredError(`Token expired at ${new Date(payload.exp * 1000).toISOString()}`);
    }
    // Check not before
    if (payload.nbf && now + clockTolerance < payload.nbf) {
        throw new errors_1.ClaimValidationError(`Token not valid before ${new Date(payload.nbf * 1000).toISOString()}`);
    }
    // Check issued at
    if (payload.iat && now + clockTolerance < payload.iat) {
        throw new errors_1.ClaimValidationError(`Token used before issued at ${new Date(payload.iat * 1000).toISOString()}`);
    }
    // Check issuer
    if (options.issuer && payload.iss !== options.issuer) {
        throw new errors_1.ClaimValidationError(`Invalid issuer: expected ${options.issuer}, got ${payload.iss}`);
    }
    // Check audience
    if (options.audience) {
        const aud = payload.aud;
        if (!aud) {
            throw new errors_1.ClaimValidationError('Token audience is required');
        }
        const expectedAud = Array.isArray(options.audience) ? options.audience : [options.audience];
        const tokenAud = Array.isArray(aud) ? aud : [aud];
        const hasValidAud = tokenAud.some((a) => expectedAud.includes(a));
        if (!hasValidAud) {
            throw new errors_1.ClaimValidationError(`Invalid audience: expected ${expectedAud.join(', ')}, got ${tokenAud.join(', ')}`);
        }
    }
    return payload;
}

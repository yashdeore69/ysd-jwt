import { createHmac, createSign } from 'crypto';
import { base64UrlEncode } from './utils';
import { parseExpiresIn } from './utils';
import { SignOptions, JwtHeader, JwtPayload } from './types';
import { MissingKeyError, ClaimValidationError } from './errors';

/**
 * Signs a JWT payload with the provided options
 * @param payload - The JWT payload to sign
 * @param options - Signing options including secret key and optional claims
 * @returns The signed JWT token
 * @throws {MissingKeyError} If secret/privateKey is missing or invalid
 * @throws {ClaimValidationError} If payload contains invalid claims
 */
export function sign(payload: JwtPayload, options: SignOptions): string {
  const algorithm = options.algorithm || 'HS256';

  // Validate key based on algorithm
  if (algorithm === 'HS256') {
    if (!options.secret) {
      throw new MissingKeyError('Secret is required for HS256 signing');
    }
    if (options.secret.length < 32) {
      throw new MissingKeyError('Secret must be at least 32 characters long');
    }
  } else if (algorithm === 'RS256') {
    if (!options.privateKey) {
      throw new MissingKeyError('Private key is required for RS256 signing');
    }
  }

  // Validate payload
  if (typeof payload !== 'object' || payload === null) {
    throw new ClaimValidationError('Payload must be a non-null object');
  }

  // Create header
  const header: JwtHeader = {
    alg: algorithm,
    typ: 'JWT',
    ...options.header, // Allow custom header fields
  };

  // Prepare payload
  const now = Math.floor(Date.now() / 1000);
  const finalPayload: JwtPayload = { ...payload };

  // Set standard claims
  finalPayload.iat = now;

  if (options.expiresIn) {
    finalPayload.exp = now + parseExpiresIn(options.expiresIn);
  }

  if (options.notBefore) {
    finalPayload.nbf = now + parseExpiresIn(options.notBefore);
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
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(finalPayload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  // Create signature based on algorithm
  let signature: Buffer;
  if (algorithm === 'HS256') {
    signature = createHmac('sha256', options.secret!)
      .update(signingInput)
      .digest();
  } else if (algorithm === 'RS256') {
    signature = createSign('RSA-SHA256')
      .update(signingInput)
      .sign(options.privateKey!);
  } else {
    throw new ClaimValidationError(`Unsupported algorithm: ${algorithm}`);
  }

  // Return final token
  return `${encodedHeader}.${encodedPayload}.${base64UrlEncode(signature)}`;
}

import { createHmac } from 'crypto';
import { base64UrlEncode } from './utils';
import { parseExpiresIn } from './utils';
import { SignOptions, JwtHeader, JwtPayload } from './types';
import { MissingKeyError, ClaimValidationError } from './errors';

/**
 * Signs a JWT payload with the provided options
 * @param payload - The JWT payload to sign
 * @param options - Signing options including secret key and optional claims
 * @returns The signed JWT token
 * @throws {MissingKeyError} If secret is missing or too short
 * @throws {ClaimValidationError} If payload contains invalid claims
 */
export function sign(payload: JwtPayload, options: SignOptions): string {
  // Validate secret
  if (!options.secret) {
    throw new MissingKeyError('Secret is required for signing');
  }
  if (options.secret.length < 32) {
    throw new MissingKeyError('Secret must be at least 32 characters long');
  }

  // Validate payload
  if (typeof payload !== 'object' || payload === null) {
    throw new ClaimValidationError('Payload must be a non-null object');
  }

  // Create header
  const header: JwtHeader = {
    alg: options.algorithm || 'HS256',
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

  // Map JWT alg to Node.js digest
  const algMap: Record<string, string> = {
    HS256: 'sha256',
    HS384: 'sha384',
    HS512: 'sha512',
  };
  const digestAlg = algMap[header.alg];
  if (!digestAlg) {
    throw new ClaimValidationError(`Unsupported algorithm: ${header.alg}`);
  }

  // Create signature
  const signature = createHmac(digestAlg, options.secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest();

  // Return final token
  return `${encodedHeader}.${encodedPayload}.${base64UrlEncode(signature)}`;
}

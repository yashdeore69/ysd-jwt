import { createHmac, timingSafeEqual } from 'crypto';
import { base64UrlDecode } from './utils';
import { VerifyOptions, JwtHeader, JwtPayload } from './types';
import {
  MissingKeyError,
  TokenExpiredError,
  InvalidSignatureError,
  ClaimValidationError,
  MalformedTokenError,
} from './errors';

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
export function verify(token: string, options: VerifyOptions): JwtPayload {
  // Validate secret
  if (!options.secret) {
    throw new MissingKeyError('Secret is required for verification');
  }

  // Split token
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new MalformedTokenError('Invalid token: expected 3 segments');
  }

  // Parse header
  let header: JwtHeader;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]).toString());
  } catch {
    throw new MalformedTokenError('Invalid token header');
  }

  // Validate algorithm
  const supportedAlgorithms = ['HS256', 'HS384', 'HS512'];
  if (!supportedAlgorithms.includes(header.alg)) {
    throw new InvalidSignatureError(`Unsupported algorithm: ${header.alg}`);
  }

  // Map JWT alg to Node.js digest
  const algMap: Record<string, string> = {
    HS256: 'sha256',
    HS384: 'sha384',
    HS512: 'sha512',
  };
  const digestAlg = algMap[header.alg];

  // Parse payload first to validate JSON
  let payload: JwtPayload;
  try {
    payload = JSON.parse(base64UrlDecode(parts[1]).toString());
  } catch {
    throw new MalformedTokenError('Invalid token payload');
  }

  // Verify signature
  const signature = createHmac(digestAlg, options.secret)
    .update(`${parts[0]}.${parts[1]}`)
    .digest();

  let providedSignature: Buffer;
  try {
    providedSignature = base64UrlDecode(parts[2]);
  } catch {
    throw new MalformedTokenError('Invalid signature encoding');
  }

  // Compare signatures
  try {
    if (!timingSafeEqual(signature, providedSignature)) {
      throw new InvalidSignatureError('Invalid signature');
    }
  } catch {
    throw new InvalidSignatureError('Invalid signature');
  }

  // Validate claims
  const now = Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockToleranceSec || 5;

  // Check expiration
  if (payload.exp && now - clockTolerance > payload.exp) {
    throw new TokenExpiredError(`Token expired at ${new Date(payload.exp * 1000).toISOString()}`);
  }

  // Check not before
  if (payload.nbf && now + clockTolerance < payload.nbf) {
    throw new ClaimValidationError(
      `Token not valid before ${new Date(payload.nbf * 1000).toISOString()}`
    );
  }

  // Check issued at
  if (payload.iat && now + clockTolerance < payload.iat) {
    throw new ClaimValidationError(
      `Token used before issued at ${new Date(payload.iat * 1000).toISOString()}`
    );
  }

  // Check issuer
  if (options.issuer && payload.iss !== options.issuer) {
    throw new ClaimValidationError(
      `Invalid issuer: expected ${options.issuer}, got ${payload.iss}`
    );
  }

  // Check audience
  if (options.audience) {
    const aud = payload.aud;
    if (!aud) {
      throw new ClaimValidationError('Token audience is required');
    }

    const expectedAud = Array.isArray(options.audience) ? options.audience : [options.audience];

    const tokenAud = Array.isArray(aud) ? aud : [aud];

    const hasValidAud = tokenAud.some((a) => expectedAud.includes(a));
    if (!hasValidAud) {
      throw new ClaimValidationError(
        `Invalid audience: expected ${expectedAud.join(', ')}, got ${tokenAud.join(', ')}`
      );
    }
  }

  return payload;
}

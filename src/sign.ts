import { createHmac } from 'crypto';
import { base64UrlEncode } from './utils';
import { parseExpiresIn } from './utils';
import { SignOptions, JwtHeader, JwtPayload } from './types';
import { MissingKeyError } from './errors';

export function sign(payload: JwtPayload, options: SignOptions): string {
  // Validate secret
  if (!options.secret) {
    throw new MissingKeyError('Secret is required for signing');
  }
  if (options.secret.length < 32) {
    throw new MissingKeyError('Secret must be at least 32 characters long');
  }

  // Create header
  const header: JwtHeader = {
    alg: 'HS256',
    typ: 'JWT'
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

  // Encode header and payload
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(finalPayload));

  // Create signature
  const signature = createHmac('sha256', options.secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest();

  // Return final token
  return `${encodedHeader}.${encodedPayload}.${base64UrlEncode(signature)}`;
} 
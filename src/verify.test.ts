import { verify } from './verify';
import { sign } from './sign';
import {
  MissingKeyError,
  TokenExpiredError,
  InvalidSignatureError,
  ClaimValidationError,
  MalformedTokenError,
} from './errors';
import crypto from 'crypto';

describe('verify', () => {
  const secret = 'your-256-bit-secret-your-256-bit-secret';
  const payload = { sub: '1234567890', name: 'John Doe' };

  it('should verify a valid token', () => {
    const token = sign(payload, { secret });
    const verified = verify(token, { secret });
    expect(verified).toEqual(expect.objectContaining(payload));
  });

  it('should throw MissingKeyError when secret is missing', () => {
    const token = sign(payload, { secret });
    expect(() => verify(token, {} as any)).toThrow(MissingKeyError);
  });

  it('should throw MalformedTokenError for invalid token format', () => {
    expect(() => verify('invalid.token', { secret })).toThrow(MalformedTokenError);
    expect(() => verify('part1.part2', { secret })).toThrow(MalformedTokenError);
    expect(() => verify('part1.part2.part3.part4', { secret })).toThrow(MalformedTokenError);
  });

  it('should throw MalformedTokenError for invalid base64url encoding', () => {
    expect(() => verify('invalid!.part2.part3', { secret })).toThrow(MalformedTokenError);
  });

  it('should throw MalformedTokenError for invalid JSON in header', () => {
    const invalidHeader = Buffer.from('invalid json').toString('base64url');
    expect(() => verify(`${invalidHeader}.part2.part3`, { secret })).toThrow(MalformedTokenError);
  });

  it('should throw MalformedTokenError for invalid JSON in payload', () => {
    const validHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString(
      'base64url'
    );
    const invalidPayload = Buffer.from('invalid json').toString('base64url');
    expect(() => verify(`${validHeader}.${invalidPayload}.part3`, { secret })).toThrow(
      MalformedTokenError
    );
  });

  it('should throw InvalidSignatureError for invalid signature', () => {
    const token = sign(payload, { secret });
    const [, payloadPart] = token.split('.');
    const invalidSignature = 'invalid_signature';
    expect(() =>
      verify(`${token.split('.')[0]}.${payloadPart}.${invalidSignature}`, { secret })
    ).toThrow(InvalidSignatureError);
  });

  it('should throw InvalidSignatureError for unsupported algorithm', () => {
    const token = sign(payload, { secret });
    const [, payloadPart, signature] = token.split('.');
    const invalidHeader = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString(
      'base64url'
    );
    expect(() => verify(`${invalidHeader}.${payloadPart}.${signature}`, { secret })).toThrow(
      InvalidSignatureError
    );
  });

  it('should throw TokenExpiredError for expired token', () => {
    // Create a token that's already expired
    const now = Math.floor(Date.now() / 1000);
    const expiredPayload = {
      ...payload,
      exp: now - 10, // Expired 10 seconds ago
    };
    const token = sign(expiredPayload, { secret });
    expect(() => verify(token, { secret, clockToleranceSec: 0 })).toThrow(TokenExpiredError);
  });

  it('should throw ClaimValidationError for future not-before time', () => {
    const token = sign(payload, { secret, notBefore: '1h' });
    expect(() => verify(token, { secret })).toThrow(ClaimValidationError);
  });

  it('should throw ClaimValidationError for future issued-at time', () => {
    const token = sign(payload, { secret });
    const [header] = token.split('.');
    const futurePayload = {
      ...payload,
      iat: Math.floor(Date.now() / 1000) + 3600, // 1 hour in the future
    };
    const encodedPayload = Buffer.from(JSON.stringify(futurePayload)).toString('base64url');
    // Recompute signature for the new payload
    const signature = crypto
      .createHmac('sha256', secret)
      .update(`${header}.${encodedPayload}`)
      .digest('base64url');
    expect(() => verify(`${header}.${encodedPayload}.${signature}`, { secret })).toThrow(
      ClaimValidationError
    );
  });

  it('should validate issuer claim', () => {
    const token = sign(payload, { secret, issuer: 'test-issuer' });
    expect(() => verify(token, { secret, issuer: 'wrong-issuer' })).toThrow(ClaimValidationError);
    expect(verify(token, { secret, issuer: 'test-issuer' })).toBeDefined();
  });

  it('should validate audience claim', () => {
    const token = sign(payload, { secret, audience: 'test-audience' });
    expect(() => verify(token, { secret, audience: 'wrong-audience' })).toThrow(
      ClaimValidationError
    );
    expect(verify(token, { secret, audience: 'test-audience' })).toBeDefined();
  });

  it('should validate array audience claim', () => {
    const token = sign(payload, { secret, audience: ['aud1', 'aud2'] });
    expect(() => verify(token, { secret, audience: 'wrong-audience' })).toThrow(
      ClaimValidationError
    );
    expect(verify(token, { secret, audience: ['aud1', 'aud2'] })).toBeDefined();
    expect(verify(token, { secret, audience: 'aud1' })).toBeDefined();
  });

  it('should support different algorithms', () => {
    const algorithms = ['HS256', 'HS384', 'HS512'] as const;

    for (const alg of algorithms) {
      const token = sign(payload, { secret, algorithm: alg });
      const verified = verify(token, { secret });
      expect(verified).toEqual(expect.objectContaining(payload));
    }
  });

  it('should preserve custom payload properties', () => {
    const customPayload = {
      ...payload,
      customField: 'customValue',
      nested: { field: 'value' },
    };
    const token = sign(customPayload, { secret });
    const verified = verify(token, { secret });
    expect(verified).toEqual(expect.objectContaining(customPayload));
  });
});

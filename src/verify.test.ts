import { verify } from './verify';
import { sign } from './sign';
import { base64UrlEncode } from '../src/utils';
import {
  MissingKeyError,
  TokenExpiredError,
  InvalidSignatureError,
  ClaimValidationError,
  MalformedTokenError,
} from './errors';
import { generateKeyPairSync } from 'crypto';

describe('verify', () => {
  const secret = 'your-256-bit-secret-your-256-bit-secret';
  const payload = { sub: '1234567890', name: 'John Doe' };

  // Generate RSA key pair for RS256 tests
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  describe('HS256', () => {
    it('should verify a valid JWT token', () => {
      const token = sign(payload, { secret });
      const verified = verify(token, { secret });
      expect(verified).toEqual(expect.objectContaining(payload));
    });

    it('should throw MissingKeyError when secret is missing', () => {
      const token = sign(payload, { secret });
      expect(() => verify(token, {} as any)).toThrow(MissingKeyError);
    });

    it('should throw InvalidSignatureError when secret is wrong', () => {
      const token = sign(payload, { secret });
      expect(() => verify(token, { secret: 'wrong-secret' })).toThrow(InvalidSignatureError);
    });

    it('should throw InvalidSignatureError when token is tampered with', () => {
      const token = sign(payload, { secret });
      const [header, payloadPart, signature] = token.split('.');
      const tamperedToken = `${header}.${payloadPart}.${signature.slice(0, -1)}`;
      expect(() => verify(tamperedToken, { secret })).toThrow(InvalidSignatureError);
    });

    it('should validate standard claims', () => {
      const token = sign(
        {
          ...payload,
          exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
          nbf: Math.floor(Date.now() / 1000) - 60, // 1 minute ago
          iss: 'test-issuer',
          aud: 'test-audience',
        },
        { secret }
      );

      const verified = verify(token, {
        secret,
        issuer: 'test-issuer',
        audience: 'test-audience',
      });

      expect(verified).toHaveProperty('exp');
      expect(verified).toHaveProperty('nbf');
      expect(verified).toHaveProperty('iss', 'test-issuer');
      expect(verified).toHaveProperty('aud', 'test-audience');
    });

    it('should throw TokenExpiredError for expired token', () => {
      const token = sign(
        {
          ...payload,
          exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        },
        { secret }
      );

      expect(() => verify(token, { secret })).toThrow(TokenExpiredError);
    });

    it('should throw ClaimValidationError for future nbf', () => {
      const token = sign(
        {
          ...payload,
          nbf: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
        },
        { secret }
      );

      expect(() => verify(token, { secret })).toThrow(ClaimValidationError);
    });

    it('should throw ClaimValidationError for wrong issuer', () => {
      const token = sign(
        {
          ...payload,
          iss: 'wrong-issuer',
        },
        { secret }
      );

      expect(() => verify(token, { secret, issuer: 'correct-issuer' })).toThrow(
        ClaimValidationError
      );
    });

    it('should throw ClaimValidationError for wrong audience', () => {
      const token = sign(
        {
          ...payload,
          aud: 'wrong-audience',
        },
        { secret }
      );

      expect(() => verify(token, { secret, audience: 'correct-audience' })).toThrow(
        ClaimValidationError
      );
    });

    describe('Clock Tolerance', () => {
      it('should accept a token that is slightly expired within tolerance', () => {
        const token = sign(
          { ...payload, exp: Math.floor(Date.now() / 1000) - 3 }, // 3 seconds ago
          { secret }
        );
        const verified = verify(token, { secret, clockToleranceSec: 5 });
        expect(verified).toBeTruthy();
      });

      it('should reject a token that is expired beyond tolerance', () => {
        const token = sign(
          { ...payload, exp: Math.floor(Date.now() / 1000) - 10 }, // 10 seconds ago
          { secret }
        );
        expect(() => verify(token, { secret, clockToleranceSec: 5 })).toThrow(TokenExpiredError);
      });

      it('should accept a token that is slightly before its nbf within tolerance', () => {
        const token = sign(
          { ...payload, nbf: Math.floor(Date.now() / 1000) + 3 }, // 3 seconds from now
          { secret }
        );
        const verified = verify(token, { secret, clockToleranceSec: 5 });
        expect(verified).toBeTruthy();
      });

      it('should reject a token that is before its nbf beyond tolerance', () => {
        const token = sign(
          { ...payload, nbf: Math.floor(Date.now() / 1000) + 10 }, // 10 seconds from now
          { secret }
        );
        expect(() => verify(token, { secret, clockToleranceSec: 5 })).toThrow(ClaimValidationError);
      });
    });

    it('should throw MalformedTokenError for invalid token format', () => {
      expect(() => verify('invalid.token', { secret })).toThrow(MalformedTokenError);
    });

    it('should throw MalformedTokenError for invalid base64', () => {
      expect(() => verify('header.payload.signature!', { secret })).toThrow(MalformedTokenError);
    });

    it('should throw MalformedTokenError for invalid JSON', () => {
      const invalidJson = Buffer.from('{"invalid": json}').toString('base64url');
      expect(() => verify(`header.${invalidJson}.signature`, { secret })).toThrow(
        MalformedTokenError
      );
    });

    it('should handle custom payload properties', () => {
      const customPayload = {
        ...payload,
        customField: 'customValue',
        nested: { field: 'value' },
      };

      const token = sign(customPayload, { secret });
      const verified = verify(token, { secret });
      expect(verified).toEqual(expect.objectContaining(customPayload));
    });

    it('should correctly verify a token with unicode characters', () => {
      const unicodePayload = { ...payload, user: 'Jöhn Døe', data: 'äöüß' };
      const token = sign(unicodePayload, { secret });
      const verified = verify(token, { secret });
      expect(verified.user).toBe('Jöhn Døe');
      expect(verified.data).toBe('äöüß');
    });

    it('should reject tokens with "none" algorithm in the header', () => {
      const header = { alg: 'none', typ: 'JWT' };
      const encodedHeader = base64UrlEncode(JSON.stringify(header));
      const encodedPayload = base64UrlEncode(JSON.stringify(payload));
      const token = `${encodedHeader}.${encodedPayload}.`; // No signature

      expect(() => verify(token, { secret, algorithm: 'HS256' })).toThrow(InvalidSignatureError);
    });
  });

  describe('RS256', () => {
    it('should verify a valid JWT token with RS256', () => {
      const token = sign(payload, { privateKey, algorithm: 'RS256' });
      const verified = verify(token, { publicKey, algorithm: 'RS256' });
      expect(verified).toEqual(expect.objectContaining(payload));
    });

    it('should throw MissingKeyError when publicKey is missing', () => {
      const token = sign(payload, { privateKey, algorithm: 'RS256' });
      expect(() => verify(token, { algorithm: 'RS256' })).toThrow(MissingKeyError);
    });

    it('should throw MissingKeyError for invalid publicKey format', () => {
      const token = sign(payload, { privateKey, algorithm: 'RS256' });
      const invalidPublicKey = 'not-a-valid-pem-key';
      expect(() => verify(token, { publicKey: invalidPublicKey, algorithm: 'RS256' })).toThrow(
        MissingKeyError
      );
    });

    it('should throw InvalidSignatureError when publicKey is wrong', () => {
      const token = sign(payload, { privateKey, algorithm: 'RS256' });
      const wrongKeyPair = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      expect(() =>
        verify(token, { publicKey: wrongKeyPair.publicKey, algorithm: 'RS256' })
      ).toThrow(InvalidSignatureError);
    });

    it('should throw InvalidSignatureError when token is tampered with', () => {
      const token = sign(payload, { privateKey, algorithm: 'RS256' });
      const [header, payloadPart, signature] = token.split('.');
      const tamperedToken = `${header}.${payloadPart}.${signature.slice(0, -1)}`;
      expect(() => verify(tamperedToken, { publicKey, algorithm: 'RS256' })).toThrow(
        InvalidSignatureError
      );
    });

    it('should validate standard claims', () => {
      const token = sign(
        {
          ...payload,
          exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
          nbf: Math.floor(Date.now() / 1000) - 60, // 1 minute ago
          iss: 'test-issuer',
          aud: 'test-audience',
        },
        { privateKey, algorithm: 'RS256' }
      );

      const verified = verify(token, {
        publicKey,
        algorithm: 'RS256',
        issuer: 'test-issuer',
        audience: 'test-audience',
      });

      expect(verified).toHaveProperty('exp');
      expect(verified).toHaveProperty('nbf');
      expect(verified).toHaveProperty('iss', 'test-issuer');
      expect(verified).toHaveProperty('aud', 'test-audience');
    });

    it('should throw TokenExpiredError for expired token', () => {
      const token = sign(
        {
          ...payload,
          exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        },
        { privateKey, algorithm: 'RS256' }
      );

      expect(() => verify(token, { publicKey, algorithm: 'RS256' })).toThrow(TokenExpiredError);
    });

    it('should throw ClaimValidationError for future nbf', () => {
      const token = sign(
        {
          ...payload,
          nbf: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
        },
        { privateKey, algorithm: 'RS256' }
      );

      expect(() => verify(token, { publicKey, algorithm: 'RS256' })).toThrow(ClaimValidationError);
    });

    it('should throw ClaimValidationError for wrong issuer', () => {
      const token = sign(
        {
          ...payload,
          iss: 'wrong-issuer',
        },
        { privateKey, algorithm: 'RS256' }
      );

      expect(() =>
        verify(token, { publicKey, algorithm: 'RS256', issuer: 'correct-issuer' })
      ).toThrow(ClaimValidationError);
    });

    it('should throw ClaimValidationError for wrong audience', () => {
      const token = sign(
        {
          ...payload,
          aud: 'wrong-audience',
        },
        { privateKey, algorithm: 'RS256' }
      );

      expect(() =>
        verify(token, { publicKey, algorithm: 'RS256', audience: 'correct-audience' })
      ).toThrow(ClaimValidationError);
    });

    it('should throw MalformedTokenError for invalid token format', () => {
      expect(() => verify('invalid.token', { publicKey, algorithm: 'RS256' })).toThrow(
        MalformedTokenError
      );
    });

    it('should throw MalformedTokenError for invalid base64', () => {
      expect(() => verify('header.payload.signature!', { publicKey, algorithm: 'RS256' })).toThrow(
        MalformedTokenError
      );
    });

    it('should throw MalformedTokenError for invalid JSON', () => {
      const invalidJson = Buffer.from('{"invalid": json}').toString('base64url');
      expect(() =>
        verify(`header.${invalidJson}.signature`, { publicKey, algorithm: 'RS256' })
      ).toThrow(MalformedTokenError);
    });
  });

  describe('Security', () => {
    it('should not allow algorithm confusion (HS256 token, RS256 verify)', () => {
      // Attacker creates a token with alg: HS256 but using the public key as the secret
      const token = sign(payload, {
        secret: publicKey.toString(), // Using public key as HS256 secret
        algorithm: 'HS256',
        header: { alg: 'HS256' },
      });

      // Server tries to verify with RS256, but attacker's token should be rejected
      expect(() =>
        verify(token, {
          publicKey,
          algorithm: 'RS256',
        })
      ).toThrow(InvalidSignatureError);
    });

    it('should reject tokens with "none" algorithm', () => {
      const header = { alg: 'none', typ: 'JWT' };
      const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
      const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const token = `${encodedHeader}.${encodedPayload}.`; // No signature

      expect(() => verify(token, { secret, algorithm: 'none' as any })).toThrow(
        InvalidSignatureError
      );
    });
  });
});

import { sign } from './sign';
import { MissingKeyError, ClaimValidationError } from './errors';
import { generateKeyPairSync } from 'crypto';

describe('sign', () => {
  const secret = 'your-256-bit-secret-your-256-bit-secret';
  const payload = { sub: '1234567890', name: 'John Doe' };

  // Generate RSA key pair for RS256 tests
  const { privateKey } = generateKeyPairSync('rsa', {
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
    it('should create a valid JWT token', () => {
      const token = sign(payload, { secret });
      const parts = token.split('.');

      expect(parts).toHaveLength(3);
      expect(parts[0]).toMatch(/^[A-Za-z0-9_-]+$/); // header
      expect(parts[1]).toMatch(/^[A-Za-z0-9_-]+$/); // payload
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/); // signature
    });

    it('should include standard claims when provided', () => {
      const token = sign(payload, {
        secret,
        expiresIn: '1h',
        notBefore: '1m',
        issuer: 'test-issuer',
        audience: 'test-audience',
        jwtid: 'test-jwtid',
      });

      const [, encodedPayload] = token.split('.');
      const decodedPayload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());

      expect(decodedPayload).toHaveProperty('exp');
      expect(decodedPayload).toHaveProperty('nbf');
      expect(decodedPayload).toHaveProperty('iss', 'test-issuer');
      expect(decodedPayload).toHaveProperty('aud', 'test-audience');
      expect(decodedPayload).toHaveProperty('jti', 'test-jwtid');
    });

    it('should throw MissingKeyError when secret is missing', () => {
      expect(() => sign(payload, {} as any)).toThrow(MissingKeyError);
    });

    it('should throw MissingKeyError when secret is too short', () => {
      expect(() => sign(payload, { secret: 'short' })).toThrow(MissingKeyError);
    });

    it('should throw ClaimValidationError for invalid payload', () => {
      expect(() => sign(null as any, { secret })).toThrow(ClaimValidationError);
      expect(() => sign(undefined as any, { secret })).toThrow(ClaimValidationError);
      expect(() => sign('invalid' as any, { secret })).toThrow(ClaimValidationError);
    });

    it('should support custom header fields', () => {
      const token = sign(payload, {
        secret,
        header: {
          kid: 'test-key-id',
          x5u: 'https://example.com/cert.pem',
        },
      });

      const [encodedHeader] = token.split('.');
      const decodedHeader = JSON.parse(Buffer.from(encodedHeader, 'base64').toString());

      expect(decodedHeader).toHaveProperty('kid', 'test-key-id');
      expect(decodedHeader).toHaveProperty('x5u', 'https://example.com/cert.pem');
    });

    it('should handle numeric expiresIn and notBefore values', () => {
      const token = sign(payload, {
        secret,
        expiresIn: 3600, // 1 hour in seconds
        notBefore: 60, // 1 minute in seconds
      });

      const [, encodedPayload] = token.split('.');
      const decodedPayload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());
      const now = Math.floor(Date.now() / 1000);

      expect(decodedPayload.exp).toBeGreaterThan(now);
      expect(decodedPayload.nbf).toBeGreaterThan(now);
    });

    it('should handle array audience', () => {
      const token = sign(payload, {
        secret,
        audience: ['aud1', 'aud2'],
      });

      const [, encodedPayload] = token.split('.');
      const decodedPayload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());

      expect(decodedPayload.aud).toEqual(['aud1', 'aud2']);
    });

    it('should preserve custom payload properties', () => {
      const customPayload = {
        ...payload,
        customField: 'customValue',
        nested: { field: 'value' },
      };

      const token = sign(customPayload, { secret });
      const [, encodedPayload] = token.split('.');
      const decodedPayload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());

      expect(decodedPayload.customField).toBe('customValue');
      expect(decodedPayload.nested).toEqual({ field: 'value' });
    });

    it('should handle empty payload object', () => {
      const token = sign({}, { secret });
      const [, encodedPayload] = token.split('.');
      const decodedPayload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());

      expect(decodedPayload).toHaveProperty('iat');
      expect(Object.keys(decodedPayload)).toHaveLength(1); // Only iat should be present
    });

    it('should handle different time units in expiresIn', () => {
      const token = sign(payload, {
        secret,
        expiresIn: '2h',
        notBefore: '30m',
      });

      const [, encodedPayload] = token.split('.');
      const decodedPayload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());
      const now = Math.floor(Date.now() / 1000);

      // exp should be approximately 2 hours from now
      expect(decodedPayload.exp).toBeGreaterThan(now + 7000); // 2 hours - 200 seconds
      expect(decodedPayload.exp).toBeLessThan(now + 7400); // 2 hours + 200 seconds

      // nbf should be approximately 30 minutes from now
      expect(decodedPayload.nbf).toBeGreaterThan(now + 1700); // 30 minutes - 100 seconds
      expect(decodedPayload.nbf).toBeLessThan(now + 1900); // 30 minutes + 100 seconds
    });
  });

  describe('RS256', () => {
    it('should create a valid JWT token with RS256', () => {
      const token = sign(payload, { privateKey, algorithm: 'RS256' });
      const parts = token.split('.');

      expect(parts).toHaveLength(3);
      expect(parts[0]).toMatch(/^[A-Za-z0-9_-]+$/); // header
      expect(parts[1]).toMatch(/^[A-Za-z0-9_-]+$/); // payload
      expect(parts[2]).toMatch(/^[A-Za-z0-9_-]+$/); // signature

      // Verify header contains RS256
      const [encodedHeader] = parts;
      const decodedHeader = JSON.parse(Buffer.from(encodedHeader, 'base64').toString());
      expect(decodedHeader.alg).toBe('RS256');
    });

    it('should throw MissingKeyError when privateKey is missing', () => {
      expect(() => sign(payload, { algorithm: 'RS256' })).toThrow(MissingKeyError);
    });

    it('should include standard claims when provided', () => {
      const token = sign(payload, {
        privateKey,
        algorithm: 'RS256',
        expiresIn: '1h',
        notBefore: '1m',
        issuer: 'test-issuer',
        audience: 'test-audience',
        jwtid: 'test-jwtid',
      });

      const [, encodedPayload] = token.split('.');
      const decodedPayload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());

      expect(decodedPayload).toHaveProperty('exp');
      expect(decodedPayload).toHaveProperty('nbf');
      expect(decodedPayload).toHaveProperty('iss', 'test-issuer');
      expect(decodedPayload).toHaveProperty('aud', 'test-audience');
      expect(decodedPayload).toHaveProperty('jti', 'test-jwtid');
    });

    it('should support custom header fields', () => {
      const token = sign(payload, {
        privateKey,
        algorithm: 'RS256',
        header: {
          kid: 'test-key-id',
          x5u: 'https://example.com/cert.pem',
        },
      });

      const [encodedHeader] = token.split('.');
      const decodedHeader = JSON.parse(Buffer.from(encodedHeader, 'base64').toString());

      expect(decodedHeader).toHaveProperty('kid', 'test-key-id');
      expect(decodedHeader).toHaveProperty('x5u', 'https://example.com/cert.pem');
    });

    it('should handle array audience', () => {
      const token = sign(payload, {
        privateKey,
        algorithm: 'RS256',
        audience: ['aud1', 'aud2'],
      });

      const [, encodedPayload] = token.split('.');
      const decodedPayload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());

      expect(decodedPayload.aud).toEqual(['aud1', 'aud2']);
    });

    it('should preserve custom payload properties', () => {
      const customPayload = {
        ...payload,
        customField: 'customValue',
        nested: { field: 'value' },
      };

      const token = sign(customPayload, { privateKey, algorithm: 'RS256' });
      const [, encodedPayload] = token.split('.');
      const decodedPayload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());

      expect(decodedPayload.customField).toBe('customValue');
      expect(decodedPayload.nested).toEqual({ field: 'value' });
    });
  });
});

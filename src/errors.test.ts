import {
  TokenError,
  MissingKeyError,
  TokenExpiredError,
  InvalidSignatureError,
  ClaimValidationError,
  MalformedTokenError,
  UtilityError,
  InvalidBase64UrlError,
  InvalidDurationError,
} from './errors';

describe('Error Classes', () => {
  describe('TokenError', () => {
    it('should create with custom message', () => {
      const error = new TokenError('Custom message');
      expect(error.message).toBe('Custom message');
      expect(error.name).toBe('TokenError');
    });
  });

  describe('MissingKeyError', () => {
    it('should create with default message', () => {
      const error = new MissingKeyError();
      expect(error.message).toBe('Missing required key');
      expect(error.name).toBe('MissingKeyError');
    });

    it('should create with custom message', () => {
      const error = new MissingKeyError('Custom key missing');
      expect(error.message).toBe('Custom key missing');
      expect(error.name).toBe('MissingKeyError');
    });
  });

  describe('TokenExpiredError', () => {
    it('should create with default message', () => {
      const error = new TokenExpiredError();
      expect(error.message).toBe('Token has expired');
      expect(error.name).toBe('TokenExpiredError');
    });
  });

  describe('InvalidSignatureError', () => {
    it('should create with default message', () => {
      const error = new InvalidSignatureError();
      expect(error.message).toBe('Invalid signature');
      expect(error.name).toBe('InvalidSignatureError');
    });
  });

  describe('ClaimValidationError', () => {
    it('should create with default message', () => {
      const error = new ClaimValidationError();
      expect(error.message).toBe('Invalid claim');
      expect(error.name).toBe('ClaimValidationError');
    });
  });

  describe('MalformedTokenError', () => {
    it('should create with default message', () => {
      const error = new MalformedTokenError();
      expect(error.message).toBe('Malformed token');
      expect(error.name).toBe('MalformedTokenError');
    });
  });

  describe('UtilityError', () => {
    it('should create with custom message', () => {
      const error = new UtilityError('Custom utility error');
      expect(error.message).toBe('Custom utility error');
      expect(error.name).toBe('UtilityError');
    });
  });

  describe('InvalidBase64UrlError', () => {
    it('should create with default message', () => {
      const error = new InvalidBase64UrlError();
      expect(error.message).toBe('Invalid base64url string');
      expect(error.name).toBe('InvalidBase64UrlError');
    });
  });

  describe('InvalidDurationError', () => {
    it('should create with default message', () => {
      const error = new InvalidDurationError();
      expect(error.message).toBe('Invalid duration format');
      expect(error.name).toBe('InvalidDurationError');
    });
  });
});

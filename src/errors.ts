export class TokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TokenError';
  }
}

export class MissingKeyError extends TokenError {
  constructor(message: string = 'Missing required key') {
    super(message);
    this.name = 'MissingKeyError';
  }
}

export class TokenExpiredError extends TokenError {
  constructor(message: string = 'Token has expired') {
    super(message);
    this.name = 'TokenExpiredError';
  }
}

export class InvalidSignatureError extends TokenError {
  constructor(message: string = 'Invalid signature') {
    super(message);
    this.name = 'InvalidSignatureError';
  }
}

export class ClaimValidationError extends TokenError {
  constructor(message: string = 'Invalid claim') {
    super(message);
    this.name = 'ClaimValidationError';
  }
}

export class MalformedTokenError extends TokenError {
  constructor(message: string = 'Malformed token') {
    super(message);
    this.name = 'MalformedTokenError';
  }
}

export class UtilityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UtilityError';
  }
}

export class InvalidBase64UrlError extends UtilityError {
  constructor(message: string = 'Invalid base64url string') {
    super(message);
    this.name = 'InvalidBase64UrlError';
  }
}

export class InvalidDurationError extends UtilityError {
  constructor(message: string = 'Invalid duration format') {
    super(message);
    this.name = 'InvalidDurationError';
  }
}

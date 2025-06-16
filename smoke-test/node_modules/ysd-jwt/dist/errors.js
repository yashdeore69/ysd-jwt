"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidDurationError = exports.InvalidBase64UrlError = exports.UtilityError = exports.MalformedTokenError = exports.ClaimValidationError = exports.InvalidSignatureError = exports.TokenExpiredError = exports.MissingKeyError = exports.TokenError = void 0;
class TokenError extends Error {
    constructor(message) {
        super(message);
        this.name = 'TokenError';
    }
}
exports.TokenError = TokenError;
class MissingKeyError extends TokenError {
    constructor(message = 'Missing required key') {
        super(message);
        this.name = 'MissingKeyError';
    }
}
exports.MissingKeyError = MissingKeyError;
class TokenExpiredError extends TokenError {
    constructor(message = 'Token has expired') {
        super(message);
        this.name = 'TokenExpiredError';
    }
}
exports.TokenExpiredError = TokenExpiredError;
class InvalidSignatureError extends TokenError {
    constructor(message = 'Invalid signature') {
        super(message);
        this.name = 'InvalidSignatureError';
    }
}
exports.InvalidSignatureError = InvalidSignatureError;
class ClaimValidationError extends TokenError {
    constructor(message = 'Invalid claim') {
        super(message);
        this.name = 'ClaimValidationError';
    }
}
exports.ClaimValidationError = ClaimValidationError;
class MalformedTokenError extends TokenError {
    constructor(message = 'Malformed token') {
        super(message);
        this.name = 'MalformedTokenError';
    }
}
exports.MalformedTokenError = MalformedTokenError;
class UtilityError extends Error {
    constructor(message) {
        super(message);
        this.name = 'UtilityError';
    }
}
exports.UtilityError = UtilityError;
class InvalidBase64UrlError extends UtilityError {
    constructor(message = 'Invalid base64url string') {
        super(message);
        this.name = 'InvalidBase64UrlError';
    }
}
exports.InvalidBase64UrlError = InvalidBase64UrlError;
class InvalidDurationError extends UtilityError {
    constructor(message = 'Invalid duration format') {
        super(message);
        this.name = 'InvalidDurationError';
    }
}
exports.InvalidDurationError = InvalidDurationError;

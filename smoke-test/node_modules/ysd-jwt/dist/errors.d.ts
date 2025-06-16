export declare class TokenError extends Error {
    constructor(message: string);
}
export declare class MissingKeyError extends TokenError {
    constructor(message?: string);
}
export declare class TokenExpiredError extends TokenError {
    constructor(message?: string);
}
export declare class InvalidSignatureError extends TokenError {
    constructor(message?: string);
}
export declare class ClaimValidationError extends TokenError {
    constructor(message?: string);
}
export declare class MalformedTokenError extends TokenError {
    constructor(message?: string);
}
export declare class UtilityError extends Error {
    constructor(message: string);
}
export declare class InvalidBase64UrlError extends UtilityError {
    constructor(message?: string);
}
export declare class InvalidDurationError extends UtilityError {
    constructor(message?: string);
}

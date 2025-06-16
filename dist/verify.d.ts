import { VerifyOptions, JwtPayload } from './types';
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
export declare function verify(token: string, options: VerifyOptions): JwtPayload;

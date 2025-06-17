import { SignOptions, JwtPayload } from './types';
/**
 * Signs a JWT payload with the provided options
 * @param payload - The JWT payload to sign
 * @param options - Signing options including secret key and optional claims
 * @returns The signed JWT token
 * @throws {MissingKeyError} If secret/privateKey is missing or invalid
 * @throws {ClaimValidationError} If payload contains invalid claims
 */
export declare function sign(payload: JwtPayload, options: SignOptions): string;

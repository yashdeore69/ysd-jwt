export interface SignOptions {
    secret?: string;
    privateKey?: string | Buffer;
    expiresIn?: string | number;
    issuer?: string;
    audience?: string | string[];
    notBefore?: string | number;
    jwtid?: string;
    algorithm?: 'HS256' | 'RS256';
    header?: Record<string, any>;
}
export interface VerifyOptions {
    secret?: string;
    publicKey?: string | Buffer;
    issuer?: string;
    audience?: string | string[];
    clockToleranceSec?: number;
    algorithm?: 'HS256' | 'RS256';
}
export interface JwtHeader {
    alg: 'HS256' | 'RS256';
    typ: 'JWT';
    [key: string]: any;
}
export interface JwtPayload {
    iss?: string;
    sub?: string;
    aud?: string | string[];
    exp?: number;
    nbf?: number;
    iat?: number;
    jti?: string;
    [key: string]: any;
}

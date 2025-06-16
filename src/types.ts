export interface SignOptions {
  secret: string;
  expiresIn?: string | number;
  issuer?: string;
  audience?: string | string[];
  notBefore?: string | number;
  algorithm?: 'HS256';
}

export interface VerifyOptions {
  secret: string;
  issuer?: string;
  audience?: string | string[];
  clockToleranceSec?: number;
  algorithm?: 'HS256';
}

export interface JwtHeader {
  alg: 'HS256';
  typ: 'JWT';
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
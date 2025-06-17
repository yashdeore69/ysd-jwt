import { Request, RequestHandler } from 'express';
export interface JwtMiddlewareOptions {
    secret?: string;
    publicKey?: string | Buffer;
    algorithm?: 'HS256' | 'RS256';
    issuer?: string;
    audience?: string | string[];
    clockToleranceSec?: number;
    getToken?: (req: Request) => string | null;
}
/**
 * Express middleware to verify JWT and attach payload to req.user
 * @param opts - Middleware options
 * @returns Express RequestHandler
 */
export declare function jwtMiddleware(opts: JwtMiddlewareOptions): RequestHandler;

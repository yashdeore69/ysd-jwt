import { Request, Response, NextFunction, RequestHandler } from 'express';
import { verify } from './verify';

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
export function jwtMiddleware(opts: JwtMiddlewareOptions): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      // Default token extractor: Authorization header
      const token = opts.getToken
        ? opts.getToken(req)
        : (() => {
            const auth = req.headers.authorization;
            if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
            return null;
          })();
      if (!token) {
        res.status(401).json({ error: 'No token provided' });
        return;
      }
      const payload = verify(token, {
        secret: opts.secret,
        publicKey: opts.publicKey,
        algorithm: opts.algorithm,
        issuer: opts.issuer,
        audience: opts.audience,
        clockToleranceSec: opts.clockToleranceSec,
      });
      // Attach to req.user
      (req as any).user = payload;
      next();
    } catch (err: any) {
      // Do not leak sensitive error details
      const msg = err && err.message ? err.message : 'Invalid token';
      res.status(401).json({ error: msg });
      return;
    }
  };
}

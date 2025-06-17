"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.jwtMiddleware = jwtMiddleware;
const verify_1 = require("./verify");
/**
 * Express middleware to verify JWT and attach payload to req.user
 * @param opts - Middleware options
 * @returns Express RequestHandler
 */
function jwtMiddleware(opts) {
    return (req, res, next) => {
        try {
            // Default token extractor: Authorization header
            const token = opts.getToken
                ? opts.getToken(req)
                : (() => {
                    const auth = req.headers.authorization;
                    if (auth && auth.startsWith('Bearer '))
                        return auth.slice(7);
                    return null;
                })();
            if (!token) {
                res.status(401).json({ error: 'No token provided' });
                return;
            }
            const payload = (0, verify_1.verify)(token, {
                secret: opts.secret,
                publicKey: opts.publicKey,
                algorithm: opts.algorithm,
                issuer: opts.issuer,
                audience: opts.audience,
                clockToleranceSec: opts.clockToleranceSec,
            });
            // Attach to req.user
            req.user = payload;
            next();
        }
        catch (err) {
            // Do not leak sensitive error details
            const msg = err && err.message ? err.message : 'Invalid token';
            res.status(401).json({ error: msg });
            return;
        }
    };
}

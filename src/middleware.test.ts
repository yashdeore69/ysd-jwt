import express from 'express';
import request from 'supertest';
import { jwtMiddleware } from './middleware';
import { sign } from './sign';
import { generateKeyPairSync } from 'crypto';

describe('jwtMiddleware', () => {
  const secret = 'your-256-bit-secret-your-256-bit-secret';
  const payload = { sub: '1234567890', name: 'John Doe' };

  // Generate RSA key pair for RS256 tests
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  function createApp(middleware: any) {
    const app = express();
    app.use(middleware);
    app.get('/protected', (req, res) => {
      res.json({ user: (req as any).user });
    });
    return app;
  }

  it('should allow access with valid HS256 token', async () => {
    const token = sign(payload, { secret });
    const app = createApp(jwtMiddleware({ secret }));
    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject(payload);
  });

  it('should allow access with valid RS256 token', async () => {
    const token = sign(payload, { privateKey, algorithm: 'RS256' });
    const app = createApp(jwtMiddleware({ publicKey, algorithm: 'RS256' }));
    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject(payload);
  });

  it('should deny access with missing token', async () => {
    const app = createApp(jwtMiddleware({ secret }));
    const res = await request(app).get('/protected');
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/No token provided/);
  });

  it('should deny access with invalid token', async () => {
    const app = createApp(jwtMiddleware({ secret }));
    const res = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer invalid.token.here');
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/Invalid token|Malformed/);
  });

  it('should deny access with expired token', async () => {
    const expiredPayload = { ...payload, exp: Math.floor(Date.now() / 1000) - 10 };
    const token = sign(expiredPayload, { secret });
    const app = createApp(jwtMiddleware({ secret }));
    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/expired/i);
  });

  it('should deny access with wrong secret', async () => {
    const token = sign(payload, { secret });
    const app = createApp(jwtMiddleware({ secret: 'wrong-secret' }));
    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/Invalid signature/);
  });

  it('should allow custom token extractor', async () => {
    const token = sign(payload, { secret });
    const app = createApp(
      jwtMiddleware({
        secret,
        getToken: (req) => req.query.token as string || null,
      })
    );
    const res = await request(app).get('/protected?token=' + token);
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject(payload);
  });
}); 
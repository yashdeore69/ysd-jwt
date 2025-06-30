# ysd-jwt

A beginner-friendly, secure-by-default JWT library for Node.js, supporting both HS256 and RS256 algorithms.

## Installation

```bash
npm install ysd-jwt
```

## Quick Start: HS256

```ts
import { sign, verify } from 'ysd-jwt';

// For HS256, use a secret that is at least 32 characters long.
// It's best practice to load this from environment variables.
const secret = 'your-super-secret-key-that-is-at-least-32-characters-long';

// Create a token
const token = sign({ sub: 'user123' }, {
  secret,
  expiresIn: '1h', // e.g., '1h', '30m', '1d'
  issuer: 'my-app',
  audience: 'my-app-users',
});

console.log('Generated Token:', token);

// Verify a token
try {
  const payload = verify(token, {
    secret,
    issuer: 'my-app',
    audience: 'my-app-users',
  });
  console.log('Verified Payload:', payload);
} catch (err) {
  console.error('Token verification failed:', err.message);
}
```

## RS256 Usage

For RS256, you need an RSA key pair. The private key is used to sign the token, and the public key is used to verify it.

### Key Generation

You can generate a 2048-bit RSA key pair using OpenSSL:

```bash
# Generate a private key
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

# Extract the public key from the private key
openssl rsa -pubout -in private.pem -out public.pem
```

### Example

```ts
import { sign, verify } from 'ysd-jwt';
import fs from 'fs';

// Load the keys from files
const privateKey = fs.readFileSync('./private.pem');
const publicKey = fs.readFileSync('./public.pem');

// Sign a token with the private key
const token = sign({ sub: 'user456' }, {
  privateKey,
  algorithm: 'RS256',
  expiresIn: '2h',
  issuer: 'my-app',
  audience: 'my-app-users',
});

// Verify the token with the public key
try {
  const payload = verify(token, {
    publicKey,
    algorithm: 'RS256',
    issuer: 'my-app',
    audience: 'my-app-users',
  });
  console.log('RS256 Verified Payload:', payload);
} catch (err) {
  console.error('Token verification failed:', err.message);
}
```

**Note:** The `privateKey` and `publicKey` must be valid PEM-formatted strings or Buffers. The library will throw an error if the format is incorrect.

## Express Middleware

`ysd-jwt` includes middleware to protect your Express routes.

```ts
import express from 'express';
import { jwtMiddleware } from 'ysd-jwt';

const app = express();
const secret = 'your-super-secret-key-that-is-at-least-32-characters-long';

// Add the middleware to all routes you want to protect
app.use('/protected-routes', jwtMiddleware({ secret, issuer: 'my-app' }));

app.get('/protected-routes/data', (req, res) => {
  // If the token is valid, `req.user` will be populated with the token's payload
  res.json({
    message: 'Welcome!',
    user: req.user
  });
});

app.listen(3000, () => console.log('Server started'));
```

## Examples

For a complete, runnable example, see the Express application in the [`/examples/express-app`](./examples/express-app) directory.

## API Reference

### `sign(payload, options)`

Signs a JWT token.

- **payload**: The payload to sign.
- **options**:
  - **algorithm**: The signing algorithm to use (`'HS256'` or `'RS256'`, default: `'HS256'`).
  - **secret**: The secret key for HS256 signing (required for HS256).
  - **privateKey**: The private key for RS256 signing (required for RS256).
  - **expiresIn**: Token expiration time (default: `'1h'`).
  - **issuer**: Token issuer.
  - **audience**: Token audience.
  - **notBefore**: Token not-before time.
  - **jwtid**: Token ID.
  - **header**: Additional header fields.

### `verify(token, options)`

Verifies a JWT token.

- **token**: The token to verify.
- **options**:
  - **algorithm**: The verification algorithm to use (`'HS256'` or `'RS256'`, default: `'HS256'`).
  - **secret**: The secret key for HS256 verification (required for HS256).
  - **publicKey**: The public key for RS256 verification (required for RS256).
  - **issuer**: Expected token issuer.
  - **audience**: Expected token audience.
  - **clockToleranceSec**: Clock tolerance in seconds (default: `5`).

## Security Notes

- For HS256: Use a strong secret (≥32 characters) for signing.
- For RS256: Keep private keys secure and never commit them to version control.
- Set short expiration times for tokens.
- Validate claims (`exp`, `iat`, `nbf`, `iss`, `aud`).
- Disallow insecure algorithms (e.g., `alg: none`).
- Always use HTTPS for token transmission.
- Do not store sensitive data in the payload.

## Limitations

- Only HS256 is supported in v0.1.0. RS256, middleware, refresh tokens, revocation, JWKS, and CLI support are planned for v0.2+.

## Examples

### Generating RSA Keys

```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Generate public key
openssl rsa -in private.pem -pubout -out public.pem
```

More examples will be added in the `/examples` folder.

## Contributing

Issues and pull requests are welcome. Please refer to the CONTRIBUTING.md file for guidelines.

## CHANGELOG

See [CHANGELOG.md](CHANGELOG.md) for details on changes for each release.

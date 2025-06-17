# ysd-jwt

A beginner-friendly, secure-by-default JWT library for Node.js, supporting both HS256 and RS256 algorithms.

## Installation

```bash
npm install ysd-jwt
```

## Quick Start

### HS256 (Symmetric)

```javascript
const { sign, verify } = require('ysd-jwt');

const payload = { sub: '1234567890', name: 'John Doe' };
const secret = 'your-256-bit-secret-your-256-bit-secret';

// Sign a token
const token = sign(payload, { secret });

// Verify a token
try {
  const decoded = verify(token, { secret });
  console.log(decoded); // { sub: '1234567890', name: 'John Doe' }
} catch (error) {
  console.error('Token verification failed:', error.message);
}
```

### RS256 (Asymmetric)

```javascript
const { sign, verify } = require('ysd-jwt');
const fs = require('fs');

const payload = { sub: '1234567890', name: 'John Doe' };

// Load RSA keys
const privateKey = fs.readFileSync('private.pem');
const publicKey = fs.readFileSync('public.pem');

// Sign a token
const token = sign(payload, { privateKey, algorithm: 'RS256' });

// Verify a token
try {
  const decoded = verify(token, { publicKey, algorithm: 'RS256' });
  console.log(decoded); // { sub: '1234567890', name: 'John Doe' }
} catch (error) {
  console.error('Token verification failed:', error.message);
}
```

## Express Middleware

You can use the provided Express middleware to easily verify JWTs in your Express application.

### Basic Usage

```javascript
const express = require('express');
const { jwtMiddleware } = require('ysd-jwt');

const app = express();

// Apply middleware globally
app.use(jwtMiddleware({ secret: 'your-256-bit-secret-your-256-bit-secret' }));

// Or apply to specific routes
app.get('/protected', jwtMiddleware({ secret: 'your-256-bit-secret-your-256-bit-secret' }), (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

### Using RS256

```javascript
const express = require('express');
const fs = require('fs');
const { jwtMiddleware } = require('ysd-jwt');

const app = express();

// Load public key for RS256 verification
const publicKey = fs.readFileSync('public.pem');

// Apply middleware with RS256
app.use(jwtMiddleware({ publicKey, algorithm: 'RS256' }));

app.get('/protected', (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

### Custom Token Extraction

You can provide a custom function to extract the token from the request:

```javascript
const express = require('express');
const { jwtMiddleware } = require('ysd-jwt');

const app = express();

app.use(jwtMiddleware({
  secret: 'your-256-bit-secret-your-256-bit-secret',
  getToken: (req) => req.query.token || null,
}));

app.get('/protected', (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

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

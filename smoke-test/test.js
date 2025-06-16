const { sign, verify } = require('ysd-jwt');

const secret = 'your-secret-key-at-least-32-chars-long';
const payload = { sub: 'user123', iat: Math.floor(Date.now() / 1000) };

// Sign a token
const token = sign(payload, { secret, expiresIn: '1h' });
console.log('Signed token:', token);

// Verify the token
try {
  const decoded = verify(token, { secret });
  console.log('Verified payload:', decoded);
} catch (err) {
  console.error('Verification failed:', err.message);
} 
// Import necessary modules
const express = require('express');
const { sign, jwtMiddleware } = require('ysd-jwt');

// Create an Express application
const app = express();
app.use(express.json()); // Middleware to parse JSON bodies

// --- Configuration ---
// In a real application, use environment variables for secrets.
const JWT_SECRET = 'your-super-secret-key-that-is-at-least-32-characters-long';
if (JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters long.');
}

// --- Public Routes ---

/**
 * @route   POST /login
 * @desc    Logs a user in by issuing a JWT.
 * @access  Public
 */
app.post('/login', (req, res) => {
  // In a real app, you would validate user credentials against a database.
  const { username, password } = req.body;
  if (username === 'user' && password === 'pass') {
    const payload = { sub: 'user123', username: 'user' };
    const token = sign(payload, {
      secret: JWT_SECRET,
      expiresIn: '1h', // Token expires in 1 hour
      issuer: 'my-api',
      audience: 'my-app',
    });
    res.json({ message: 'Login successful!', token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// --- Middleware ---

// This middleware will protect the routes below it.
const protectedRouteMiddleware = jwtMiddleware({
  secret: JWT_SECRET,
  issuer: 'my-api',
  audience: 'my-app',
});

// --- Protected Routes ---

/**
 * @route   GET /protected
 * @desc    An example protected route.
 * @access  Private
 */
app.get('/protected', protectedRouteMiddleware, (req, res) => {
  // The user payload is attached to req.user by the middleware.
  res.json({
    message: 'You have accessed a protected route!',
    user: req.user,
  });
});

// --- Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Example app listening at http://localhost:${PORT}`);
  console.log('---');
  console.log('Try the following routes:');
  console.log('POST /login with JSON body {"username": "user", "password": "pass"} to get a token.');
  console.log('GET /protected with "Authorization: Bearer <your-token>" to access protected data.');
}); 
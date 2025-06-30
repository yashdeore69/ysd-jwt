# ysd-jwt Express Example

This example demonstrates how to use `ysd-jwt` to secure an Express application.

## 1. Installation

Navigate to this directory and install the dependencies:

```bash
cd examples/express-app
npm install
```

This will install `express` and create a local link to the `ysd-jwt` package from the parent directory.

## 2. Running the Server

Start the Express server:

```bash
npm start
```

The server will be running at `http://localhost:3000`.

## 3. How to Use

You can use a tool like `curl` or Postman to interact with the API.

### Login

To get a token, send a POST request to `/login` with the hardcoded credentials.

```bash
curl -X POST http://localhost:3000/login \
-H "Content-Type: application/json" \
-d '{"username": "user", "password": "pass"}'
```

The response will contain a JWT:

```json
{
  "message": "Login successful!",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Accessing a Protected Route

To access the `/protected` route, include the token in the `Authorization` header as a Bearer token.

Replace `<your-token>` with the token you received from the login step.

```bash
curl http://localhost:3000/protected \
-H "Authorization: Bearer <your-token>"
```

If the token is valid, you will get a successful response:

```json
{
  "message": "You have accessed a protected route!",
  "user": {
    "sub": "user123",
    "username": "user",
    "iat": 1678886400,
    "exp": 1678890000,
    "iss": "my-api",
    "aud": "my-app"
  }
}
```

If the token is missing, invalid, or expired, you will receive a `401 Unauthorized` error. 
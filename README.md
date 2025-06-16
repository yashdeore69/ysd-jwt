Beginner-friendly, secure-by-default JWT library for Node.js

for detailed documentation: https://www.notion.so/ysd-jwt-1ef5e9eb7b0f804cbe7cc722e5374e5f?source=copy_link

# ysd-jwt
**Work in Progress (v0.1.0)**

A beginner-friendly, secure-by-default JWT library for Node.js.  
**Planned features**:
- HS256 sign/verify with secure defaults (v0.1.0)
- Claim validation (`exp`, `iat`, `nbf`, `iss`, `aud`)
- TypeScript types
- RS256 support, Express middleware, refresh tokens, revocation hooks, JWKS, etc. in subsequent versions.

## Day 1-Sprint 1 Progress
- Initialized the project with:
  - TypeScript
  - ESLint (Airbnb + Prettier)
  - Jest (unit testing setup)
- Created initial module structure under `src/`
├── src/
│   ├── index.ts          # Main export
│   ├── sign.ts           # Token creation (HS256)
│   ├── verify.ts         # Token verification
│   ├── middleware.ts     # Express middleware (Week 2)
│   ├── types.ts          # TypeScript interfaces and types
│   ├── errors.ts         # Custom error classes
│   └── utils.ts          # Base64URL, duration parser, etc.
- Defined roadmap for core functionality and modular design
- Next task: implement core HS256 token signing in `src/sign.ts`

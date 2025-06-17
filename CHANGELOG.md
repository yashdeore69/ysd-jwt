# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2024-03-20

### Added
- RS256 support for asymmetric signing and verification
- RSA key pair generation instructions in README
- Comprehensive tests for RS256 functionality
- Updated documentation with RS256 examples and API reference

## [0.1.0] - 2024-03-19

### Added
- HS256 sign and verify with secure defaults
- Claim validation (`exp`, `iat`, `nbf`, optional `iss`, `aud`)
- TypeScript types
- Custom error classes with clear messages including ISO timestamps
- Base64Url utilities, simple duration parsing
- Jest tests covering edge cases 
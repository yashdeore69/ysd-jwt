# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Added
- RS256 sign/verify support with key format validation.
- Express middleware for JWT extraction and verification.
- Example Express app in `/examples`.
- Expanded tests, including for clock skew, unicode payloads, and algorithm confusion attacks.
- Key validation helpers to ensure correct PEM formatting.

### Changed
- Improved error messages for several validation scenarios.

## [0.1.0] - 2024-05-23

### Added
- Initial release with HS256 support.
- `sign` and `verify` functions.
- Custom error classes.
- Basic claim validation. 
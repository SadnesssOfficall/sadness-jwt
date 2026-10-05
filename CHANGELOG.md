# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-05

### Added

- `decode`, `inspect` and `verify` commands
- Library API: `decode`, `inspect`, `verify`
- HS256 and RS256 signature verification with `node:crypto` and no runtime dependencies
- Explicit algorithm allow-list; `none` is always rejected
- Algorithm confusion protection: PEM/DER public keys are refused as HMAC secrets
- Validation of `exp`, `nbf`, `iat`, `iss`, `aud`, maximum age and clock tolerance
- Strict base64url and JSON parsing with duplicate key rejection and a token size limit
- Keys are read from an environment variable, a file or stdin, never from arguments

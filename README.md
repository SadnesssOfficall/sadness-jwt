# sadness-jwt

Decode, inspect and safely verify JSON Web Tokens from the command line or from code.

`sadness-jwt` verifies HS256 and RS256 tokens using only `node:crypto`. The verifier never trusts
the token to choose its own algorithm or key, so the classic JWT attacks do not apply. It has no
runtime dependencies.

## Features

- `decode`, `inspect` and `verify`, as a CLI and as a library
- HS256 and RS256 signature verification, timing-safe for HMAC
- Explicit algorithm allow-list; `alg: none` is always rejected
- Algorithm confusion protection: a PEM or DER public key is refused as an HMAC secret
- Claim checks: `exp`, `nbf`, `iat`, `iss`, `aud`, maximum token age, clock tolerance
- Strict base64url, strict JSON (duplicate keys rejected), token size limit
- `kid`, `jku`, `x5u`, `jwk` and `x5c` are never followed; `crit` is rejected
- Keys come from an environment variable, a file or stdin, never from arguments
- Stable exit codes and `--json` output

## Installation

Requires Node.js 20 or newer.

```sh
npm install sadness-jwt
npx sadness-jwt --help
```

Global install:

```sh
npm install --global sadness-jwt
```

## Usage

```text
sadness-jwt decode  <token | -> [--json]
sadness-jwt inspect <token | -> [--json]
sadness-jwt verify  <token | -> --alg <HS256|RS256>... (--secret-env <NAME> | --key-file <path> | --secret-stdin)
                    [--issuer <iss>]... [--audience <aud>]... [--kid <id>]
                    [--tolerance <seconds>] [--max-age <seconds>] [--allow-no-exp] [--json]
```

Pass `-` instead of the token to read it from standard input.

### decode

Prints the header and payload. Nothing is verified, so never make a trust decision from this output.

### inspect

Decodes and summarises the algorithm, signature size, issuer, subject, audience, key id, timing
relative to now, and warnings (unsigned token, empty signature, `jku`/`x5u`/`jwk`/`x5c`/`crit`
headers, missing `exp`). The signature is not verified.

### verify

Checks the signature using an explicit algorithm list, then the claims. `exp` is required unless
`--allow-no-exp` is given.

| Option                   | Meaning                                                               |
| ------------------------ | --------------------------------------------------------------------- |
| `--alg`                  | Allowed algorithm (`HS256` or `RS256`). Required, repeatable          |
| `--secret-env NAME`      | Read the HMAC secret or PEM public key from environment variable      |
| `--key-file PATH`        | Read the key from a file (max 64 KiB)                                 |
| `--secret-stdin`         | Read the key from standard input                                      |
| `--issuer`, `--audience` | Accepted values. Repeatable; the claim must match one of them         |
| `--kid`                  | Require this exact `kid` header. It is compared, never looked up      |
| `--tolerance`            | Clock tolerance in seconds, 0 to 3600                                 |
| `--max-age`              | Maximum token age in seconds, measured from `iat` (which is required) |
| `--allow-no-exp`         | Do not require an `exp` claim                                         |
| `--json`                 | Machine-readable output                                               |

Exactly one key source is required. A single trailing line break is removed from files and stdin.

### Exit codes

| Code | Meaning                                                       |
| ---- | ------------------------------------------------------------- |
| 0    | Success; for `verify` the token is valid                      |
| 1    | Token is malformed or rejected                                |
| 2    | Usage, key or file error (including a weak or mismatched key) |

## Configuration

The library takes options per call; there are no configuration files.

| Option                  | Applies to          | Default | Meaning                                               |
| ----------------------- | ------------------- | ------- | ----------------------------------------------------- |
| `algorithms`            | `verify`            | none    | Required, non-empty allow-list of `HS256` / `RS256`   |
| `key`                   | `verify`            | none    | `string`, `Uint8Array` or `KeyObject`                 |
| `issuer`, `audience`    | `verify`            | unset   | String or list of accepted values                     |
| `keyId`                 | `verify`            | unset   | Required exact `kid` header                           |
| `clockToleranceSeconds` | `verify`, `inspect` | `0`     | Allowed clock skew, at most 3600                      |
| `maxAgeSeconds`         | `verify`            | unset   | Maximum age from `iat`                                |
| `requireExpiration`     | `verify`            | `true`  | Reject tokens without `exp`                           |
| `now`                   | all                 | current | `Date` used as the current time                       |
| `maxTokenLength`        | all                 | `8192`  | Maximum token length in characters, at most 1,048,576 |

## Examples

Verify from the command line, with the secret in an environment variable:

```sh
export JWT_SECRET='example-secret-that-is-at-least-32-bytes'
TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJhdWQiOiJvcmRlcnMtYXBpIiwic3ViIjoidXNlci00MiIsImlhdCI6MTc2NzIyNTYwMCwiZXhwIjo0MTAyNDQ0ODAwfQ.3Wb2bgSj_7N2tAyzihpkV0UyKNAJNacVlDGzH0Hwtio'
sadness-jwt verify "$TOKEN" --alg HS256 --secret-env JWT_SECRET \
  --issuer https://auth.example.com --audience orders-api
```

Verify RS256 with a public key file and read the token from stdin:

```sh
echo "$TOKEN" | sadness-jwt verify - --alg RS256 --key-file public.pem --json
```

Library:

```ts
import { decode, inspect, verify, JwtError } from 'sadness-jwt';

try {
  const { payload } = verify(token, {
    algorithms: ['RS256'],
    key: publicKeyPem,
    issuer: 'https://auth.example.com',
    audience: 'orders-api',
    clockToleranceSeconds: 30,
  });
  console.log(payload['sub']);
} catch (error) {
  if (error instanceof JwtError) console.error(error.code);
}

const { header, payload } = decode(token);
const report = inspect(token);
```

`verify` throws `JwtError` with a stable `code` such as `invalid_signature`, `token_expired`,
`algorithm_none`, `algorithm_not_allowed`, `audience_mismatch` or `key_mismatch`. Error messages never
contain the key, the token or claim values.

## Architecture

```text
src/
  base64url.ts   strict base64url decoding
  json.ts        strict JSON object parsing, duplicate key detection
  token.ts       token splitting and decode
  algorithms.ts  supported algorithms
  keys.ts        key type checks and algorithm confusion guard
  signature.ts   HMAC (timing-safe) and RSA verification
  claims.ts      exp, nbf, iat, iss, aud checks
  verify.ts      verification pipeline
  inspect.ts     unverified summary and warnings
  cli/           argument handling and output formatting
```

## Security

- **The token never picks the algorithm.** `verify` requires an explicit `algorithms` allow-list. The
  header `alg` must be in that list, and the key must fit the algorithm.
- **`none` is always rejected**, in any case or padding, and cannot be added to the allow-list.
- **Algorithm confusion.** HS256 refuses keys that look like PEM or DER public keys and asymmetric
  `KeyObject`s, so an attacker cannot sign with a public key as an HMAC secret. RS256 refuses shared
  secrets and non-RSA keys.
- **Key strength.** HMAC secrets under 32 bytes and RSA keys under 2048 bits are refused.
- **Timing-safe comparison** for HMAC signatures, with a length check first.
- **Strict parsing.** Base64url must be canonical (no padding, no standard alphabet, no whitespace).
  Header and payload must be UTF-8 JSON objects without duplicate keys. Tokens over 8192 characters
  are refused before any decoding, and `__proto__` is handled as plain data.
- **Headers are not followed.** `jku`, `x5u`, `jwk` and `x5c` are ignored. `kid` is only compared to an
  expected value you provide. Tokens with `crit` are rejected.
- **Signature before claims.** Claims are examined only after the signature is valid. `exp` is
  required by default, `nbf`/`iat` are checked, and `iss`/`aud` use exact string matching.
- **Secrets are never printed.** Keys are not accepted as command line arguments, because arguments
  appear in shell history and in the process list for every user on the machine. Use
  `--secret-env`, `--key-file` or `--secret-stdin` instead. Error messages and CLI output never
  contain key material.
- `decode` and `inspect` do not verify anything. Do not authorise requests based on them.
- Out of scope: JWE, JWS JSON serialization, `ES*`/`PS*`/`EdDSA` algorithms, key discovery and
  revocation.

## Development

```sh
git clone https://github.com/SadnesssOfficall/sadness-jwt.git
cd sadness-jwt
npm install
npm run build
```

| Script                 | Purpose             |
| ---------------------- | ------------------- |
| `npm run build`        | Compile to `dist/`  |
| `npm run lint`         | ESLint (type-aware) |
| `npm run format:check` | Prettier            |
| `npm run typecheck`    | `tsc --noEmit`      |

## Testing

```sh
npm test
```

Tests cover decoding and strict parsing, HS256 and RS256 verification, every claim check, the CLI end
to end including exit codes, and attack scenarios: `alg: none`, HS256 with a public key, truncated,
extended, flipped and empty signatures, oversized tokens, malformed base64url, expired and
not-yet-valid tokens, issuer and audience mismatch, embedded `jwk`/`jku`/`x5u` keys and secret
leakage in errors. No external services are needed.

## License

[MIT](LICENSE)

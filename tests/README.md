# Test Scripts

Test scripts for the PasskeyAuthenticator against a Relying Party (RP).

## Available Test Scripts

### 1. Full Registration and Authentication Tests

These tests perform complete passkey flows including registration (attestation) and authentication (assertion):

#### `attestation-assertion-test-ec.ts` (Elliptic Curve - ES256)
Forces the use of elliptic curve cryptography (ES256, algorithm -7).

```bash
npx ts-node tests/attestation-assertion-test-ec.ts [rp_uuid [username [password]]]
```

**Output files:**
- `virtual.passkey.ec.pem` - EC private key
- `virtual.passkey.ec.credid` - Credential ID

#### `attestation-assertion-test-rsa.ts` (RSA - RS256)
Forces the use of RSA cryptography (RS256, algorithm -257).

```bash
npx ts-node tests/attestation-assertion-test-rsa.ts [rp_uuid [username [password]]]
```

**Output files:**
- `virtual.passkey.rsa.pem` - RSA private key
- `virtual.passkey.rsa.credid` - Credential ID

### 2. Authentication-Only Test

#### `assertion-test.ts` (Authentication with Existing Credential)
Performs authentication using a previously registered credential from a PKCS8 key file.

```bash
npx ts-node tests/assertion-test.ts [rp_uuid [key_type [username [password]]]]
```

**Parameters:**
- `rp_uuid`: Relying party UUID (default: `aa583468-4702-4f0e-803f-d813418a2cd3`)
- `key_type`: Type of key to use - `ec` or `rsa` (default: `ec`)
  - `ec` - Uses `virtual.passkey.ec.pem` and `virtual.passkey.ec.credid`
  - `rsa` - Uses `virtual.passkey.rsa.pem` and `virtual.passkey.rsa.credid`
- `username`: Test username (default: `testuser`)
- `password`: User password (default: `passw0rd`)

**Examples:**
```bash
# Use EC key (default)
npx ts-node tests/assertion-test.ts

# Use RSA key
npx ts-node tests/assertion-test.ts aa583468-4702-4f0e-803f-d813418a2cd3 rsa

# Use RSA key with custom username
npx ts-node tests/assertion-test.ts aa583468-4702-4f0e-803f-d813418a2cd3 rsa myuser mypassword
```

## Common Parameters

All test scripts accept these parameters:

- `RP_URL`: Your RP base URL; hard-coded in each `.ts` file, must be updated if different
- `RP_UUID`: ID of relying party endpoint in Verify Identity Access
- `USERNAME`: Test username to register authenticator for; user must already exist in user registry
- `PASSWORD`: Secret to use when authenticating as `USERNAME`

## Building the Project

First, build the project:

```bash
npm run build
```

Alternatively, compile and run manually:

```bash
npx tsc tests/attestation-assertion-test.ts --outDir tests/dist --module commonjs --target es2020 --esModuleInterop
node tests/dist/attestation-assertion-test.js
```

## Notes

- TLS verification is disabled for testing purposes
- The scripts use the built TypeScript source directly from `../src/`
- Make sure to build the project first if you've made changes: `npm run build`
- The AuthSvc password policy/mechanism must be enabled and configured to establish a session as the given user
- Each test variant creates its own key files with appropriate suffixes (`.ec` or `.rsa`) to avoid conflicts

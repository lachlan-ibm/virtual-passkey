# Test Scripts

Simple test script for the PasskeyAuthenticator against a RP.

## Running the Tests

First, build the project:

```bash
npm run build
```

Then compile and run the test:

```bash
npx tsc tests/attestation-assertion-test.ts --outDir tests/dist --module commonjs --target es2020 --esModuleInterop
node tests/dist/attestation-assertion-test.js
```

Or use the simpler approach with ts-node:

```bash
npx ts-node tests/attestation-assertion-test.ts
```

### Usage:

`tests/attestation-assertion-test.ts [rp_uuid [username [password]]]`

- `RP_URL`: Your RP base URL; hard-coded, must be updated in `.ts` file
- `RP_UUID`: Id of relying party endpoint in Verify Identity Access
- `USERNAME`: Test username to register authenticator for; user must laready exist in user registry
- `PASSWORD`: Secret to use when authenticating as `USERNAME`

## Notes

- TLS verification is disabled for testing purposes
- The scripts use the built TypeScript source directly from `../src/`
- Make sure to build the project first if you've made changes: `npm run build`
- The AuthSvc password policy/mechanism must be enabled and configured to establish a session as the given user.

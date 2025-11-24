# Passkey Authenticator

A WebAuthn/Fido2/Passkey authenticator implementation for Node.js that simulates a hardware security key or platform authenticator.

## Overview

This module implements the authenticator side of the WebAuthn specification. It generates attestation responses during registration and assertion responses during authentication, similar to how a hardware security key (like YubiKey) or platform authenticator (like Touch ID) would work.

**Note:** This is NOT a relying party implementation. If you need to verify WebAuthn responses on the server side, use libraries like `@simplewebauthn/server` instead.

## Installation

```bash
npm install passkey-authenticator
```

## Usage

### Basic Setup

```typescript
import { PasskeyAuthenticator } from 'passkey-authenticator';

// Create a new authenticator instance
const authenticator = new PasskeyAuthenticator();

// Optionally provide a custom AAGUID (Authenticator Attestation GUID)
const customAAGUID = new Uint8Array(16); // 16 bytes
const authenticatorWithAAGUID = new PasskeyAuthenticator(customAAGUID);
```

### Registration (Credential Creation)

When a user wants to register a new credential, the relying party sends credential creation options. The authenticator processes these options and returns an attestation response.

```typescript
// Options received from the relying party (from navigator.credentials.create)
const creationOptions = {
  challenge: "random-challenge-from-server",
  rp: {
    name: "Example Corp",
    id: "example.com"
  },
  user: {
    id: "user-123",
    name: "john.doe@example.com",
    displayName: "John Doe"
  },
  pubKeyCredParams: [
    { alg: -7, type: "public-key" },  // ES256
    { alg: -257, type: "public-key" } // RS256
  ],
  timeout: 60000,
  attestation: "none",
  authenticatorSelection: {
    authenticatorAttachment: "platform",
    requireResidentKey: false,
    userVerification: "preferred"
  }
};

// Generate attestation response
const attestationResponse = await authenticator.credentialCreate(creationOptions);

// Send attestationResponse back to the relying party for verification
// The response includes:
// - id: credential ID
// - rawId: credential ID as base64url
// - response.clientDataJSON: client data
// - response.attestationObject: attestation data
// - type: "public-key"
```

### Authentication (Credential Get)

When a user wants to authenticate, the relying party sends credential request options. The authenticator processes these options and returns an assertion response.

```typescript
// Options received from the relying party (from navigator.credentials.get)
const requestOptions = {
  challenge: "random-challenge-from-server",
  rpId: "example.com",
  allowCredentials: [
    {
      id: "credential-id-from-registration",
      type: "public-key",
      transports: ["internal"]
    }
  ],
  timeout: 60000,
  userVerification: "preferred"
};

// Generate assertion response
const assertionResponse = await authenticator.credentialGet(requestOptions);

// Send assertionResponse back to the relying party for verification
// The response includes:
// - id: credential ID
// - rawId: credential ID as base64url
// - response.clientDataJSON: client data
// - response.authenticatorData: authenticator data
// - response.signature: signature over clientDataJSON and authenticatorData
// - response.userHandle: user handle (if available)
// - type: "public-key"
```

### Using PKCS8 Private Key Files

You can use existing PKCS8 private key files (PEM format) for credential creation and authentication. This is useful for testing with pre-generated keys or for scenarios where you need to use specific keys.

**Note:** The PKCS8 file must not be password-protected.

```typescript
// Create credential using an existing PKCS8 key file
const attestationResponse = await authenticator.credentialCreate(
  creationOptions,
  '/path/to/private-key.pem'
);

// Authenticate using a specific PKCS8 key file
// (overrides the stored credential's key)
const assertionResponse = await authenticator.credentialGet(
  requestOptions,
  '/path/to/private-key.pem'
);

// Export a credential's private key to a PKCS8 file
const exported = authenticator.exportCredentialKey(
  'credential-id',
  '/path/to/exported-key.pem'
);
if (exported) {
  console.log('Key exported successfully');
}
```

**Supported Key Types:**
- **ES256 (ECDSA with P-256)**: Elliptic curve keys using the prime256v1 curve
- **RS256 (RSA with SHA-256)**: RSA keys with 2048-bit modulus

**Generating PKCS8 Keys with OpenSSL:**

```bash
# Generate ES256 (P-256) key
openssl ecparam -name prime256v1 -genkey -noout -out es256-private-key.pem

# Generate RS256 (RSA 2048) key
openssl genrsa -out rsa-private-key.pem 2048
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rsa-private-key.pem -out rs256-private-key.pem
```

### Managing Credentials

```typescript
// Get all stored credentials
const credentials = authenticator.getCredentials();
console.log(`Stored ${credentials.length} credentials`);

// Get a specific credential
const credential = authenticator.getCredential('credential-id');
if (credential) {
  console.log(`Found credential for RP: ${credential.rpId}`);
}

// Remove a credential
const removed = authenticator.removeCredential('credential-id');
if (removed) {
  console.log('Credential removed successfully');
}

// Clear all credentials
authenticator.clearCredentials();
console.log('All credentials cleared');
```

## Complete Example

```typescript
import { PasskeyAuthenticator } from 'passkey-authenticator';

async function registerAndAuthenticate() {
  // Create authenticator
  const authenticator = new PasskeyAuthenticator();

  // Step 1: Registration
  const registrationOptions = {
    challenge: "server-generated-challenge-1",
    rp: { name: "My App", id: "myapp.com" },
    user: {
      id: "user-456",
      name: "alice@example.com",
      displayName: "Alice"
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    timeout: 60000
  };

  const attestation = await authenticator.credentialCreate(registrationOptions);
  console.log('Registration successful!');
  console.log('Credential ID:', attestation.id);

  // Step 2: Authentication
  const authenticationOptions = {
    challenge: "server-generated-challenge-2",
    rpId: "myapp.com",
    allowCredentials: [
      {
        id: attestation.id,
        type: "public-key"
      }
    ],
    timeout: 60000
  };

  const assertion = await authenticator.credentialGet(authenticationOptions);
  console.log('Authentication successful!');
  console.log('Signature:', assertion.response.signature);
}

registerAndAuthenticate().catch(console.error);
```

## End-to-End Example

This example demonstrates a complete WebAuthn flow including server-side verification using `@simplewebauthn/server`.

**Installation:**

```bash
npm install passkey-authenticator @simplewebauthn/server @simplewebauthn/types
```

**Complete Flow:**

```typescript
import { PasskeyAuthenticator } from 'passkey-authenticator';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';

// Server configuration
const rpName = 'My App';
const rpID = 'localhost';
const origin = `http://${rpID}:3000`;

// In-memory storage (use a database in production)
const userCredentials = new Map<string, any>();

async function completeWebAuthnFlow() {
  // Create authenticator instance
  const authenticator = new PasskeyAuthenticator();

  // ============================================
  // REGISTRATION FLOW
  // ============================================

  console.log('\n=== REGISTRATION ===\n');

  // Step 1: Server generates registration options
  const registrationOptions = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: 'user@example.com',
    userDisplayName: 'Example User',
    // Timeout in milliseconds
    timeout: 60000,
    // Attestation type
    attestationType: 'none',
    // Supported algorithms
    supportedAlgorithmIDs: [-7, -257], // ES256, RS256
  });

  console.log('Server generated registration options');
  console.log('Challenge:', registrationOptions.challenge);

  // Step 2: Authenticator creates credential
  const registrationResponse = await authenticator.credentialCreate(
    registrationOptions
  );

  console.log('Authenticator created credential');
  console.log('Credential ID:', registrationResponse.id);

  // Step 3: Server verifies registration response
  let verification: VerifiedRegistrationResponse;
  try {
    verification = await verifyRegistrationResponse({
      response: registrationResponse,
      expectedChallenge: registrationOptions.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (error) {
    console.error('Registration verification failed:', error);
    throw error;
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    console.log('✓ Registration verified successfully!');
    
    // Store credential for future authentication
    userCredentials.set(registrationResponse.id, {
      credentialID: registrationInfo.credentialID,
      credentialPublicKey: registrationInfo.credentialPublicKey,
      counter: registrationInfo.counter,
      credentialDeviceType: registrationInfo.credentialDeviceType,
      credentialBackedUp: registrationInfo.credentialBackedUp,
    });
    
    console.log('Credential stored on server');
  } else {
    throw new Error('Registration verification failed');
  }

  // ============================================
  // AUTHENTICATION FLOW
  // ============================================

  console.log('\n=== AUTHENTICATION ===\n');

  // Step 1: Server generates authentication options
  const authenticationOptions = await generateAuthenticationOptions({
    rpID,
    timeout: 60000,
    // Allow any credential for this user
    allowCredentials: [{
      id: registrationResponse.id,
      type: 'public-key',
      transports: ['internal'],
    }],
    userVerification: 'preferred',
  });

  console.log('Server generated authentication options');
  console.log('Challenge:', authenticationOptions.challenge);

  // Step 2: Authenticator generates assertion
  const authenticationResponse = await authenticator.credentialGet(
    authenticationOptions
  );

  console.log('Authenticator generated assertion');
  console.log('Credential ID:', authenticationResponse.id);

  // Step 3: Server verifies authentication response
  const storedCredential = userCredentials.get(authenticationResponse.id);
  
  if (!storedCredential) {
    throw new Error('Credential not found');
  }

  let authVerification: VerifiedAuthenticationResponse;
  try {
    authVerification = await verifyAuthenticationResponse({
      response: authenticationResponse,
      expectedChallenge: authenticationOptions.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: storedCredential.credentialID,
        credentialPublicKey: storedCredential.credentialPublicKey,
        counter: storedCredential.counter,
      },
    });
  } catch (error) {
    console.error('Authentication verification failed:', error);
    throw error;
  }

  const { verified: authVerified, authenticationInfo } = authVerification;

  if (authVerified) {
    console.log('✓ Authentication verified successfully!');
    
    // Update counter to prevent replay attacks
    storedCredential.counter = authenticationInfo.newCounter;
    
    console.log('User authenticated successfully!');
    console.log('New counter value:', authenticationInfo.newCounter);
  } else {
    throw new Error('Authentication verification failed');
  }

  console.log('\n=== FLOW COMPLETE ===\n');
}

// Run the complete flow
completeWebAuthnFlow().catch(console.error);
```

**Expected Output:**

```
=== REGISTRATION ===

Server generated registration options
Challenge: <base64url-encoded-challenge>
Authenticator created credential
Credential ID: <base64url-encoded-credential-id>
✓ Registration verified successfully!
Credential stored on server

=== AUTHENTICATION ===

Server generated authentication options
Challenge: <base64url-encoded-challenge>
Authenticator generated assertion
Credential ID: <base64url-encoded-credential-id>
✓ Authentication verified successfully!
User authenticated successfully!
New counter value: 1

=== FLOW COMPLETE ===
```

## API Reference

### `PasskeyAuthenticator`

#### Constructor

```typescript
constructor(aaguid?: Uint8Array)
```

Creates a new authenticator instance.

- `aaguid` (optional): 16-byte Authenticator Attestation GUID. Defaults to all zeros.

#### Methods

##### `credentialCreate(options: PublicKeyCredentialCreationOptionsJSON, pkcs8FilePath?: string): Promise<RegistrationResponseJSON>`

Generates an attestation response for credential registration.

- **Parameters:**
  - `options`: Credential creation options from the relying party
  - `pkcs8FilePath` (optional): Path to a PKCS8 private key file. If provided and the file exists, the key will be loaded and used. If the file doesn't exist, an error is thrown. If not provided, a new key pair will be generated.
- **Returns:** Registration response (attestation) to send back to the relying party

##### `credentialGet(options: PublicKeyCredentialRequestOptionsJSON, pkcs8FilePath?: string): Promise<AuthenticationResponseJSON>`

Generates an assertion response for authentication.

- **Parameters:**
  - `options`: Credential request options from the relying party
  - `pkcs8FilePath` (optional): Path to a PKCS8 private key file. If provided, this key will be used instead of the stored credential's key. The key must match the credential's algorithm. If the file doesn't exist, an error is thrown.
- **Returns:** Authentication response (assertion) to send back to the relying party

##### `exportCredentialKey(credentialId: string, filePath: string): boolean`

Exports a credential's private key to a PKCS8 file.

- **Parameters:**
  - `credentialId`: The credential ID to export
  - `filePath`: Path where the PKCS8 file should be written
- **Returns:** `true` if credential was found and exported, `false` if not found

##### `getCredentials(): StoredCredential[]`

Returns all stored credentials.

##### `getCredential(credentialId: string): StoredCredential | undefined`

Returns a specific credential by ID.

##### `removeCredential(credentialId: string): boolean`

Removes a credential. Returns `true` if successful.

##### `clearCredentials(): void`

Removes all stored credentials.

## Types

The module exports the following TypeScript types:

- `StoredCredential`: Internal credential storage format
- `PublicKeyCredentialCreationOptionsJSON`: Credential creation options
- `PublicKeyCredentialRequestOptionsJSON`: Credential request options
- `RegistrationResponseJSON`: Attestation response format
- `AuthenticationResponseJSON`: Assertion response format
- `AuthenticatorTransport`: Transport types for credentials


## Security Considerations

- This implementation is intended for testing and development purposes
- Private keys are stored in memory and will be lost when the process exits
- For production use, consider implementing secure key storage
- Always validate responses on the relying party side

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Resources

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [FIDO2 Project](https://fidoalliance.org/fido2/)
- [SimpleWebAuthn Documentation](https://simplewebauthn.dev/)
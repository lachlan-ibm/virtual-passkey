import * as crypto from 'crypto';
import {
  generateKeyPair,
  buildAttestationAuthData,
  buildAssertionAuthData,
  createClientDataJSON,
  createPackedAttestation,
  signData,
  selectAlgorithm,
  getRpId,
  generateOrigin,
  readPKCS8PrivateKey,
  writePKCS8PrivateKey,
  extractPublicKeyFromPrivate,
  detectAlgorithmFromKey
} from './helpers';

/**
 * WebAuthn Types
 * These types match the W3C WebAuthn specification
 */

export type AuthenticatorTransport = 'usb' | 'nfc' | 'ble' | 'internal' | 'hybrid';

export type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';

export type AttestationConveyancePreference = 'none' | 'indirect' | 'direct' | 'enterprise';

export type AuthenticatorAttachment = 'platform' | 'cross-platform';

export type ResidentKeyRequirement = 'discouraged' | 'preferred' | 'required';

export interface PublicKeyCredentialRpEntity {
  id?: string;
  name: string;
}

export interface PublicKeyCredentialUserEntity {
  id: string;
  name: string;
  displayName: string;
}

export interface PublicKeyCredentialParameters {
  type: 'public-key';
  alg: number;
}

export interface PublicKeyCredentialDescriptor {
  type: 'public-key';
  id: string;
  transports?: AuthenticatorTransport[];
}

export interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: AuthenticatorAttachment;
  residentKey?: ResidentKeyRequirement;
  requireResidentKey?: boolean;
  userVerification?: UserVerificationRequirement;
}

export interface PublicKeyCredentialCreationOptionsJSON {
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntity;
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptor[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: Record<string, unknown>;
}

export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptor[];
  userVerification?: UserVerificationRequirement;
  extensions?: Record<string, unknown>;
}

export interface AuthenticatorAttestationResponseJSON {
  clientDataJSON: string;
  attestationObject: string;
  transports?: AuthenticatorTransport[];
}

export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  response: AuthenticatorAttestationResponseJSON;
  type: 'public-key';
  clientExtensionResults?: Record<string, unknown>;
  authenticatorAttachment?: AuthenticatorAttachment;
}

export interface AuthenticatorAssertionResponseJSON {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  response: AuthenticatorAssertionResponseJSON;
  type: 'public-key';
  clientExtensionResults?: Record<string, unknown>;
  authenticatorAttachment?: AuthenticatorAttachment;
}

/**
 * Convert Uint8Array to base64url string
 */
function uint8ArrayToBase64url(buffer: Uint8Array): string {
  const base64 = Buffer.from(buffer).toString('base64');
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Convert base64url string to Uint8Array
 */
function base64urlToUint8Array(base64url: string): Uint8Array {
  const base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  return new Uint8Array(Buffer.from(base64 + padding, 'base64'));
}

/**
 * Stored credential information
 */
export interface StoredCredential {
  /**
   * Credential ID
   */
  credentialId: Uint8Array;
  
  /**
   * Private key for this credential
   */
  privateKey: any; // CryptoKey from Web Crypto API
  
  /**
   * Public key for this credential
   */
  publicKey: Uint8Array;
  
  /**
   * Signature counter
   */
  counter: number;
  
  /**
   * Relying Party ID this credential is for
   */
  rpId: string;
  
  /**
   * User handle (optional)
   */
  userHandle?: Uint8Array;
  
  /**
   * Algorithm used (-7 for ES256, -257 for RS256)
   */
  algorithm: number;
}

/**
 * Main PasskeyAuthenticator class that simulates a WebAuthn/Fido2/Passkey authenticator
 * This class generates attestation and assertion responses like a hardware security key would
 */
export class PasskeyAuthenticator {
  private credentials: Map<string, StoredCredential>;
  private aaguid: Uint8Array;
  private disableCounter: boolean;

  /**
   * Creates a new PasskeyAuthenticator instance
   * @param aaguid - Optional Authenticator Attestation GUID (16 bytes)
   * @param disableCounter - If true, counter will always remain at 0 and not increment
   */
  constructor(aaguid?: Uint8Array, disableCounter: boolean = false) {
    this.credentials = new Map();
    this.aaguid = aaguid || new Uint8Array(16);
    this.disableCounter = disableCounter;
  }

  // Constant for credential ID size
  private static readonly CREDENTIAL_ID_SIZE = 128;

  /**
   * Load a private key from a PKCS8 file and validate it
   * @param pkcs8FilePath - Path to the PKCS8 file
   * @param expectedAlgorithm - Optional expected algorithm to validate against
   * @returns Object containing the private key, public key bytes, and algorithm
   */
  private loadKeyFromPKCS8(
    pkcs8FilePath: string,
    expectedAlgorithm?: number
  ): { privateKey: crypto.KeyObject; publicKeyBytes: Uint8Array; algorithm: number } {
    const loadedKey = readPKCS8PrivateKey(pkcs8FilePath);
    
    if (!loadedKey) {
      throw new Error(`PKCS8 file not found: ${pkcs8FilePath}`);
    }
    
    const algorithm = detectAlgorithmFromKey(loadedKey);
    
    // If an expected algorithm is provided, validate it matches
    if (expectedAlgorithm !== undefined && algorithm !== expectedAlgorithm) {
      throw new Error(
        `Key algorithm mismatch: expected ${expectedAlgorithm}, but loaded key is ${algorithm}`
      );
    }
    
    const publicKeyBytes = extractPublicKeyFromPrivate(loadedKey, algorithm);
    
    return {
      privateKey: loadedKey,
      publicKeyBytes,
      algorithm
    };
  }

  /**
   * Prepare key pair for credential creation
   * Either loads from PKCS8 file or generates a new key pair
   * @param options - The credential creation options
   * @param pkcs8FilePath - Optional path to PKCS8 file
   * @returns Object containing private key, public key bytes, and algorithm
   */
  private initKeyPair(
    options: PublicKeyCredentialCreationOptionsJSON,
    pkcs8FilePath?: string
  ): { privateKey: crypto.KeyObject; publicKeyBytes: Uint8Array; algorithm: number } {
    if (pkcs8FilePath) {
      // Load private key from PKCS8 file
      const keyData = this.loadKeyFromPKCS8(pkcs8FilePath);
      
      // Verify the algorithm is supported by the RP
      const supportedAlgs = options.pubKeyCredParams.map(p => p.alg);
      if (!supportedAlgs.includes(keyData.algorithm)) {
        throw new Error(
          `Key algorithm ${keyData.algorithm} not supported by RP. Supported: ${supportedAlgs.join(', ')}`
        );
      }
      
      return keyData;
    } else {
      // Generate new key pair
      const algorithm = selectAlgorithm(options.pubKeyCredParams);
      const keyPair = generateKeyPair(algorithm);
      
      return {
        privateKey: keyPair.privateKey,
        publicKeyBytes: keyPair.publicKeyBytes,
        algorithm
      };
    }
  }

  /**
   * Create a new credential (registration/attestation)
   * Takes the publicKey options from navigator.credentials.create() and returns an attestation response
   *
   * @param options - The publicKey credential creation options from the relying party
   * @param pkcs8FilePath - Optional path to a PKCS8 private key file. If provided and the file exists,
   *                        the key will be loaded and used. If the file doesn't exist, an error is thrown.
   *                        If not provided, a new key pair will be generated.
   * @returns A registration response (attestation) to send back to the relying party
   *
   * @example
   * ```typescript
   * const authenticator = new PasskeyAuthenticator();
   *
   * // Options received from relying party
   * const creationOptions = {
   *   challenge: "...",
   *   rp: { name: "Example", id: "example.com" },
   *   user: {
   *     id: "user123",
   *     name: "john@example.com",
   *     displayName: "John Doe"
   *   },
   *   pubKeyCredParams: [{ alg: -7, type: "public-key" }],
   *   // ... other options
   * };
   *
   * // Create credential with generated key
   * const attestationResponse = await authenticator.credentialCreate(creationOptions);
   *
   * // Or create credential using existing PKCS8 key file
   * const attestationResponse2 = await authenticator.credentialCreate(
   *   creationOptions,
   *   '/path/to/private-key.pem'
   * );
   * // Send attestationResponse back to relying party for verification
   * ```
   */
  async credentialCreate(
   options: PublicKeyCredentialCreationOptionsJSON,
   pkcs8FilePath?: string
 ): Promise<RegistrationResponseJSON> {
   // Validate and extract required parameters
   const rpId = getRpId(options.rp.id);
   
   // Prepare key pair (load from file or generate new)
   const { privateKey, publicKeyBytes, algorithm } = this.initKeyPair(
     options,
     pkcs8FilePath
   );
   
   const credentialId = crypto.randomBytes(PasskeyAuthenticator.CREDENTIAL_ID_SIZE);
    const credentialIdString = uint8ArrayToBase64url(new Uint8Array(credentialId));
    
    // Build attestation components
    const authenticatorData = buildAttestationAuthData(
      rpId,
      this.aaguid,
      credentialId,
      publicKeyBytes,
      algorithm
    );
    
    const origin = generateOrigin(rpId);
    const clientDataJSON = createClientDataJSON('webauthn.create', options.challenge, origin);
    
    const attestationObject = createPackedAttestation(
      authenticatorData,
      clientDataJSON,
      privateKey,
      algorithm
    );
    
    // Store credential
    this.storeCredential(
      credentialIdString,
      credentialId,
      privateKey,
      publicKeyBytes,
      rpId,
      options.user.id,
      algorithm
    );
    
    // Build and return response
    return this.buildRegistrationResponse(
      credentialIdString,
      clientDataJSON,
      attestationObject
    );
  }

  /**
   * Store a new credential
   */
  private storeCredential(
    credentialIdString: string,
    credentialId: Buffer,
    privateKey: crypto.KeyObject,
    publicKey: Uint8Array,
    rpId: string,
    userId: string,
    algorithm: number
  ): void {
    const credential: StoredCredential = {
      credentialId: new Uint8Array(credentialId),
      privateKey,
      publicKey,
      counter: 0,
      rpId,
      userHandle: base64urlToUint8Array(userId),
      algorithm
    };
    
    this.credentials.set(credentialIdString, credential);
  }

  /**
   * Build registration response
   */
  private buildRegistrationResponse(
    credentialIdString: string,
    clientDataJSON: Buffer,
    attestationObject: Uint8Array
  ): RegistrationResponseJSON {
    return {
      id: credentialIdString,
      rawId: credentialIdString,
      response: {
        clientDataJSON: uint8ArrayToBase64url(new Uint8Array(clientDataJSON)),
        attestationObject: uint8ArrayToBase64url(attestationObject),
        transports: ['internal']
      },
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: 'platform'
    };
  }

  /**
   * Get/use an existing credential (authentication/assertion)
   * Takes the publicKey options from navigator.credentials.get() and returns an assertion response
   *
   * @param options - The publicKey credential request options from the relying party
   * @param pkcs8FilePath - Optional path to a PKCS8 private key file. If provided, this key will be used
   *                        instead of the stored credential's key. The key must match the credential's algorithm.
   *                        If the file doesn't exist, an error is thrown.
   * @returns An authentication response (assertion) to send back to the relying party
   *
   * @example
   * ```typescript
   * const authenticator = new PasskeyAuthenticator();
   *
   * // Options received from relying party
   * const requestOptions = {
   *   challenge: "...",
   *   rpId: "example.com",
   *   allowCredentials: [
   *     { id: "credentialId", type: "public-key" }
   *   ],
   *   // ... other options
   * };
   *
   * // Use stored credential key
   * const assertionResponse = await authenticator.credentialGet(requestOptions);
   *
   * // Or use a specific PKCS8 key file
   * const assertionResponse2 = await authenticator.credentialGet(
   *   requestOptions,
   *   '/path/to/private-key.pem'
   * );
   * // Send assertionResponse back to relying party for verification
   * ```
   */
  async credentialGet(
   options: PublicKeyCredentialRequestOptionsJSON,
   pkcs8FilePath?: string
 ): Promise<AuthenticationResponseJSON> {
   // Validate and find credential
   const rpId = getRpId(options.rpId);
   const { credential, credentialIdString } = this.findMatchingCredential(options, rpId);
   
   // If pkcs8FilePath is provided, override the stored private key
   if (pkcs8FilePath) {
     const keyData = this.loadKeyFromPKCS8(pkcs8FilePath, credential.algorithm);
     // Use the loaded key instead of the stored one
     credential.privateKey = keyData.privateKey;
   }
    
   // Increment counter (unless disabled)
   if (!this.disableCounter) {
     credential.counter++;
   }
    
    // Build assertion components
    const authenticatorData = buildAssertionAuthData(rpId, credential.counter);
    const origin = generateOrigin(rpId);
    const clientDataJSON = createClientDataJSON('webauthn.get', options.challenge, origin);
    
    // Create signature
    const signature = this.createAssertionSignature(
      authenticatorData,
      clientDataJSON,
      credential
    );
    
    // Build and return response
    return this.buildAuthenticationResponse(
      credentialIdString,
      clientDataJSON,
      authenticatorData,
      signature,
      credential.userHandle
    );
  }

  /**
   * Create assertion signature
   */
  private createAssertionSignature(
    authenticatorData: Buffer,
    clientDataJSON: Buffer,
    credential: StoredCredential
  ): Buffer {
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
    const signatureData = Buffer.concat([authenticatorData, clientDataHash]);
    return signData(signatureData, credential.privateKey, credential.algorithm);
  }

  /**
   * Build authentication response
   */
  private buildAuthenticationResponse(
    credentialIdString: string,
    clientDataJSON: Buffer,
    authenticatorData: Buffer,
    signature: Buffer,
    userHandle?: Uint8Array
  ): AuthenticationResponseJSON {
    const response: AuthenticatorAssertionResponseJSON = {
      clientDataJSON: uint8ArrayToBase64url(new Uint8Array(clientDataJSON)),
      authenticatorData: uint8ArrayToBase64url(new Uint8Array(authenticatorData)),
      signature: uint8ArrayToBase64url(new Uint8Array(signature))
    };
    
    if (userHandle) {
      response.userHandle = uint8ArrayToBase64url(userHandle);
    }
    
    return {
      id: credentialIdString,
      rawId: credentialIdString,
      response,
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: 'platform'
    };
  }

  /**
   * Find a matching credential for the given options
   */
  private findMatchingCredential(
    options: PublicKeyCredentialRequestOptionsJSON,
    rpId: string
  ): { credential: StoredCredential; credentialIdString: string } {
    let credential: StoredCredential | undefined;
    let credentialIdString: string | undefined;
    
    if (options.allowCredentials && options.allowCredentials.length > 0) {
      // Find credential from allowCredentials list
      for (const allowedCred of options.allowCredentials) {
        const cred = this.credentials.get(allowedCred.id);
        if (cred && cred.rpId === rpId) {
          credential = cred;
          credentialIdString = allowedCred.id;
          break;
        }
      }
    } else {
      // Find any credential for this RP ID
      for (const [id, cred] of this.credentials.entries()) {
        if (cred.rpId === rpId) {
          credential = cred;
          credentialIdString = id;
          break;
        }
      }
    }
    
    if (!credential || !credentialIdString) {
      throw new Error('No matching credential found');
    }
    
    return { credential, credentialIdString };
  }

  /**
   * Get all stored credentials
   * @returns Array of stored credentials
   */
  getCredentials(): StoredCredential[] {
    return Array.from(this.credentials.values());
  }

  /**
   * Get a specific credential by ID
   * @param credentialId - The credential ID to retrieve
   * @returns The stored credential or undefined
   */
  getCredential(credentialId: string): StoredCredential | undefined {
    return this.credentials.get(credentialId);
  }

  /**
   * Remove a credential
   * @param credentialId - The credential ID to remove
   * @returns True if credential was removed, false if not found
   */
  removeCredential(credentialId: string): boolean {
    return this.credentials.delete(credentialId);
  }

  /**
   * Import a credential
   */
  importCredential(credential: StoredCredential): void {
    const credentialIdString = uint8ArrayToBase64url(credential.credentialId);
    this.credentials.set(credentialIdString, credential);
  }

  /**
   * Clear all stored credentials
   */
  clearCredentials(): void {
    this.credentials.clear();
  }

  /**
   * Export a credential's private key to a PKCS8 file
   * @param credentialId - The credential ID to export
   * @param filePath - Path where the PKCS8 file should be written
   * @returns True if credential was found and exported, false if not found
   */
  exportCredentialKey(credentialId: string, filePath: string): boolean {
    const credential = this.credentials.get(credentialId);
    
    if (!credential) {
      return false;
    }
    
    writePKCS8PrivateKey(credential.privateKey, filePath);
    return true;
  }

}

// Made with Bob

import * as crypto from 'crypto';
import * as fs from 'fs';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { CBOREncoder } from './cbor';
import { encodeCOSEPublicKey } from './cose';

/**
 * Helper functions for WebAuthn operations
 */

export interface KeyPairResult {
  privateKey: crypto.KeyObject;
  publicKeyBytes: Uint8Array;
}

/**
 * Validate and get RP ID from options
 */
export function getRpId(rpId?: string): string {
  if (!rpId || rpId.trim() === '') {
    throw new Error('RP ID is required and cannot be empty');
  }
  return rpId;
}

/**
 * Generate origin URL from RP ID
 */
export function generateOrigin(rpId: string): string {
  // Validate RP ID format (basic validation)
  if (!rpId || rpId.includes('://') || rpId.includes(' ')) {
    throw new Error('Invalid RP ID format');
  }
  return `https://${rpId}`;
}

/**
 * Generate a key pair for the specified algorithm
 */
export function generateKeyPair(algorithm: number): KeyPairResult {
  if (algorithm === -7) {
    // ES256: ECDSA with P-256 curve
    const keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    
    // Extract raw public key (65 bytes: 0x04 + X + Y)
    const publicKeyDer = keyPair.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    const publicKeyBytes = new Uint8Array(publicKeyDer.slice(-65));
    
    return {
      privateKey: keyPair.privateKey,
      publicKeyBytes
    };
  } else if (algorithm === -257) {
    // RS256: RSA with SHA-256
    const keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048
    });
    
    const publicKeyBytes = new Uint8Array(
      keyPair.publicKey.export({ type: 'spki', format: 'der' }) as Buffer
    );
    
    return {
      privateKey: keyPair.privateKey,
      publicKeyBytes
    };
  } else if (algorithm === -8) {
    // Ed25519: EdDSA with Ed25519 curve
    const keyPair = crypto.generateKeyPairSync('ed25519');
    
    // Extract raw public key (32 bytes)
    // Ed25519 public key in SPKI format: last 32 bytes are the raw public key
    const publicKeyDer = keyPair.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    const publicKeyBytes = new Uint8Array(publicKeyDer.slice(-32));
    
    return {
      privateKey: keyPair.privateKey,
      publicKeyBytes
    };
  } else if (algorithm === -48) {
    // ML-DSA-44: Module-Lattice-Based Digital Signature Algorithm (FIPS 204)
    const keyPair = ml_dsa44.keygen();
    
    // ML-DSA-44 returns { publicKey: Uint8Array, secretKey: Uint8Array }
    // Store it as a custom object since Node.js crypto doesn't support ML-DSA natively
    const privateKey = {
      type: 'ml-dsa-44',
      secretKey: keyPair.secretKey
    } as any;
    
    return {
      privateKey: privateKey as crypto.KeyObject,
      publicKeyBytes: keyPair.publicKey
    };
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

/**
 * Build authenticator data for attestation
 */
export function buildAttestationAuthData(
  rpId: string,
  aaguid: Uint8Array,
  credentialId: Buffer,
  publicKeyBytes: Uint8Array,
  algorithm: number
): Buffer {
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  
  // Flags: UP (User Present) = 0x01, UV (User Verified) = 0x04, AT (Attested) = 0x40, BE (Backup Eligible) = 0x08
  const flags = 0x01 | 0x04 | 0x40 | 0x08;
  
  // Counter (4 bytes, starts at 0)
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(0, 0);
  
  // Attested credential data
  const attestedCredData = Buffer.concat([
    Buffer.from(aaguid),                              // AAGUID (16 bytes)
    Buffer.from([0x00, credentialId.length]),         // Credential ID length (2 bytes)
    credentialId,                                      // Credential ID
    encodeCOSEPublicKey(publicKeyBytes, algorithm)    // COSE public key
  ]);
  
  return Buffer.concat([
    rpIdHash,              // RP ID hash (32 bytes)
    Buffer.from([flags]),  // Flags (1 byte)
    counter,               // Counter (4 bytes)
    attestedCredData       // Attested credential data
  ]);
}

/**
 * Build authenticator data for assertion
 */
export function buildAssertionAuthData(
  rpId: string,
  counter: number
): Buffer {
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  
  // Flags: UP (User Present) = 0x01, UV (User Verified) = 0x04, BE (Backup Eligible) = 0x08, BS (Backup State) = 0x10
  const flags = 0x01 | 0x04 | 0x08 | 0x10;
  
  const counterBuffer = Buffer.alloc(4);
  counterBuffer.writeUInt32BE(counter, 0);
  
  return Buffer.concat([
    rpIdHash,                 // RP ID hash (32 bytes)
    Buffer.from([flags]),     // Flags (1 byte)
    counterBuffer             // Counter (4 bytes)
  ]);
}

/**
 * Create client data JSON
 */
export function createClientDataJSON(
  type: 'webauthn.create' | 'webauthn.get',
  challenge: string,
  origin: string
): Buffer {
  const clientData = {
    type,
    challenge,
    origin,
    crossOrigin: false
  };
  return Buffer.from(JSON.stringify(clientData), 'utf8');
}

/**
 * Sign data with the private key
 */
export function signData(
  data: Buffer,
  privateKey: crypto.KeyObject,
  algorithm: number
): Buffer {
  // The data passed here should already be: authenticatorData || hash(clientDataJSON)
  if (algorithm === -7) {
    // ES256 signature
    // WebAuthn spec requires DER encoding for ECDSA signatures

    const sign = crypto.createSign('SHA256');
    sign.update(data);
    return sign.sign(privateKey); // DER encoding (default)
  } else if (algorithm === -257) {
    // RS256 signature
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    return sign.sign(privateKey);
  } else if (algorithm === -8) {
    // Ed25519 signature
    // EdDSA doesn't require specifying a hash algorithm
    return crypto.sign(null, data, {
      key: privateKey,
      dsaEncoding: 'der'
    });
  } else if (algorithm === -48) {
    // ML-DSA-44 signature
    const mldsaKey = privateKey as any;
    if (mldsaKey.type !== 'ml-dsa-44') {
      throw new Error('Invalid ML-DSA-44 key');
    }
    // The secretKey is the full encoded secret key from keygen
    const signature = ml_dsa44.sign(new Uint8Array(data), mldsaKey.secretKey);
    return Buffer.from(signature);
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

/**
 * Create packed attestation object (basic-self)
 */
export function createPackedAttestation(
  authenticatorData: Buffer,
  clientDataJSON: Buffer,
  privateKey: crypto.KeyObject,
  algorithm: number
): Uint8Array {
  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
  const signatureData = Buffer.concat([authenticatorData, clientDataHash]);
  const signature = signData(signatureData, privateKey, algorithm);
  
  const encoder = new CBOREncoder();
  return encoder.encode({
    fmt: 'packed',
    attStmt: {
      alg: algorithm,
      sig: new Uint8Array(signature)
    },
    authData: new Uint8Array(authenticatorData)
  });
}

/**
 * Select supported algorithm from pubKeyCredParams
 */
export function selectAlgorithm(pubKeyCredParams: Array<{ alg: number; type: string }>): number {
  const supportedAlgs = pubKeyCredParams.filter(
    param => param.alg === -7 || param.alg === -257 || param.alg === -8 || param.alg === -48
  );
  
  if (supportedAlgs.length === 0) {
    throw new Error('No supported algorithms found (ES256, RS256, Ed25519, or ML-DSA-44 required)');
  }
  
  return supportedAlgs[0].alg;
}

/**
 * Read and parse a PKCS8 private key file
 * @param filePath - Path to the PKCS8 file
 * @returns KeyObject containing the private key, or null if file doesn't exist
 */
export function readPKCS8PrivateKey(filePath: string): crypto.KeyObject | null {
  try {
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return null;
    }
    
    // Read the file
    const keyData = fs.readFileSync(filePath, 'utf8');
    
    // Check if it's an ML-DSA-44 key (custom format)
    if (keyData.includes('-----BEGIN ML-DSA-44 PRIVATE KEY-----')) {
      // Extract the base64 data between the markers
      const base64Data = keyData
        .replace('-----BEGIN ML-DSA-44 PRIVATE KEY-----', '')
        .replace('-----END ML-DSA-44 PRIVATE KEY-----', '')
        .replace(/\s/g, '');
      
      // Decode the base64 data
      const keyBuffer = Buffer.from(base64Data, 'base64');
      
      // ML-DSA-44 encoded secret key is 2560 bytes
      if (keyBuffer.length !== 2560) {
        throw new Error(`Invalid ML-DSA-44 key length: expected 2560 bytes, got ${keyBuffer.length}`);
      }
      
      const secretKey = new Uint8Array(keyBuffer);
      
      // Return as custom object
      return {
        type: 'ml-dsa-44',
        secretKey
      } as any;
    }
    
    // Validate it's a PKCS8 format
    if (!keyData.includes('-----BEGIN PRIVATE KEY-----') ||
        !keyData.includes('-----END PRIVATE KEY-----')) {
      throw new Error('Invalid PKCS8 format: missing BEGIN/END PRIVATE KEY markers');
    }
    
    // Create KeyObject from PEM
    const privateKey = crypto.createPrivateKey({
      key: keyData,
      format: 'pem',
      type: 'pkcs8'
    });
    
    return privateKey;
  } catch (error) {
    throw new Error(`Failed to read PKCS8 private key: ${(error as Error).message}`);
  }
}

/**
 * Write a private key to a PKCS8 file
 * @param privateKey - The private key to export
 * @param filePath - Path where the PKCS8 file should be written
 */
export function writePKCS8PrivateKey(privateKey: crypto.KeyObject, filePath: string): void {
  try {
    // Check if it's an ML-DSA-44 key (custom object)
    const mldsaKey = privateKey as any;
    if (mldsaKey.type === 'ml-dsa-44') {
      // The secretKey is already the full encoded secret key (2560 bytes)
      const base64Data = Buffer.from(mldsaKey.secretKey).toString('base64');
      
      // Format with PEM markers
      const pemData = `-----BEGIN ML-DSA-44 PRIVATE KEY-----\n${base64Data.match(/.{1,64}/g)?.join('\n')}\n-----END ML-DSA-44 PRIVATE KEY-----\n`;
      
      // Write to file
      fs.writeFileSync(filePath, pemData, 'utf8');
      return;
    }
    
    // Export private key in PKCS8 PEM format
    const keyData = privateKey.export({
      type: 'pkcs8',
      format: 'pem'
    }) as string;
    
    // Write to file
    fs.writeFileSync(filePath, keyData, 'utf8');
  } catch (error) {
    throw new Error(`Failed to write PKCS8 private key: ${(error as Error).message}`);
  }
}

/**
 * Extract public key bytes from a private key
 * @param privateKey - The private key KeyObject
 * @param algorithm - The algorithm (-7 for ES256, -257 for RS256)
 * @returns Public key bytes in the appropriate format
 */
export function extractPublicKeyFromPrivate(
  privateKey: crypto.KeyObject,
  algorithm: number
): Uint8Array {
  if (algorithm === -48) {
    // ML-DSA-44: Extract public key from the encoded secret key
    const mldsaKey = privateKey as any;
    if (mldsaKey.type !== 'ml-dsa-44') {
      throw new Error('Invalid ML-DSA-44 key');
    }
    // Use ml_dsa44.getPublicKey to extract public key from secret key
    return ml_dsa44.getPublicKey(mldsaKey.secretKey);
  }
  
  // Export the public key from the private key
  const publicKey = crypto.createPublicKey(privateKey);
  
  if (algorithm === -7) {
    // ES256: Extract raw public key (65 bytes: 0x04 + X + Y)
    const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    return new Uint8Array(publicKeyDer.slice(-65));
  } else if (algorithm === -257) {
    // RS256: Export full DER format
    const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    return new Uint8Array(publicKeyDer);
  } else if (algorithm === -8) {
    // Ed25519: Extract raw public key (32 bytes)
    const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    return new Uint8Array(publicKeyDer.slice(-32));
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

/**
 * Detect algorithm from private key
 * @param privateKey - The private key KeyObject
 * @returns Algorithm number (-7 for ES256, -257 for RS256)
 */
export function detectAlgorithmFromKey(privateKey: crypto.KeyObject): number {
  // Check if it's an ML-DSA-44 key (custom object)
  const mldsaKey = privateKey as any;
  if (mldsaKey.type === 'ml-dsa-44') {
    return -48; // ML-DSA-44
  }
  
  const keyType = privateKey.asymmetricKeyType;
  
  if (keyType === 'ec') {
    // Check if it's P-256 curve
    const keyDetails = privateKey.asymmetricKeyDetails;
    if (keyDetails && keyDetails.namedCurve === 'prime256v1') {
      return -7; // ES256
    }
    throw new Error('Only P-256 (prime256v1) EC keys are supported');
  } else if (keyType === 'rsa') {
    return -257; // RS256
  } else if (keyType === 'ed25519') {
    return -8; // Ed25519
  } else {
    throw new Error(`Unsupported key type: ${keyType}`);
  }
}

// Made with Bob

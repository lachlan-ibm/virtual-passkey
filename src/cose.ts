import { CBOREncoder } from './cbor';

/**
 * COSE (CBOR Object Signing and Encryption) utilities for WebAuthn
 */

/**
 * Encode a COSE key for WebAuthn
 * @param publicKey - The public key bytes
 * @param algorithm - The algorithm (-7 for ES256, -257 for RS256)
 */
export function encodeCOSEPublicKey(publicKey: Uint8Array, algorithm: number): Uint8Array {
  const encoder = new CBOREncoder();
  
  if (algorithm === -7) {
    return encodeECDSAKey(encoder, publicKey);
  } else if (algorithm === -257) {
    return encodeRSAKey(encoder, publicKey);
  } else if (algorithm === -8) {
    return encodeED25519Key(encoder, publicKey);
  } else if (algorithm === -48) {
    return encodeMLDSA44Key(encoder, publicKey);
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

function encodeRSAKey(encoder: CBOREncoder, publicKey: Uint8Array): Uint8Array {
  // RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
  // Extract modulus (n) and exponent (e) from DER-encoded public key
  const { n, e } = extractRSAPublicKey(publicKey);
  
  // COSE key format for RS256
  const coseKey = {
    1: 3,        // kty: RSA
    3: -257,     // alg: RS256
    '-1': n,     // n: modulus
    '-2': e      // e: exponent
  };
  return encoder.encode(coseKey);
}

function encodeECDSAKey(encoder: CBOREncoder, publicKey: Uint8Array): Uint8Array {
  // ES256 (ECDSA with P-256 and SHA-256)
  // Public key is 65 bytes: 0x04 + 32-byte X + 32-byte Y
  if (publicKey.length !== 65 || publicKey[0] !== 0x04) {
    throw new Error('Invalid ES256 public key format');
  }
  
  const x = publicKey.slice(1, 33);
  const y = publicKey.slice(33, 65);
  
  // COSE key format for ES256
  const coseKey = {
    1: 2,        // kty: EC2
    3: -7,       // alg: ES256
    '-1': 1,     // crv: P-256
    '-2': x,     // x coordinate
    '-3': y      // y coordinate
  };
  
  return encoder.encode(coseKey);
}

function encodeED25519Key(encoder: CBOREncoder, publicKey: Uint8Array): Uint8Array {
  // Ed25519 public key should be exactly 32 bytes
  if (publicKey.length !== 32) {
    throw new Error('Invalid Ed25519 public key format: expected 32 bytes');
  }
  
  // COSE key format for Ed25519
  const coseKey = {
    1: 1,        // kty: OKP (Octet Key Pair)
    3: -8,       // alg: EdDSA
    '-1': 6,     // crv: Ed25519
    '-2': publicKey  // x: public key bytes
  };
  
  return encoder.encode(coseKey);
}

function encodeMLDSA44Key(encoder: CBOREncoder, publicKey: Uint8Array): Uint8Array {
  // ML-DSA-44 public key should be 1312 bytes (as per FIPS 204)
  if (publicKey.length !== 1312) {
    throw new Error(`Invalid ML-DSA-44 public key format: expected 1312 bytes, got ${publicKey.length}`);
  }
  
  // COSE key format for ML-DSA-44
  // Using OKP (Octet Key Pair) key type with ML-DSA-44 algorithm
  const coseKey = {
    1: 1,        // kty: OKP (Octet Key Pair)
    3: -48,      // alg: ML-DSA-44 (IANA registered value)
    '-1': publicKey  // x: public key bytes
  };
  
  return encoder.encode(coseKey);
}

/** DER tag for SEQUENCE type */
const DER_TAG_SEQUENCE = 0x30;

/** DER tag for INTEGER type */
const DER_TAG_INTEGER = 0x02;

/** Mask to check if length is in long form (bit 7 set) */
const DER_LENGTH_LONG_FORM_MASK = 0x80;

/** Mask to extract number of length bytes in long form */
const DER_LENGTH_BYTES_MASK = 0x7f;

/**
 * Parse DER length encoding
 * @param data - The DER-encoded data
 * @param offset - Current offset in the data
 * @returns Object containing the parsed length and number of bytes consumed
 * @throws Error if data is insufficient or malformed
 */
function parseDERLength(data: Uint8Array, offset: number): { length: number; bytesRead: number } {
  if (offset >= data.length) {
    throw new Error(`DER parsing error: unexpected end of data at offset ${offset}`);
  }

  const firstByte = data[offset];
  
  // Short form: length is in the first byte (bit 7 is 0)
  if ((firstByte & DER_LENGTH_LONG_FORM_MASK) === 0) {
    return { length: firstByte, bytesRead: 1 };
  }
  
  // Long form: first byte indicates how many subsequent bytes encode the length
  const lengthBytes = firstByte & DER_LENGTH_BYTES_MASK;
  
  if (lengthBytes === 0) {
    throw new Error(`DER parsing error: indefinite length not supported at offset ${offset}`);
  }
  
  if (offset + lengthBytes >= data.length) {
    throw new Error(`DER parsing error: insufficient data for length bytes at offset ${offset}`);
  }
  
  let length = 0;
  for (let i = 0; i < lengthBytes; i++) {
    length = (length << 8) | data[offset + 1 + i];
  }
  
  return { length, bytesRead: 1 + lengthBytes };
}

/**
 * Parse a DER INTEGER value
 * @param data - The DER-encoded data
 * @param offset - Current offset in the data
 * @param fieldName - Name of the field being parsed (for error messages)
 * @returns Object containing the parsed integer value and number of bytes consumed
 * @throws Error if data is insufficient or malformed
 */
function parseDERInteger(
  data: Uint8Array,
  offset: number,
  fieldName: string
): { value: Uint8Array; bytesRead: number } {
  if (offset >= data.length) {
    throw new Error(`DER parsing error: unexpected end of data when parsing ${fieldName} at offset ${offset}`);
  }
  
  // Validate INTEGER tag
  if (data[offset] !== DER_TAG_INTEGER) {
    throw new Error(
      `Invalid RSA public key: expected INTEGER tag (0x02) for ${fieldName} at offset ${offset}, got 0x${data[offset].toString(16)}`
    );
  }
  
  let currentOffset = offset + 1;
  
  // Parse length
  const { length, bytesRead } = parseDERLength(data, currentOffset);
  currentOffset += bytesRead;
  
  // Validate we have enough data
  if (currentOffset + length > data.length) {
    throw new Error(
      `DER parsing error: insufficient data for ${fieldName} INTEGER value at offset ${currentOffset} (need ${length} bytes)`
    );
  }
  
  // Skip leading zero byte if present (used for positive integers with high bit set)
  let valueOffset = currentOffset;
  let valueLength = length;
  
  if (length > 0 && data[currentOffset] === 0x00) {
    valueOffset++;
    valueLength--;
  }
  
  const value = data.slice(valueOffset, valueOffset + valueLength);
  const totalBytesRead = 1 + bytesRead + length; // tag + length bytes + value bytes
  
  return { value, bytesRead: totalBytesRead };
}

/**
 * Extract RSA public key components from DER-encoded key
 *
 * Parses a DER-encoded RSA public key in SPKI (SubjectPublicKeyInfo) format:
 * SEQUENCE {
 *   SEQUENCE {
 *     OBJECT IDENTIFIER rsaEncryption
 *     NULL
 *   }
 *   BIT STRING {
 *     SEQUENCE {
 *       modulus INTEGER,
 *       exponent INTEGER
 *     }
 *   }
 * }
 *
 * @param derKey - DER-encoded RSA public key in SPKI format
 * @returns Object containing the modulus (n) and exponent (e) as Uint8Arrays
 * @throws Error if the input is invalid or malformed
 */
function extractRSAPublicKey(derKey: Uint8Array): { n: Uint8Array; e: Uint8Array } {
  // Input validation
  if (!derKey || derKey.length === 0) {
    throw new Error('Invalid RSA public key: input is empty or undefined');
  }
  
  if (derKey.length < 10) {
    throw new Error(`Invalid RSA public key: input too short (${derKey.length} bytes, minimum 10 required)`);
  }
  
  let offset = 0;
  
  // Parse outer SEQUENCE tag (SPKI wrapper)
  if (derKey[offset] !== DER_TAG_SEQUENCE) {
    throw new Error(
      `Invalid RSA public key: expected SEQUENCE tag (0x30) at offset ${offset}, got 0x${derKey[offset].toString(16)}`
    );
  }
  offset++;
  
  // Parse outer SEQUENCE length
  const { bytesRead: outerSequenceLengthBytes } = parseDERLength(derKey, offset);
  offset += outerSequenceLengthBytes;
  
  // Parse algorithm identifier SEQUENCE
  if (derKey[offset] !== DER_TAG_SEQUENCE) {
    throw new Error(
      `Invalid RSA public key: expected algorithm SEQUENCE tag (0x30) at offset ${offset}, got 0x${derKey[offset].toString(16)}`
    );
  }
  offset++;
  
  // Parse algorithm SEQUENCE length
  const { length: algSeqLength, bytesRead: algSeqLengthBytes } = parseDERLength(derKey, offset);
  offset += algSeqLengthBytes;
  
  // Skip the algorithm identifier SEQUENCE content (OID + NULL)
  offset += algSeqLength;
  
  // Parse BIT STRING tag
  const BIT_STRING_TAG = 0x03;
  if (derKey[offset] !== BIT_STRING_TAG) {
    throw new Error(
      `Invalid RSA public key: expected BIT STRING tag (0x03) at offset ${offset}, got 0x${derKey[offset].toString(16)}`
    );
  }
  offset++;
  
  // Parse BIT STRING length
  const { bytesRead: bitStringLengthBytes } = parseDERLength(derKey, offset);
  offset += bitStringLengthBytes;
  
  // Skip the unused bits byte (should be 0x00)
  offset++;
  
  // Now we're at the actual RSA key SEQUENCE
  if (derKey[offset] !== DER_TAG_SEQUENCE) {
    throw new Error(
      `Invalid RSA public key: expected RSA key SEQUENCE tag (0x30) at offset ${offset}, got 0x${derKey[offset].toString(16)}`
    );
  }
  offset++;
  
  // Parse RSA key SEQUENCE length
  const { bytesRead: rsaSeqLengthBytes } = parseDERLength(derKey, offset);
  offset += rsaSeqLengthBytes;
  
  // Parse modulus (n)
  const { value: n, bytesRead: nBytesRead } = parseDERInteger(derKey, offset, 'modulus');
  offset += nBytesRead;
  
  // Parse exponent (e)
  const { value: e } = parseDERInteger(derKey, offset, 'exponent');
  
  // Validate we got valid values
  if (n.length === 0) {
    throw new Error('Invalid RSA public key: modulus is empty');
  }
  
  if (e.length === 0) {
    throw new Error('Invalid RSA public key: exponent is empty');
  }
  
  return { n, e };
}

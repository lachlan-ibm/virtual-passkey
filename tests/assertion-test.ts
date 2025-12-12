import fs from 'fs';
import assert from 'assert';
import {
  PasskeyAuthenticator,
  PublicKeyCredentialRequestOptionsJSON,
  AuthenticationResponseJSON,
  StoredCredential
} from '../src/index';
import { readPKCS8PrivateKey, extractPublicKeyFromPrivate, detectAlgorithmFromKey } from '../src/helpers';
import { TestHelper, HttpResponse } from './test-helper';

const RP_URL = 'https://www.myidp.ibm.com';
const RP_UUID = process.argv[2] || 'aa583468-4702-4f0e-803f-d813418a2cd3';
const KEY_TYPE = process.argv[3] || 'ec';
const ASSERTION_OPTIONS_PATH = `/mga/sps/fido2/${RP_UUID}/assertion/options`;
const ASSERTION_RESULT_PATH = `/mga/sps/fido2/${RP_UUID}/assertion/result`;
const USERNAME = process.argv[4] || 'testuser';
const SECRET = process.argv[5] || "passw0rd";

const testHelper = new TestHelper(RP_URL);

/**
 * Result structure for passkey authentication
 */
interface AuthenticationResult {
  options: PublicKeyCredentialRequestOptionsJSON;
  assertion: AuthenticationResponseJSON;
  verification: HttpResponse<unknown>;
}


/**
 * Performs passkey authentication flow
 * @param authenticator - The PasskeyAuthenticator instance
 * @param pkcs8FilePath - Path to PKCS8 private key file
 * @returns Authentication result containing options, assertion, and verification
 */
async function performAuthentication(
  authenticator: PasskeyAuthenticator,
  pkcs8FilePath: string
): Promise<AuthenticationResult> {
  const authOptions = await testHelper.makeRequest<PublicKeyCredentialRequestOptionsJSON>(
    `${testHelper.getRpUrl()}${ASSERTION_OPTIONS_PATH}`,
    'POST',
    { username: USERNAME }
  );
  
  const assertion = await authenticator.credentialGet(authOptions.data as any, pkcs8FilePath);
  
  const authVerify = await testHelper.makeRequest(
    `${testHelper.getRpUrl()}${ASSERTION_RESULT_PATH}`,
    'POST',
    assertion as unknown as Record<string, unknown>
  );
  
  return { options: authOptions.data, assertion, verification: authVerify };
}


/**
 * Main test function that orchestrates the complete passkey flow
 * Performs login, registration, and authentication in sequence
 */
async function main(): Promise<void> {
  try {
    console.log('Testing PasskeyAuthenticator with', testHelper.getRpUrl());

    console.log("\n=== Get session cookie via Password Authentication ===");
    await testHelper.performPasswordLogin(USERNAME, SECRET);

    // Passkey Authentication using PKCS8 private key (with counter disabled)
    const authenticator = new PasskeyAuthenticator(undefined, true);
    console.log('\n=== AUTHENTICATION ===');
    
    console.log('Read credential ID from virtual.passkey.credid');
    assert(fs.existsSync('virtual.passkey.' + KEY_TYPE + '.credid'), 'Credential ID file not found');
    const credentialId = fs.readFileSync('virtual.passkey.' + KEY_TYPE + '.credid', 'utf-8');
    console.log('  Credential ID loaded:', credentialId);
    
    console.log('Import credential from PKCS8 file');
    assert(fs.existsSync('virtual.passkey.pem'), 'PKCS8 key file not found');
    
    const privateKey = readPKCS8PrivateKey('virtual.passkey.' + KEY_TYPE + '.pem');
    assert(privateKey, 'Failed to read PKCS8 private key');
    
    const algorithm = detectAlgorithmFromKey(privateKey);
    const publicKeyBytes = extractPublicKeyFromPrivate(privateKey, algorithm);
    
    const credentialIdBytes = Buffer.from(credentialId, 'base64url');
    
    const storedCredential: StoredCredential = {
      credentialId: new Uint8Array(credentialIdBytes),
      privateKey: privateKey,
      publicKey: publicKeyBytes,
      counter: 0,
      rpId: 'www.myidp.ibm.com',
      algorithm: algorithm
    };
    
    authenticator.importCredential(storedCredential);
    console.log('  Credential imported successfully');
    
    const authResult = await performAuthentication(authenticator, undefined as any);
    console.log('Assertion Options:', authResult.options);
    console.log('Assertion Response:', authResult.assertion);
    console.log('Authentication Result:', authResult.verification);
    
    assert.strictEqual(authResult.assertion.id, credentialId, 'Credential ID mismatch between file and assertion response');
    console.log('  Credential ID verified - matches assertion response');
    
    assert.strictEqual(authResult.verification.status, 200, 'Authentication verification failed - expected status 200');
    console.log('  Authentication status verified - received 200');
    
    assert.strictEqual((authResult.verification.data as any).status, 'ok', 'Authentication verification failed - expected status "ok"');
    console.log('  Authentication response status verified - received "ok"');

    console.log('\n  Test complete - All phases successful');
  } catch (error) {
    console.error('\n  Test failed:', error instanceof Error ? error.message : error);
    throw error;
  }
}

main().catch(console.error);

import fs from 'fs';
import assert from 'assert';
import {
  PasskeyAuthenticator,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON
} from '../src/index';
import { TestHelper, HttpResponse } from './test-helper';

const RP_URL = 'https://www.myidp.ibm.com';
const RP_UUID = process.argv[2] || 'aa583468-4702-4f0e-803f-d813418a2cd3';
const ATTESTATION_OPTIONS_PATH = `/mga/sps/fido2/${RP_UUID}/attestation/options`;
const ATTESTATION_RESULT_PATH = `/mga/sps/fido2/${RP_UUID}/attestation/result`;
const ASSERTION_OPTIONS_PATH = `/mga/sps/fido2/${RP_UUID}/assertion/options`;
const ASSERTION_RESULT_PATH = `/mga/sps/fido2/${RP_UUID}/assertion/result`;
const USERNAME = process.argv[3] || 'testuser';
const SECRET = process.argv[4] || "passw0rd";

const testHelper = new TestHelper(RP_URL);

/**
 * Force ED25519 algorithm by modifying the pubKeyCredParams
 * @param options - The original credential creation options
 * @returns Modified options with only ES256 algorithm
 */
function forceEDAlgorithm(
  options: PublicKeyCredentialCreationOptionsJSON
): PublicKeyCredentialCreationOptionsJSON {
  const modifiedOptions = { ...options };
  
  // Filter to only include ED25519 (-8) algorithm
  const edParams = modifiedOptions.pubKeyCredParams.filter(param => param.alg === -8);
  
  if (edParams.length === 0) {
    console.log('  ED25519 not found in server options, adding it');
    modifiedOptions.pubKeyCredParams = [
      { type: 'public-key', alg: -8 }
    ];
  } else {
    console.log('  Forcing ED25519 algorithm (filtering out other algorithms)');
    modifiedOptions.pubKeyCredParams = edParams;
  }
  
  return modifiedOptions;
}

/**
 * Result structure for passkey registration
 */
interface RegistrationResult {
  options: PublicKeyCredentialCreationOptionsJSON;
  attestation: RegistrationResponseJSON;
  verification: HttpResponse<unknown>;
}

/**
 * Performs passkey registration flow with forced EC key
 * @param authenticator - The PasskeyAuthenticator instance
 * @returns Registration result containing options, attestation, and verification
 */
async function performRegistration(
  authenticator: PasskeyAuthenticator
): Promise<RegistrationResult> {
  const regOptions = await testHelper.makeRequest<PublicKeyCredentialCreationOptionsJSON>(
    `${testHelper.getRpUrl()}${ATTESTATION_OPTIONS_PATH}`,
    'POST',
    { username: USERNAME }
  );
  
  console.log('  Original pubKeyCredParams:', regOptions.data.pubKeyCredParams);
  
  const modifiedOptions = forceEDAlgorithm(regOptions.data);
  console.log('  Modified pubKeyCredParams:', modifiedOptions.pubKeyCredParams);
  
  const attestation = await authenticator.credentialCreate(modifiedOptions as any);
  
  const regVerify = await testHelper.makeRequest(
    `${testHelper.getRpUrl()}${ATTESTATION_RESULT_PATH}`,
    'POST',
    attestation as unknown as Record<string, unknown>
  );
  
  return { options: regOptions.data, attestation, verification: regVerify };
}

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
 * @returns Authentication result containing options, assertion, and verification
 */
async function performAuthentication(
  authenticator: PasskeyAuthenticator
): Promise<AuthenticationResult> {
  const authOptions = await testHelper.makeRequest<PublicKeyCredentialRequestOptionsJSON>(
    `${testHelper.getRpUrl()}${ASSERTION_OPTIONS_PATH}`,
    'POST',
    { username: USERNAME }
  );
  
  const assertion = await authenticator.credentialGet(authOptions.data as any);
  
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
    console.log('Testing PasskeyAuthenticator with ED25519 keys at', testHelper.getRpUrl());

    console.log("\n=== Get session cookie via Password Authentication ===");
    await testHelper.performPasswordLogin(USERNAME, SECRET);

    // Passkey Registration with EC
    const authenticator = new PasskeyAuthenticator(undefined, true);
    console.log('\n=== REGISTRATION (ED25519) ===');
    const regResult = await performRegistration(authenticator);
    console.log('Attestation Options:', regResult.options);
    console.log('Attestation Response:', regResult.attestation);
    console.log('Registration Result:', regResult.verification);

    // Passkey Authentication
    console.log('\n=== AUTHENTICATION ===');
    const authResult = await performAuthentication(authenticator);
    console.log('Assertion Options:', authResult.options);
    console.log('Assertion Response:', authResult.assertion);
    console.log('Authentication Result:', authResult.verification);


    console.log('Write ED key to virtual.passkey.ec.pem');
    const exportSuccess = authenticator.exportCredentialKey(regResult.attestation.id, 'virtual.passkey.ed25519.pem');
    
    assert(exportSuccess, 'Credential key export failed - credential not found');
    console.log('  EC credential key exported successfully');
    
    console.log('Write credential ID to virtual.passkey.ed25519.credid');
    fs.writeFileSync('virtual.passkey.ec.credid', regResult.attestation.id);
    console.log('  Credential ID written successfully');

    console.log('\n  Test complete - All phases successful with ED25519 key');
  } catch (error) {
    console.error('\n  Test failed:', error instanceof Error ? error.message : error);
    throw error;
  }
}

main().catch(console.error);

// Made with Bob

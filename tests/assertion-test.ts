import https from 'https';
import { IncomingMessage } from 'http';
import fs from 'fs';
import assert from 'assert';
import {
  PasskeyAuthenticator,
  PublicKeyCredentialRequestOptionsJSON,
  AuthenticationResponseJSON,
  StoredCredential
} from '../src/index';
import { readPKCS8PrivateKey, extractPublicKeyFromPrivate, detectAlgorithmFromKey } from '../src/helpers';

const RP_URL = 'https://www.myidp.ibm.com';
// Usage: ts-node tests/attestation-assertion-test.ts <uuid>
const RP_UUID = process.argv[2] || 'aa583468-4702-4f0e-803f-d813418a2cd3';
const KEY_TYPE = process.argv[3] || 'ec';
const ASSERTION_OPTIONS_PATH = `/mga/sps/fido2/${RP_UUID}/assertion/options`;
const ASSERTION_RESULT_PATH = `/mga/sps/fido2/${RP_UUID}/assertion/result`;
const USERNAME = process.argv[4] || 'testuser';
const SECRET = process.argv[5] || "passw0rd";
const LOGIN_PATH = "/mga/sps/apiauthsvc/policy/password"

const agent = new https.Agent({
  rejectUnauthorized: false
});

let sessionCookies: string[] = [];

// Type definitions
interface HttpResponse<T = unknown> {
  status: number;
  data: T;
  cookies: string[];
}


/**
 * Extracts the cookie name from a Set-Cookie header value
 * @param cookie - The Set-Cookie header value
 * @returns The cookie name (part before the '=' sign)
 */
function extractCookieName(cookie: string): string {
  return cookie.split('=')[0];
}

/**
 * Updates the session cookies array with new Set-Cookie headers
 * Replaces existing cookies with the same name
 * @param currentCookies - Current session cookies
 * @param setCookieHeaders - New Set-Cookie headers from response
 * @returns Updated cookies array
 */
function updateSessionCookies(
  currentCookies: string[],
  setCookieHeaders: string[]
): string[] {
  let updated = [...currentCookies];
  
  setCookieHeaders.forEach(cookie => {
    const cookieName = extractCookieName(cookie);
    updated = updated.filter(c => !c.startsWith(`${cookieName}=`));
    updated.push(cookie.split(';')[0]);
  });
  
  return updated;
}

/**
 * Parses response data, attempting JSON parse first, falling back to raw string
 * @param rawData - Raw response data string
 * @returns Parsed JSON object or raw string if parsing fails
 */
function parseResponseData(rawData: string): unknown {
  if (!rawData.trim()) {
    return null;
  }
  
  try {
    return JSON.parse(rawData);
  } catch {
    return rawData;
  }
}

/**
 * Builds request configuration including headers and options
 * @param url - The full URL to request
 * @param method - HTTP method (GET or POST)
 * @param contentType - Content-Type header value
 * @returns Request headers and HTTPS options
 */
function buildRequestConfig(
  url: string,
  method: 'GET' | 'POST',
  contentType: string = 'application/json'
): {
  headers: Record<string, string>;
  options: https.RequestOptions;
} {
  const urlObj = new URL(url);
  
  const headers: Record<string, string> = {
    'Content-Type': contentType,
    'User-Agent': 'PasskeyAuthenticator-Test/1.0',
    ...(sessionCookies.length > 0 && {
      Cookie: sessionCookies.join('; ')
    })
  };
  
  const options: https.RequestOptions = {
    hostname: urlObj.hostname,
    port: urlObj.port || 443,
    path: urlObj.pathname + urlObj.search,
    method,
    headers,
    agent
  };
  
  return { headers, options };
}

/**
 * Creates a response handler for HTTPS requests
 * @param resolve - Promise resolve function
 * @returns Response handler function
 */
function createResponseHandler<T>(
  resolve: (value: HttpResponse<T>) => void
): (res: IncomingMessage) => void {
  return (res) => {
    const setCookieHeaders = res.headers['set-cookie'];
    if (setCookieHeaders) {
      sessionCookies = updateSessionCookies(sessionCookies, setCookieHeaders);
    }
    
    let rawData = '';
    res.on('data', (chunk: Buffer) => rawData += chunk);
    res.on('end', () => {
      resolve({
        status: res.statusCode ?? 0,
        data: parseResponseData(rawData) as T,
        cookies: sessionCookies
      });
    });
  };
}

/**
 * Makes an HTTPS request with automatic cookie management
 * @param url - The full URL to request
 * @param method - HTTP method (GET or POST)
 * @param body - Request body for POST requests
 * @param isFormEncoded - Whether to send as form-encoded data instead of JSON
 * @returns Promise resolving to HTTP response with status, data, and cookies
 */
async function makeRequest<T = unknown>(
  url: string,
  method: 'GET' | 'POST' = 'GET',
  body?: Record<string, unknown> | unknown,
  isFormEncoded: boolean = false
): Promise<HttpResponse<T>> {
  return new Promise((resolve, reject) => {
    const contentType = isFormEncoded
      ? 'application/x-www-form-urlencoded'
      : 'application/json';
    
    let requestBody = '';
    if (body) {
      if (isFormEncoded && typeof body === 'object' && body !== null) {
        requestBody = Object.entries(body as Record<string, unknown>)
          .map(([key, value]) =>
            `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`
          )
          .join('&');
      } else {
        requestBody = JSON.stringify(body);
      }
    }
    
    const { options } = buildRequestConfig(url, method, contentType);
    
    if (requestBody) {
      options.headers = {
        ...options.headers,
        'Content-Length': Buffer.byteLength(requestBody)
      };
    }

    const req = https.request(options, createResponseHandler<T>(resolve));

    req.on('error', (error) => {
      reject(new Error(`HTTP ${method} request to ${url} failed: ${error.message}`));
    });
    
    if (requestBody) {
      req.write(requestBody);
    }
    
    req.end();
  });
}

/**
 * Validates the login response for successful authentication
 * @param response - The HTTP response from the login request
 * @throws Error if login validation fails
 */
function validateLoginResponse(response: HttpResponse<unknown>): void {
  if (response.status !== 204) {
    throw new Error(
      `Login failed (Status: ${response.status}). ` +
      `Expected status 204 for successful authentication.`
    );
  }
}

/**
 * Performs password-based login authentication using authsvc API
 * @throws Error if login fails
 */
async function performPasswordLogin(): Promise<void> {
  const loginResponse = await makeRequest<unknown>(
    `${RP_URL}${LOGIN_PATH}`,
    'POST',
    { username: USERNAME, password: SECRET, operation: "verify" },
    false
  );
  
  console.log('Login Response Status:', loginResponse.status);
  validateLoginResponse(loginResponse);
  console.log('  Login successful - received 204 status');
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
 * @param pkcs8FilePath - Path to PKCS8 private key file
 * @returns Authentication result containing options, assertion, and verification
 */
async function performAuthentication(
  authenticator: PasskeyAuthenticator,
  pkcs8FilePath: string
): Promise<AuthenticationResult> {
  const authOptions = await makeRequest<PublicKeyCredentialRequestOptionsJSON>(
    `${RP_URL}${ASSERTION_OPTIONS_PATH}`,
    'POST',
    { username: USERNAME }
  );
  
  const assertion = await authenticator.credentialGet(authOptions.data as any, pkcs8FilePath);
  
  const authVerify = await makeRequest(
    `${RP_URL}${ASSERTION_RESULT_PATH}`,
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
    console.log('Testing PasskeyAuthenticator with', RP_URL);

    // Bootstrap Assertion with username
    console.log("\n=== Get session cookie via Password Authentication ===");
    await performPasswordLogin();

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

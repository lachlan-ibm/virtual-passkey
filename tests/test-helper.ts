import https from 'https';
import { IncomingMessage } from 'http';

/**
 * HTTP response structure
 */
export interface HttpResponse<T = unknown> {
  status: number;
  data: T;
  cookies: string[];
}

/**
 * Test helper class for PasskeyAuthenticator tests
 * Provides HTTP client functionality with cookie management and common test utilities
 */
export class TestHelper {
  private sessionCookies: string[] = [];
  private agent: https.Agent;
  private rpUrl: string;
  private loginPath: string;

  constructor(rpUrl: string, loginPath: string = '/mga/sps/apiauthsvc/policy/password') {
    this.rpUrl = rpUrl;
    this.loginPath = loginPath;
    this.agent = new https.Agent({
      rejectUnauthorized: false
    });
  }

  /**
   * Extracts the cookie name from a Set-Cookie header value
   */
  private extractCookieName(cookie: string): string {
    return cookie.split('=')[0];
  }

  /**
   * Updates the session cookies array with new Set-Cookie headers
   * Replaces existing cookies with the same name
   */
  private updateSessionCookies(setCookieHeaders: string[]): void {
    let updated = [...this.sessionCookies];
    
    setCookieHeaders.forEach(cookie => {
      const cookieName = this.extractCookieName(cookie);
      updated = updated.filter(c => !c.startsWith(`${cookieName}=`));
      updated.push(cookie.split(';')[0]);
    });
    
    this.sessionCookies = updated;
  }

  /**
   * Parses response data, attempting JSON parse first, falling back to raw string
   */
  private parseResponseData(rawData: string): unknown {
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
   */
  private buildRequestConfig(
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
      ...(this.sessionCookies.length > 0 && {
        Cookie: this.sessionCookies.join('; ')
      })
    };
    
    const options: https.RequestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname + urlObj.search,
      method,
      headers,
      agent: this.agent
    };
    
    return { headers, options };
  }

  /**
   * Creates a response handler for HTTPS requests
   */
  private createResponseHandler<T>(
    resolve: (value: HttpResponse<T>) => void
  ): (res: IncomingMessage) => void {
    return (res) => {
      const setCookieHeaders = res.headers['set-cookie'];
      if (setCookieHeaders) {
        this.updateSessionCookies(setCookieHeaders);
      }
      
      let rawData = '';
      res.on('data', (chunk: Buffer) => rawData += chunk);
      res.on('end', () => {
        resolve({
          status: res.statusCode ?? 0,
          data: this.parseResponseData(rawData) as T,
          cookies: this.sessionCookies
        });
      });
    };
  }

  /**
   * Makes an HTTPS request with automatic cookie management
   */
  async makeRequest<T = unknown>(
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
      
      const { options } = this.buildRequestConfig(url, method, contentType);
      
      if (requestBody) {
        options.headers = {
          ...options.headers,
          'Content-Length': Buffer.byteLength(requestBody)
        };
      }

      const req = https.request(options, this.createResponseHandler<T>(resolve));

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
   */
  private validateLoginResponse(response: HttpResponse<unknown>): void {
    if (response.status !== 204) {
      throw new Error(
        `Login failed (Status: ${response.status}). ` +
        `Expected status 204 for successful authentication.`
      );
    }
  }

  /**
   * Performs password-based login authentication using authsvc API
   */
  async performPasswordLogin(username: string, password: string): Promise<void> {
    const loginResponse = await this.makeRequest<unknown>(
      `${this.rpUrl}${this.loginPath}`,
      'POST',
      { username, password, operation: "verify" },
      false
    );
    
    console.log('Login Response Status:', loginResponse.status);
    this.validateLoginResponse(loginResponse);
    console.log('  Login successful - received 204 status');
  }

  /**
   * Gets the current session cookies
   */
  getSessionCookies(): string[] {
    return [...this.sessionCookies];
  }

  /**
   * Clears the current session cookies
   */
  clearSessionCookies(): void {
    this.sessionCookies = [];
  }

  /**
   * Gets the RP URL
   */
  getRpUrl(): string {
    return this.rpUrl;
  }
}

// Made with Bob

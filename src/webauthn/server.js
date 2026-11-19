// Port of DogTagKit/WebAuthnServer.swift — routes /webauthn/* requests to the WebAuthnManager.
import { extractClientIP } from '../utils.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

/** HTTPResponse.json */
const json = (object, statusCode = 200) =>
  new Response(JSON.stringify(object), { status: statusCode, headers: { 'Content-Type': 'application/json', ...CORS } });
/** HTTPResponse.success */
const success = (message = 'Success') => json({ success: true, message });
/** HTTPResponse.error */
const error = (message, statusCode = 400) => json({ success: false, error: message }, statusCode);

const log = (...a) => console.log('[WebAuthnServer]', ...a);

export class WebAuthnServer {
  constructor(manager) {
    this.manager = manager;
  }

  async handleRequest(request) {
    const path = new URL(request.url).pathname;
    log(`${request.method} ${path}`);

    let body = null;
    try { body = JSON.parse(await request.text()); } catch { body = null; }
    if (body === null || typeof body !== 'object' || Array.isArray(body)) body = null;

    const ctx = { body, userAgent: request.headers.get('user-agent') ?? '', clientIP: extractClientIP(request) };

    if (request.method !== 'POST') return error('Not Found', 404);
    switch (path) {
      case '/webauthn/register/begin': return this.handleRegisterBegin(ctx);
      case '/webauthn/register/begin/linux':
        return this.registerWith(ctx, 'Linux', (u) => this.manager.generateLinuxCompatibleRegistrationOptions(u));
      case '/webauthn/register/begin/linux-software':
        return this.registerWith(ctx, 'Linux software', (u) => this.manager.generateLinuxSoftwareRegistrationOptions(u));
      case '/webauthn/register/begin/universal':
        return this.registerWith(ctx, 'Universal', (u) => this.manager.generateHybridRegistrationOptions(u));
      case '/webauthn/register/begin/hybrid':
        return this.registerWith(ctx, 'Hybrid', (u) => this.manager.generateHybridRegistrationOptions(u));
      case '/webauthn/register/begin/android':
        return this.registerWith(ctx, 'Android', (u) => this.manager.generateAndroidRegistrationOptions(u));
      case '/webauthn/register/complete': return this.handleRegisterComplete(ctx);
      case '/webauthn/authenticate/begin': return this.handleAuthenticateBegin(ctx);
      case '/webauthn/authenticate/begin/linux-software':
        return this.authenticateWith(ctx, (u) => this.manager.generateLinuxSoftwareAuthenticationOptions(u));
      case '/webauthn/authenticate/begin/hybrid':
        return this.authenticateWith(ctx, (u) => this.manager.generateHybridAuthenticationOptions(u));
      case '/webauthn/authenticate/complete': return this.handleAuthenticateComplete(ctx);
      case '/webauthn/username/check': return this.handleUsernameCheck(ctx);
      default: return error('Not Found', 404);
    }
  }

  // MARK: - Registration Routes

  handleRegisterBegin({ body, userAgent }) {
    const username = body?.username;
    if (typeof username !== 'string') return error('Invalid request body - username required');

    const isChrome = userAgent.includes('Chrome');
    const isWindows11 = userAgent.includes('Windows NT 10.0');

    let options;
    if (isChrome) {
      log(`Using Chrome-compatible registration options for: ${username}`);
      options = this.manager.generateChromeCompatibleRegistrationOptions(username);
    } else if (isWindows11) {
      log(`Using Windows 11 compatible registration options for: ${username}`);
      options = this.manager.generateWindows11CompatibleRegistrationOptions(username);
    } else {
      options = this.manager.generateRegistrationOptions(username);
    }
    return json(options);
  }

  registerWith({ body }, label, generate) {
    const username = body?.username;
    if (typeof username !== 'string') {
      log(`${label} registration begin: Invalid request body`);
      return error('Invalid request body - username required');
    }
    log(`Using ${label} registration options for: ${username}`);
    return json(generate(username));
  }

  async handleRegisterComplete({ body, clientIP }) {
    const username = body?.username;
    if (typeof username !== 'string') return error('Invalid request body - username required');
    try {
      await this.manager.verifyRegistration(username, body, clientIP);
      log(`Registration completed successfully for: ${username}`);
      return success('Registration successful');
    } catch (e) {
      log(`Registration verification failed: ${e.message}`);
      return error(`Registration verification failed: ${e.message}`);
    }
  }

  // MARK: - Authentication Routes

  handleAuthenticateBegin({ body }) {
    if (!body) return error('Invalid request body');
    const username = typeof body.username === 'string' ? body.username : null;
    const securityKeyOnly = body.securityKeyOnly === true;
    try {
      const options = securityKeyOnly
        ? this.manager.generateSecurityKeyAuthenticationOptions(username)
        : this.manager.generateAuthenticationOptions(username);
      return json(options);
    } catch (e) {
      return error(`Failed to generate authentication options: ${e.message}`);
    }
  }

  authenticateWith({ body }, generate) {
    if (!body) return error('Invalid request body');
    const username = typeof body.username === 'string' ? body.username : null;
    try {
      return json(generate(username));
    } catch (e) {
      return error(`Failed to generate authentication options: ${e.message}`);
    }
  }

  async handleAuthenticateComplete({ body, clientIP }) {
    if (!body) return error('Invalid request body');
    const username = typeof body.username === 'string' ? body.username : null;
    try {
      const foundUsername = await this.manager.verifyAuthentication(username, body, clientIP);
      log(`Authentication completed successfully for: ${foundUsername ?? username ?? 'usernameless'}`);
      return json({ success: true, username: foundUsername ?? username ?? '' });
    } catch (e) {
      log(`Authentication verification failed: ${e.message}`);
      return error(e.message);
    }
  }

  // MARK: - Utility Routes

  handleUsernameCheck({ body }) {
    const username = body?.username;
    if (typeof username !== 'string') return error('Invalid request body - username required');
    const isRegistered = this.manager.isUsernameRegistered(username);
    const response = { available: !isRegistered, username };
    if (isRegistered) response.error = 'Username already registered';
    return json(response);
  }
}

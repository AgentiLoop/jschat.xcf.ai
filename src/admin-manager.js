// Ports of DogTagKit/WebAuthAdminManager.swift and MultiPeerChatCore/AdminManager.swift
import { WebAuthnError } from './webauthn/types.js';
import { iso8601, uuid } from './utils.js';

const log = (tag, ...a) => console.log(`[${tag}]`, ...a);

export class WebAuthAdminManager {
  constructor(webAuthnManager, adminUsername) {
    this.webAuthnManager = webAuthnManager;
    this.configuredAdminUsername = adminUsername;
  }

  // MARK: - Admin Authentication

  async authenticateAdmin(username, requestData, clientIP) {
    if (username !== this.configuredAdminUsername) {
      log('WebAuthAdminManager', `❌ Username ${username} does not match configured admin`);
      throw WebAuthnError.accessDenied();
    }
    const authenticatedUsername = await this.webAuthnManager.verifyAuthentication(username, requestData, clientIP);
    const finalUsername = authenticatedUsername ?? username;
    if (finalUsername !== this.configuredAdminUsername) throw WebAuthnError.verificationFailed();
    return finalUsername;
  }

  verifyAdminAccess(username) {
    const user = this.webAuthnManager.getAllUsers().find((u) => u.username === username);
    if (!user || !(user.isEnabled && user.isAdmin)) {
      log('WebAuthAdminManager', `❌ User ${username} is not an admin or is disabled`);
      return false;
    }
    return true;
  }

  shouldAllowAdminAccess(username) {
    if (!this.webAuthnManager.isUserEnabled(username)) return false;
    return this.verifyAdminAccess(username);
  }

  // MARK: - Admin User Management

  getAllUsers() {
    return this.webAuthnManager.getAllUsers().map((c) => ({
      id: c.id,
      username: c.username,
      credentialId: c.id,
      publicKey: c.publicKey,
      signCount: c.signCount,
      createdAt: iso8601(c.createdAt ? new Date(c.createdAt) : new Date()),
      lastLoginAt: c.lastLoginAt ? iso8601(new Date(c.lastLoginAt)) : null,
      lastLoginIP: c.lastLoginIP ?? null,
      isEnabled: c.isEnabled,
      isAdmin: c.isAdmin,
      userNumber: c.userNumber ?? 0,
      emoji: c.emoji ?? '👤',
    }));
  }

  findByCredentialId(credentialId) {
    const user = this.webAuthnManager.getAllUsers().find((u) => u.id === credentialId);
    if (!user) log('WebAuthAdminManager', `❌ User with credential ID ${credentialId} not found`);
    return user;
  }

  toggleUserStatus(credentialId, enabled) {
    const user = this.findByCredentialId(credentialId);
    return user ? this.webAuthnManager.updateUserEnabledStatus(user.username, enabled) : false;
  }

  deleteUser(credentialId) {
    const user = this.findByCredentialId(credentialId);
    if (!user) return false;
    this.webAuthnManager.deleteUserCredentials(user.username);
    return true;
  }

  disableUsersByIP(ipAddress) {
    let disabledCount = 0;
    for (const user of this.webAuthnManager.getAllUsers()) {
      if (user.lastLoginIP === ipAddress && this.webAuthnManager.updateUserEnabledStatus(user.username, false)) {
        disabledCount += 1;
      }
    }
    return disabledCount;
  }

  updateUserEmoji(credentialId, emoji) {
    const user = this.findByCredentialId(credentialId);
    return user ? this.webAuthnManager.updateUserEmoji(user.username, emoji) : false;
  }

  toggleUserAdminStatus(credentialId, isAdmin) {
    const user = this.findByCredentialId(credentialId);
    return user ? this.webAuthnManager.updateUserAdminStatus(user.username, isAdmin) : false;
  }

  // MARK: - Admin Bootstrap

  bootstrapAdminUser() {
    const admin = this.webAuthnManager.getAllUsers().find((u) => u.username === this.configuredAdminUsername);
    if (!admin) {
      log('WebAuthAdminManager', `⚠️ Admin user '${this.configuredAdminUsername}' not found — register first, then auto-promoted`);
    } else if (!admin.isAdmin) {
      this.webAuthnManager.updateUserAdminStatus(this.configuredAdminUsername, true);
      log('WebAuthAdminManager', `✅ Promoted '${this.configuredAdminUsername}' to admin`);
    }
  }
}

const SESSION_TIMEOUT_MS = 3600 * 1000; // 1 hour

/**
 * AdminManager — admin sessions. Sessions are mirrored into Durable Object storage
 * (sessionStore) so they survive the object being evicted from memory.
 */
export class AdminManager {
  constructor(adminUsername, sessionStore) {
    this.configuredAdminUsername = adminUsername;
    this.sessionStore = sessionStore;
    this.adminSessions = new Map(sessionStore.loadAll().map((s) => [s.sessionId, s]));
    this.delegate = null; // { didAuthenticateUser(username), shouldAllowAdminAccess(username) }
  }

  static isExpired(session) {
    return Date.now() - session.loginTime > SESSION_TIMEOUT_MS;
  }

  extractSessionId(request) {
    const cookie = request.headers.get('cookie');
    if (cookie) {
      for (const part of cookie.split(';')) {
        const pieces = part.trim().split('=');
        if (pieces.length === 2 && pieces[0] === 'adminSessionId') return pieces[1];
      }
    }
    const auth = request.headers.get('authorization');
    if (auth && auth.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim();
    return null;
  }

  removeSession(sessionId) {
    this.adminSessions.delete(sessionId);
    this.sessionStore.delete(sessionId);
  }

  isValidAdminSession(request) {
    const sessionId = this.extractSessionId(request);
    const session = sessionId ? this.adminSessions.get(sessionId) : null;
    if (!session || AdminManager.isExpired(session)) return false;

    if (session.username !== this.configuredAdminUsername) {
      this.removeSession(sessionId);
      return false;
    }
    if (!(this.delegate?.shouldAllowAdminAccess(session.username) ?? false)) {
      this.removeSession(sessionId);
      return false;
    }
    return true;
  }

  hasValidAdminSession(request) {
    // Same semantics as the Swift version: any live admin session allows admin API access
    const validSessions = [...this.adminSessions.values()].filter((s) => !AdminManager.isExpired(s));
    if (validSessions.length) return true;

    const sessionId = this.extractSessionId(request);
    const session = sessionId ? this.adminSessions.get(sessionId) : null;
    return !!(session && !AdminManager.isExpired(session) && session.username === this.configuredAdminUsername);
  }

  createAdminSession(username, clientIP) {
    if (username !== this.configuredAdminUsername) return { sessionId: '', success: false };
    if (!(this.delegate?.didAuthenticateUser(username) ?? false)) return { sessionId: '', success: false };

    const session = { sessionId: uuid(), username, loginTime: Date.now(), clientIP: clientIP ?? 'unknown' };
    this.adminSessions.set(session.sessionId, session);
    this.sessionStore.put(session);
    return { sessionId: session.sessionId, success: true };
  }

  cleanupExpiredSessions() {
    for (const [id, s] of this.adminSessions) if (AdminManager.isExpired(s)) this.removeSession(id);
  }
}

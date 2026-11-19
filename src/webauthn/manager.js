// Port of DogTagKit/WebAuthnManager.swift
// Storage: a credential store backed by Durable Object SQLite (replaces SwiftData).
// Crypto: WebCrypto (replaces CryptoKit / Security.framework).
import { parseAttestationObject, parseCBORValue } from './cbor.js';
import { WebAuthnError, AttestationFormat, supportedAAGUIDs, makeCredential } from './types.js';
import {
  base64ToBytes, bytesToBase64, base64ToBase64url, concatBytes, sha256, randomBytes, toHex, fromUtf8, utf8,
} from '../utils.js';

const log = (...a) => console.log('[WebAuthn]', ...a);

/** Port of PersistenceManager+WebAuthn.swift (WebAuthnUserManager). All user data lives in credentials. */
export const persistenceUserManager = {
  isUserEnabled: () => true, // no legacy admin-user records in this deployment
  getUserEmoji: () => null,
  updateUserEmoji: () => false,
  createUser: () => {},
  updateUserLogin: () => {},
  deleteUser: () => {},
};

export class WebAuthnManager {
  /**
   * @param {object} opts
   * @param {string} opts.rpId
   * @param {object} opts.store  { loadAll(): cred[], put(cred), delete(username) }
   */
  constructor({ rpId, store, rpName = null, rpIcon = null, defaultUserIcon = null, adminUsername = null,
    userManager = persistenceUserManager, webAuthnProtocol = 'fido2CBOR' }) {
    this.rpId = rpId;
    this.store = store;
    this.rpName = rpName;
    this.rpIcon = rpIcon;
    this.defaultUserIcon = defaultUserIcon;
    this.adminUsername = adminUsername;
    this.userManager = userManager;
    this.webAuthnProtocol = webAuthnProtocol;

    // Database-direct cache keyed by username (write-through to SQLite)
    this.credentials = new Map();
    for (const c of store.loadAll()) this.credentials.set(c.username, makeCredential(c));

    log(`🚀 RP ID: ${rpId}, Admin Username: ${adminUsername ?? 'none'}, ${this.credentials.size} credentials`);
    this.migrateUserNumbers();
  }

  // MARK: - Public Key Extraction

  extractPublicKey(attestationObject) {
    const authData = attestationObject.authData;
    if (!(authData instanceof Uint8Array)) throw WebAuthnError.invalidCredential();

    // rpIdHash(32) + flags(1) + signCount(4) + attestedCredentialData(variable)
    if (authData.length < 37) throw WebAuthnError.invalidCredential();

    const flags = authData[32];
    const attestedCredentialDataIncluded = (flags & 0x40) !== 0;
    const backupEligible = (flags & 0x08) !== 0;
    const backupState = (flags & 0x10) !== 0;

    if (!attestedCredentialDataIncluded) throw WebAuthnError.invalidCredential();

    let offset = 37;
    if (!(offset + 15 < authData.length)) throw WebAuthnError.invalidCredential();
    const aaguid = this.formatAAGUID(authData.subarray(offset, offset + 16));
    offset += 16;

    if (!(offset + 1 < authData.length)) throw WebAuthnError.invalidCredential();
    const credentialIdLength = (authData[offset] << 8) | authData[offset + 1];
    offset += 2;
    offset += credentialIdLength;

    if (!(offset < authData.length)) throw WebAuthnError.invalidCredential();

    const publicKeyMap = parseCBORValue(authData.subarray(offset), { index: 0 });

    const kty = publicKeyMap['1'];
    const alg = publicKeyMap['3'];
    if (typeof kty !== 'number' || typeof alg !== 'number') throw WebAuthnError.invalidCredential();

    let publicKeyString;
    if (kty === 2) { // EC2
      const curve = publicKeyMap['-1'];
      if (typeof curve !== 'number') throw WebAuthnError.invalidCredential();
      const x = publicKeyMap['-2'];
      const y = publicKeyMap['-3'];
      if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) throw WebAuthnError.invalidCredential();
      if (curve === 1 && alg === -7) { // ES256 / P-256
        publicKeyString = bytesToBase64(concatBytes(new Uint8Array([0x04]), x, y));
      } else {
        throw WebAuthnError.invalidCredential();
      }
    } else if (kty === 3) { // RSA
      const n = publicKeyMap['-1'];
      const e = publicKeyMap['-2'];
      if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) throw WebAuthnError.invalidCredential();
      if (alg === -257) { // RS256 — stored as base64(JSON) like Swift
        const rsaKey = JSON.stringify({ kty: 'RSA', n: bytesToBase64(n), e: bytesToBase64(e) });
        publicKeyString = bytesToBase64(utf8(rsaKey));
      } else {
        throw WebAuthnError.invalidCredential();
      }
    } else {
      throw WebAuthnError.invalidCredential();
    }

    return { publicKey: publicKeyString, algorithm: alg, aaguid, backupEligible, backupState };
  }

  formatAAGUID(data) {
    if (data.length !== 16) return '00000000-0000-0000-0000-000000000000';
    const hex = toHex(data);
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`.toUpperCase();
  }

  detectAttestationFormat(attestationObject, aaguid) {
    const fmt = attestationObject.fmt;
    if (typeof fmt !== 'string') return AttestationFormat.none;
    if (Object.values(AttestationFormat).includes(fmt)) return fmt;
    if (aaguid) {
      for (const [format, list] of Object.entries(supportedAAGUIDs)) {
        if (list.includes(aaguid)) return AttestationFormat[format] ?? format;
      }
    }
    return AttestationFormat.none;
  }

  verifyAppleAttestationStatement(attStmt, authData) {
    log('Verifying Apple Anonymous attestation...');
    if (authData.length < 53) throw WebAuthnError.invalidCredential();
    const aaguid = this.formatAAGUID(authData.subarray(37, 53));
    if (!supportedAAGUIDs.apple.includes(aaguid)) {
      log(`❌ AAGUID ${aaguid} is not a known Apple authenticator`);
      throw WebAuthnError.invalidCredential();
    }
    log(`✅ Apple authenticator AAGUID ${aaguid} verified`);
    return true;
  }

  verifyAttestationStatement(attestationObject /*, clientDataHash */) {
    const { fmt, attStmt, authData } = attestationObject;
    if (typeof fmt !== 'string' || !attStmt || typeof attStmt !== 'object' || !(authData instanceof Uint8Array)) {
      throw WebAuthnError.invalidCredential();
    }
    const format = Object.values(AttestationFormat).includes(fmt) ? fmt : AttestationFormat.none;
    switch (format) {
      case AttestationFormat.none:
        log('✅ None attestation format - no verification required');
        break;
      case AttestationFormat.apple:
        this.verifyAppleAttestationStatement(attStmt, authData);
        break;
      default:
        log(`⚠️ ${format} attestation format not yet implemented`);
    }
  }

  // MARK: - Registration options

  generateRegistrationOptions(username, displayName = null, userIconUrl = '', enablePasskeys = true) {
    const challenge = this.generateChallenge();
    const userId = this.generateUserId();

    const rpData = { id: this.rpId, name: this.rpName ?? this.rpId };
    if (this.rpIcon !== null && this.rpIcon !== undefined) {
      if (this.rpIcon !== '') rpData.icon = this.rpIcon;
    } else {
      rpData.icon = `https://${this.rpId}/icon-192.png`;
    }

    const userData = { id: userId, name: username, displayName: displayName ?? username };
    if (userIconUrl) {
      userData.icon = userIconUrl;
    } else if (this.defaultUserIcon !== null && this.defaultUserIcon !== undefined) {
      if (this.defaultUserIcon !== '') userData.icon = this.defaultUserIcon;
    } else {
      userData.icon = this.generateUserIcon(username);
    }

    const pubKeyCredParams = [
      { type: 'public-key', alg: -7 },   // ES256
      { type: 'public-key', alg: -257 }, // RS256 (Windows Hello)
      { type: 'public-key', alg: -35 },  // ES384
      { type: 'public-key', alg: -36 },  // ES512
    ];

    const authenticatorSelection = enablePasskeys
      ? { authenticatorAttachment: 'platform', userVerification: 'required', requireResidentKey: true, residentKey: 'required' }
      : { authenticatorAttachment: 'cross-platform', userVerification: 'preferred', requireResidentKey: false, residentKey: 'discouraged' };

    const options = {
      publicKey: {
        challenge, rp: rpData, user: userData, pubKeyCredParams,
        timeout: 300000, attestation: 'none', authenticatorSelection,
      },
    };

    if (enablePasskeys) {
      options.publicKey.extensions = {
        largeBlob: { support: 'required' },
        credProtect: { credentialProtectionPolicy: 3, enforceCredentialProtectionPolicy: true },
        enterpriseAttestation: { rp: this.rpId },
      };
    }
    return options;
  }

  generateWindows11CompatibleRegistrationOptions(username, displayName = null) {
    return {
      publicKey: {
        challenge: this.generateChallenge(),
        rp: { id: this.rpId, name: this.rpName ?? this.rpId },
        user: { id: this.generateUserId(), name: username, displayName: displayName ?? username },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        timeout: 120000,
        attestation: 'none',
        authenticatorSelection: {
          authenticatorAttachment: 'platform', userVerification: 'preferred', requireResidentKey: false, residentKey: 'preferred',
        },
      },
    };
  }

  generateChromeCompatibleRegistrationOptions(username, displayName = null) {
    return {
      publicKey: {
        challenge: this.generateChallenge(),
        rp: { id: this.rpId, name: this.rpName ?? this.rpId },
        user: { id: this.generateUserId(), name: username, displayName: displayName ?? username },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: 60000,
        attestation: 'none',
      },
    };
  }

  generateLinuxCompatibleRegistrationOptions(username, displayName = null) {
    return {
      publicKey: {
        challenge: this.generateChallenge(),
        rp: { id: this.rpId, name: this.rpName ?? this.rpId },
        user: { id: this.generateUserId(), name: username, displayName: displayName ?? username },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }, { type: 'public-key', alg: -8 },
        ],
        timeout: 60000,
        attestation: 'none',
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform', userVerification: 'discouraged', requireResidentKey: false, residentKey: 'discouraged',
        },
      },
    };
  }

  generateHybridRegistrationOptions(username, displayName = null) {
    return {
      publicKey: {
        challenge: this.generateChallenge(),
        rp: { id: this.rpId, name: this.rpName ?? this.rpId },
        user: { id: this.generateUserId(), name: username, displayName: displayName ?? username },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }, { type: 'public-key', alg: -8 },
          { type: 'public-key', alg: -35 }, { type: 'public-key', alg: -36 },
        ],
        timeout: 300000,
        attestation: 'none',
        extensions: { credProps: true },
      },
    };
  }

  // Android registration with discoverable credentials for credential provider support
  generateAndroidRegistrationOptions(username, displayName = null) {
    return {
      publicKey: {
        challenge: this.generateChallenge(),
        rp: { id: this.rpId, name: this.rpName ?? this.rpId },
        user: { id: this.generateUserId(), name: username, displayName: displayName ?? username },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        timeout: 120000,
        attestation: 'none',
        authenticatorSelection: { userVerification: 'preferred', requireResidentKey: false, residentKey: 'preferred' },
      },
    };
  }

  generateLinuxSoftwareRegistrationOptions(username, displayName = null) {
    return {
      publicKey: {
        challenge: this.generateChallenge(),
        rp: { id: this.rpId, name: this.rpName ?? this.rpId },
        user: { id: this.generateUserId(), name: username, displayName: displayName ?? username },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        timeout: 60000,
        attestation: 'none',
        authenticatorSelection: { userVerification: 'discouraged' },
      },
    };
  }

  generateLinuxAutoRegistrationOptions(username, displayName = null, preferSoftware = false) {
    return preferSoftware
      ? this.generateLinuxSoftwareRegistrationOptions(username, displayName)
      : this.generateLinuxCompatibleRegistrationOptions(username, displayName);
  }

  generateUserIcon(username) {
    const encoded = encodeURI(username).replace(/#/g, '%23');
    return `https://ui-avatars.com/api/?name=${encoded}&background=007bff&color=white&size=64`;
  }

  // MARK: - Authentication options

  allowCredentialsFor(username, transports) {
    if (username) {
      const credential = this.getCredential(username);
      if (!credential) throw WebAuthnError.credentialNotFound();
      return [{ type: 'public-key', id: credential.id, transports }];
    }
    return []; // discoverable credentials
  }

  generateAuthenticationOptions(username) {
    return {
      publicKey: {
        challenge: this.generateChallenge(),
        timeout: 60000,
        rpId: this.rpId,
        allowCredentials: this.allowCredentialsFor(username, ['internal']),
        userVerification: 'preferred',
      },
    };
  }

  generateSecurityKeyAuthenticationOptions(username) {
    return {
      publicKey: {
        challenge: this.generateChallenge(),
        timeout: 120000,
        rpId: this.rpId,
        allowCredentials: this.allowCredentialsFor(username, ['usb', 'nfc', 'hybrid']),
        userVerification: 'discouraged',
        authenticatorSelection: { authenticatorAttachment: 'cross-platform', userVerification: 'discouraged' },
      },
    };
  }

  generateLinuxSoftwareAuthenticationOptions(username) {
    return {
      publicKey: {
        challenge: this.generateChallenge(),
        timeout: 60000,
        rpId: this.rpId,
        allowCredentials: this.allowCredentialsFor(username, ['internal']),
        userVerification: 'discouraged',
      },
    };
  }

  generateHybridAuthenticationOptions(username) {
    return {
      publicKey: {
        challenge: this.generateChallenge(),
        timeout: 300000,
        rpId: this.rpId,
        allowCredentials: this.allowCredentialsFor(username, ['internal', 'usb', 'nfc', 'ble', 'hybrid']),
        userVerification: 'discouraged',
      },
    };
  }

  base64urlToBase64(s) {
    let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const rem = b64.length % 4;
    if (rem > 0) b64 += '='.repeat(4 - rem);
    return b64;
  }

  // MARK: - Registration verification

  async verifyRegistration(username, credential, clientIP = null, isAdmin = false) {
    log(`🔍 verifyRegistration called for username: ${username} (IP: ${clientIP ?? 'unknown'})`);

    if (this.isUsernameRegistered(username)) {
      log(`❌ Username '${username}' already exists`);
      throw WebAuthnError.duplicateUsername();
    }

    const shouldBeAdmin = isAdmin || (this.adminUsername != null && username === this.adminUsername);
    const emoji = typeof credential.emoji === 'string' ? credential.emoji : '👤';

    if (typeof credential.id !== 'string') throw WebAuthnError.invalidCredential();
    const id = this.base64urlToBase64(credential.id);

    const response = credential.response;
    if (!response || typeof response !== 'object') throw WebAuthnError.invalidCredential();

    try {
      const r = await this.verifyFIDO2Registration(username, id, response, clientIP);
      this.storeCredential(makeCredential({
        id, publicKey: r.publicKey, signCount: 0, username, algorithm: r.algorithm,
        protocolVersion: 'fido2CBOR', attestationFormat: r.attestationFormat, aaguid: r.aaguid,
        isDiscoverable: r.isDiscoverable, backupEligible: r.backupEligible, backupState: r.backupState,
        emoji, lastLoginIP: clientIP, createdAt: new Date().toISOString(), isEnabled: true,
        isAdmin: shouldBeAdmin, userNumber: this.getNextUserNumber(),
      }));
      log('✅ FIDO2 registration successful');
    } catch (error) {
      log(`⚠️ FIDO2 verification failed: ${error.message}, trying U2F...`);
      const u2fPublicKey = this.verifyU2FRegistration(username, id, response, clientIP);
      this.storeCredential(makeCredential({
        id, publicKey: u2fPublicKey, signCount: 0, username, algorithm: -7, protocolVersion: 'u2fV1A',
        attestationFormat: 'none', aaguid: null, isDiscoverable: false, backupEligible: null, backupState: null,
        emoji, lastLoginIP: clientIP, createdAt: new Date().toISOString(), isEnabled: true,
        isAdmin: shouldBeAdmin, userNumber: this.getNextUserNumber(),
      }));
      log('✅ U2F registration successful');
    }
  }

  async verifyFIDO2Registration(username, id, response) {
    const attestationObjectString = response.attestationObject;
    const clientDataJSONString = response.clientDataJSON;
    if (typeof attestationObjectString !== 'string' || typeof clientDataJSONString !== 'string') {
      throw WebAuthnError.invalidCredential();
    }

    this.verifyClientData(clientDataJSONString, 'webauthn.create');

    const attestationObject = parseAttestationObject(attestationObjectString);

    const clientDataJSON = base64ToBytes(clientDataJSONString);
    if (!clientDataJSON) throw WebAuthnError.invalidCredential();
    const clientDataHash = await sha256(clientDataJSON);
    this.verifyAttestationStatement(attestationObject, clientDataHash);
    const { publicKey, algorithm, aaguid, backupEligible, backupState } = this.extractPublicKey(attestationObject);

    const attestationFormat = this.detectAttestationFormat(attestationObject, aaguid);
    log(`Successfully extracted public key for ${username} — AAGUID: ${aaguid}, Format: ${attestationFormat}`);
    return { publicKey, algorithm, aaguid, attestationFormat, isDiscoverable: true, backupEligible, backupState };
  }

  verifyU2FRegistration(username, id, response) {
    if (typeof response.registrationData !== 'string' || typeof response.clientData !== 'string') {
      log('MISSING U2F registration data');
      throw WebAuthnError.invalidCredential();
    }
    const regData = base64ToBytes(response.registrationData);
    if (!regData || regData.length < 67 || regData[0] !== 0x05) throw WebAuthnError.invalidCredential();
    return bytesToBase64(regData.subarray(1, 66));
  }

  // MARK: - Authentication verification

  async verifyAuthentication(username, credential, clientIP = null) {
    log(`verifyAuthentication called for username: ${username ?? 'nil'} (IP: ${clientIP ?? 'unknown'})`);

    if (typeof credential.id !== 'string') throw WebAuthnError.invalidCredential();
    const id = this.base64urlToBase64(credential.id);

    const usernameToUse = !username ? this.getUsernameByCredentialId(id) : username;
    if (!usernameToUse) {
      log(`No username found for credential ID: ${id}`);
      throw WebAuthnError.credentialNotFound();
    }

    if (!this.isUserEnabled(usernameToUse)) {
      log(`❌ Authentication rejected - user '${usernameToUse}' is disabled`);
      throw WebAuthnError.accessDenied();
    }

    const storedCredential = this.getCredential(usernameToUse);
    if (!storedCredential) throw WebAuthnError.credentialNotFound();

    const response = credential.response;
    if (!response || typeof response !== 'object') throw WebAuthnError.invalidCredential();

    const protocol = ['fido2CBOR', 'u2fV1A'].includes(storedCredential.protocolVersion)
      ? storedCredential.protocolVersion : this.webAuthnProtocol;
    if (protocol === 'u2fV1A') {
      await this.verifyU2FAuthentication(response, storedCredential, id, clientIP);
    } else {
      await this.verifyFIDO2Authentication(response, storedCredential, id, clientIP);
    }

    log(`Authentication successful for ${usernameToUse}`);
    return !username ? usernameToUse : null;
  }

  async verifyFIDO2Authentication(response, storedCredential, id, clientIP) {
    const { clientDataJSON, authenticatorData, signature } = response;
    if (typeof clientDataJSON !== 'string' || typeof authenticatorData !== 'string' || typeof signature !== 'string') {
      throw WebAuthnError.invalidCredential();
    }

    this.verifyClientData(clientDataJSON, 'webauthn.get');

    const authData = base64ToBytes(authenticatorData);
    if (!authData) throw WebAuthnError.invalidCredential();

    const newSignCount = this.extractAndValidateSignCount(authData, storedCredential);

    await this.verifySignature(authenticatorData, clientDataJSON, signature, storedCredential);

    if (id !== storedCredential.id) {
      log(`❌ Credential ID mismatch: ${id} != ${storedCredential.id}`);
      throw WebAuthnError.invalidCredential();
    }

    this.updateCredentialSignCount(storedCredential, newSignCount, clientIP);
  }

  extractAndValidateSignCount(authenticatorData, storedCredential) {
    if (authenticatorData.length < 37) throw WebAuthnError.invalidCredential();
    const view = new DataView(authenticatorData.buffer, authenticatorData.byteOffset, authenticatorData.byteLength);
    const newSignCount = view.getUint32(33, false);

    if (newSignCount === 0) {
      // Platform authenticators (Touch ID, Face ID, Windows Hello) report 0 — keep our own counter
      return (storedCredential.signCount + 1) >>> 0;
    }
    if (storedCredential.signCount > 0 && newSignCount <= storedCredential.signCount) {
      log(`Sign count validation failed: new=${newSignCount}, stored=${storedCredential.signCount}`);
      throw WebAuthnError.signCountInvalid();
    }
    return newSignCount;
  }

  updateCredentialSignCount(credential, newSignCount, clientIP = null) {
    const updated = makeCredential({
      ...credential, signCount: newSignCount, lastLoginIP: clientIP, lastLoginAt: new Date().toISOString(),
    });
    this.userManager.updateUserLogin(credential.username, newSignCount, clientIP);
    this.storeCredential(updated);
  }

  async verifyU2FAuthentication(response, storedCredential, id, clientIP) {
    if (typeof response.signatureData !== 'string' || typeof response.clientData !== 'string') {
      throw WebAuthnError.invalidCredential();
    }
    const sigData = base64ToBytes(response.signatureData);
    const clientDataBytes = base64ToBytes(response.clientData);
    if (!sigData || !clientDataBytes) throw WebAuthnError.invalidCredential();
    if (sigData.length < 5 || sigData[0] !== 0x01) throw WebAuthnError.invalidCredential();

    const newSignCount = new DataView(sigData.buffer, sigData.byteOffset).getUint32(1, false);
    if (storedCredential.signCount > 0 && newSignCount <= storedCredential.signCount) {
      throw WebAuthnError.signCountInvalid();
    }

    const signatureBytes = sigData.subarray(5);
    const applicationParameter = await sha256(utf8(this.rpId));
    const challengeParameter = await sha256(clientDataBytes);
    const signedData = concatBytes(applicationParameter, sigData.subarray(0, 5), challengeParameter);

    await this.verifyES256Signature(signedData, signatureBytes, storedCredential.publicKey);

    if (id !== storedCredential.id) throw WebAuthnError.invalidCredential();
    this.updateCredentialSignCount(storedCredential, newSignCount, clientIP);
  }

  // MARK: - Verification helpers

  verifyClientData(clientDataJSONString, type) {
    const bytes = base64ToBytes(clientDataJSONString);
    let clientData;
    try { clientData = JSON.parse(fromUtf8(bytes)); } catch { throw WebAuthnError.invalidCredential(); }
    if (!bytes || !clientData || typeof clientData !== 'object') throw WebAuthnError.invalidCredential();
    if (clientData.type !== type) throw WebAuthnError.invalidCredential();
    if (typeof clientData.origin !== 'string') throw WebAuthnError.invalidCredential();
    if (!this.isOriginValid(clientData.origin, this.rpId)) {
      log(`🚨 Origin mismatch: ${clientData.origin} not valid for RP ID: ${this.rpId}`);
      throw WebAuthnError.invalidCredential();
    }
  }

  isOriginValid(origin, rpId) {
    let url;
    try { url = new URL(origin); } catch { return false; }
    const scheme = url.protocol.replace(/:$/, '');
    const host = url.hostname;
    if (!scheme || !host) return false;
    const hostMatches = (rpId.toLowerCase() === 'localhost' && host.toLowerCase() === 'localhost')
      || host.toLowerCase() === rpId.toLowerCase();
    const schemeMatches = scheme === 'http' || scheme === 'https';
    return hostMatches && schemeMatches;
  }

  async verifySignature(authenticatorData, clientDataJSON, signature, storedCredential) {
    const authDataBytes = base64ToBytes(authenticatorData);
    const clientDataBytes = base64ToBytes(clientDataJSON);
    const signatureBytes = base64ToBytes(signature);
    if (!authDataBytes || !clientDataBytes || !signatureBytes) throw WebAuthnError.invalidCredential();

    const signedData = concatBytes(authDataBytes, await sha256(clientDataBytes));

    switch (storedCredential.algorithm) {
      case -7: return this.verifyES256Signature(signedData, signatureBytes, storedCredential.publicKey);
      case -257: return this.verifyRS256Signature(signedData, signatureBytes, storedCredential.publicKey);
      default: throw WebAuthnError.invalidCredential();
    }
  }

  async verifyES256Signature(signedData, signature, publicKey) {
    const publicKeyData = base64ToBytes(publicKey);
    if (!publicKeyData || publicKeyData.length !== 65 || publicKeyData[0] !== 0x04) {
      throw WebAuthnError.invalidCredential();
    }
    try {
      const key = await crypto.subtle.importKey('raw', publicKeyData, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      // Raw (r||s, 64 bytes) first, then DER — same order as Swift
      const raw = signature.length === 64 ? signature : derToRawSignature(signature);
      if (!raw) throw WebAuthnError.verificationFailed();
      const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, signedData);
      if (!ok) throw WebAuthnError.verificationFailed();
      log('✅ ES256 signature verification successful');
    } catch (error) {
      log(`ES256 signature verification failed: ${error.message}`);
      throw WebAuthnError.verificationFailed();
    }
  }

  async verifyRS256Signature(signedData, signature, publicKey) {
    let n, e;
    try {
      const dict = JSON.parse(fromUtf8(base64ToBytes(publicKey)));
      n = base64ToBytes(dict.n);
      e = base64ToBytes(dict.e);
    } catch { throw WebAuthnError.invalidCredential(); }
    if (!n || !e) throw WebAuthnError.invalidCredential();

    try {
      const key = await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', n: base64ToBase64url(bytesToBase64(n)), e: base64ToBase64url(bytesToBase64(e)), alg: 'RS256', ext: true },
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'],
      );
      const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signedData);
      if (!ok) throw WebAuthnError.verificationFailed();
      log('✅ RS256 signature verification successful');
    } catch (error) {
      log(`RS256 signature verification failed: ${error.message}`);
      throw WebAuthnError.verificationFailed();
    }
  }

  generateChallenge() { return bytesToBase64(randomBytes(32)); }
  generateUserId() { return bytesToBase64(randomBytes(16)); }

  // MARK: - User management

  isUsernameRegistered(username) { return this.getCredential(username) != null; }

  isUserEnabled(username) {
    const credential = this.getCredential(username);
    if (credential) return credential.isEnabled;
    return this.userManager.isUserEnabled(username);
  }

  isUserEnabledByCredential(credentialId) {
    return this.getCredentialByCredentialId(credentialId)?.isEnabled ?? false;
  }

  updateCredentialField(username, patch) {
    const credential = this.getCredential(username);
    if (!credential) return false;
    this.storeCredential(makeCredential({ ...credential, ...patch }));
    return true;
  }

  updateUserEmoji(username, emoji) { return this.updateCredentialField(username, { emoji }); }
  updateUserAdminStatus(username, isAdmin) { return this.updateCredentialField(username, { isAdmin }); }
  updateUserEnabledStatus(username, isEnabled) { return this.updateCredentialField(username, { isEnabled }); }

  getUserEmoji(username) {
    const credential = this.getCredential(username);
    if (credential) return credential.emoji ?? '👤';
    return '👤';
  }

  deleteUserCredentials(username) {
    this.userManager.deleteUser(username);
    this.credentials.delete(username);
    this.store.delete(username);
    log(`✅ Successfully deleted credentials for user: ${username}`);
  }

  getNextUserNumber() {
    const numbers = this.getAllUsers().map((u) => u.userNumber).filter((n) => n != null);
    return (numbers.length ? Math.max(...numbers) : 0) + 1;
  }

  migrateUserNumbers() {
    const all = this.getAllUsers();
    const without = all.filter((u) => u.userNumber == null);
    if (!without.length) return;
    without.sort((a, b) => new Date(a.createdAt ?? 0) - new Date(b.createdAt ?? 0));
    const existing = all.map((u) => u.userNumber).filter((n) => n != null);
    let next = (existing.length ? Math.max(...existing) : 0) + 1;
    for (const user of without) this.storeCredential(makeCredential({ ...user, userNumber: next++ }));
    log(`✅ User number migration complete: Assigned numbers to ${without.length} users`);
  }

  getAllUsers() { return Array.from(this.credentials.values()); }
  getCredential(username) { return this.credentials.get(username) ?? null; }
  getCredentialByCredentialId(credentialId) {
    return this.getAllUsers().find((c) => c.id === credentialId) ?? null;
  }
  getUsernameByCredentialId(credentialId) { return this.getCredentialByCredentialId(credentialId)?.username ?? null; }

  storeCredential(credential) {
    this.credentials.set(credential.username, credential);
    this.store.put(credential);
  }
}

/** Convert an ASN.1 DER ECDSA signature to the 64-byte r||s form WebCrypto expects. */
export function derToRawSignature(der) {
  let o = 0;
  if (der[o++] !== 0x30) return null;
  let len = der[o++];
  if (len & 0x80) o += len & 0x7f;
  const readInt = () => {
    if (der[o++] !== 0x02) return null;
    const l = der[o++];
    let v = der.slice(o, o + l);
    o += l;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) return null;
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  return r && s ? concatBytes(r, s) : null;
}

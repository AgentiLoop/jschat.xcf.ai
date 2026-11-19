// Port of DogTagKit/WebAuthnTypes.swift

/** AttestationFormat */
export const AttestationFormat = {
  none: 'none',
  packed: 'packed',
  tpm: 'tpm',
  androidKey: 'android-key',
  androidSafetynet: 'android-safetynet',
  fido_u2f: 'fido-u2f',
  apple: 'apple',
};

/** AttestationFormat.supportedAAGUIDs */
export const supportedAAGUIDs = {
  apple: [
    '00000000-0000-0000-0000-000000000000', // Apple Face ID
    'ADCE0002-35BC-C60A-648B-0B25F1F05503', // Apple Touch ID
  ],
  tpm: ['08987058-CADC-4B81-B6E1-30DE50DCBE96'], // Windows Hello TPM
  'android-key': ['B93FD961-F2E6-462F-B122-82002247DE78'], // Android Key Attestation
};

const ERROR_DESCRIPTIONS = {
  credentialNotFound: 'Credential not found',
  invalidCredential: 'Invalid credential data',
  verificationFailed: 'Credential verification failed',
  duplicateUsername: 'Username already exists',
  signCountInvalid: 'Invalid signature counter',
  accessDenied: 'Access denied',
  unsupportedProtocol: 'Unsupported WebAuthn protocol',
  storageError: 'Storage operation failed',
  networkError: 'Network request failed',
  userCancelled: 'User cancelled operation',
  timeoutExpired: 'Operation timed out',
};

/** WebAuthnError — `message` mirrors Swift's localizedDescription */
export class WebAuthnError extends Error {
  constructor(code) {
    super(ERROR_DESCRIPTIONS[code] ?? code);
    this.code = code;
  }
  static credentialNotFound() { return new WebAuthnError('credentialNotFound'); }
  static invalidCredential() { return new WebAuthnError('invalidCredential'); }
  static verificationFailed() { return new WebAuthnError('verificationFailed'); }
  static duplicateUsername() { return new WebAuthnError('duplicateUsername'); }
  static signCountInvalid() { return new WebAuthnError('signCountInvalid'); }
  static accessDenied() { return new WebAuthnError('accessDenied'); }
}

/**
 * WebAuthnCredential (enhanced initializer). Dates are ISO-8601 strings.
 * Fields: id, publicKey, signCount, username, algorithm, protocolVersion, attestationFormat,
 * aaguid, isDiscoverable, backupEligible, backupState, emoji, lastLoginIP, lastLoginAt,
 * createdAt, isEnabled, isAdmin, userNumber
 */
export function makeCredential(c) {
  return {
    id: c.id,
    publicKey: c.publicKey,
    signCount: c.signCount >>> 0,
    username: c.username,
    algorithm: c.algorithm,
    protocolVersion: c.protocolVersion,
    attestationFormat: c.attestationFormat ?? 'none',
    aaguid: c.aaguid ?? null,
    isDiscoverable: c.isDiscoverable ?? false,
    backupEligible: c.backupEligible ?? null,
    backupState: c.backupState ?? null,
    emoji: c.emoji ?? null,
    lastLoginIP: c.lastLoginIP ?? null,
    lastLoginAt: c.lastLoginAt ?? null,
    createdAt: c.createdAt ?? new Date().toISOString(),
    isEnabled: c.isEnabled ?? true,
    isAdmin: c.isAdmin ?? false,
    userNumber: c.userNumber ?? null,
  };
}

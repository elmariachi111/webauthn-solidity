/**
 * WebAuthn utility functions for encoding, decoding, and parsing
 */

/**
 * Convert Uint8Array to hex string
 */
export function bufferToHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToBuffer(hex: string): Uint8Array {
  const cleaned = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert base64url string to Uint8Array
 */
export function base64UrlToBuffer(base64url: string): Uint8Array {
  // Add padding if needed
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const padded = base64 + padding;

  // Decode base64
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert Uint8Array to base64url string
 */
export function bufferToBase64Url(buffer: Uint8Array): string {
  // Convert to base64
  const binary = String.fromCharCode(...Array.from(buffer));
  const base64 = btoa(binary);

  // Convert to base64url
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate a cryptographically secure random challenge
 */
export function generateChallenge(length: number = 32): Uint8Array {
  const buffer = new Uint8Array(length);
  crypto.getRandomValues(buffer);
  return buffer;
}

/**
 * Parse authenticator data structure
 */
export interface ParsedAuthenticatorData {
  rpIdHash: Uint8Array;
  flags: {
    userPresent: boolean;
    userVerified: boolean;
    backupEligible: boolean;
    backupState: boolean;
    attestedCredentialData: boolean;
    extensionDataIncluded: boolean;
  };
  signCount: number;
  attestedCredentialData?: {
    aaguid: Uint8Array;
    credentialIdLength: number;
    credentialId: Uint8Array;
    credentialPublicKey: Uint8Array;
  };
}

/**
 * Parse authenticator data from WebAuthn response
 */
export function parseAuthenticatorData(authData: Uint8Array): ParsedAuthenticatorData {
  let offset = 0;

  // RP ID hash (32 bytes)
  const rpIdHash = authData.slice(offset, offset + 32);
  offset += 32;

  // Flags (1 byte)
  const flagsByte = authData[offset];
  const flags = {
    userPresent: !!(flagsByte & 0x01),
    userVerified: !!(flagsByte & 0x04),
    backupEligible: !!(flagsByte & 0x08),
    backupState: !!(flagsByte & 0x10),
    attestedCredentialData: !!(flagsByte & 0x40),
    extensionDataIncluded: !!(flagsByte & 0x80),
  };
  offset += 1;

  // Signature counter (4 bytes)
  const signCount = new DataView(authData.buffer, authData.byteOffset + offset, 4).getUint32(0, false);
  offset += 4;

  // Attested credential data (only present during registration)
  let attestedCredentialData;
  if (flags.attestedCredentialData) {
    const aaguid = authData.slice(offset, offset + 16);
    offset += 16;

    const credentialIdLength = new DataView(authData.buffer, authData.byteOffset + offset, 2).getUint16(0, false);
    offset += 2;

    const credentialId = authData.slice(offset, offset + credentialIdLength);
    offset += credentialIdLength;

    // Remaining data is the credential public key (COSE format)
    const credentialPublicKey = authData.slice(offset);

    attestedCredentialData = {
      aaguid,
      credentialIdLength,
      credentialId,
      credentialPublicKey,
    };
  }

  return {
    rpIdHash,
    flags,
    signCount,
    attestedCredentialData,
  };
}

/**
 * Find the offset of the challenge in clientDataJSON
 */
export function findChallengeOffset(clientDataJSON: string, challenge: Uint8Array): number {
  const challengeBase64Url = bufferToBase64Url(challenge);
  const offset = clientDataJSON.indexOf(challengeBase64Url);
  if (offset === -1) {
    throw new Error('Challenge not found in clientDataJSON');
  }
  return offset;
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatUint8Arrays(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

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

/**
 * P-256 public key encoding utilities
 *
 * Note: P-256 keys are NOT Ethereum addresses. These are secp256r1 keys
 * used for WebAuthn/passkey authentication, encoded for display and storage.
 */

/**
 * Derive a unique identifier from P-256 public key coordinates using base64 encoding
 *
 * This creates a compact, URL-safe identifier for the public key by encoding
 * the uncompressed public key format (0x04 || x || y) as base64.
 */
export function publicKeyToIdentifier(x: Uint8Array, y: Uint8Array): string {
  // Ensure coordinates are 32 bytes each
  if (x.length !== 32 || y.length !== 32) {
    throw new Error('Public key coordinates must be 32 bytes each');
  }

  // Create uncompressed public key (0x04 || x || y)
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);

  // Encode as base64 for compact, human-readable representation
  return btoa(String.fromCharCode(...uncompressed));
}

/**
 * Convert public key to hex format (for debugging/display)
 */
export function publicKeyToHex(x: Uint8Array, y: Uint8Array): string {
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);

  return Array.from(uncompressed)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Format public key coordinates for display
 */
export function formatPublicKey(x: Uint8Array, y: Uint8Array): {
  x: string;
  y: string;
  uncompressed: string;
} {
  // Encode coordinates as base64 for cleaner display
  const xBase64 = btoa(String.fromCharCode(...x));
  const yBase64 = btoa(String.fromCharCode(...y));

  return {
    x: xBase64,
    y: yBase64,
    uncompressed: publicKeyToIdentifier(x, y),
  };
}

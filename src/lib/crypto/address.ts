/**
 * Ethereum address derivation from P-256 public keys
 */

import { getAddress, keccak256 } from 'viem';

/**
 * Derive Ethereum address from P-256 public key coordinates
 *
 * Process:
 * 1. Concatenate x and y coordinates (uncompressed format: 0x04 || x || y)
 * 2. Hash with Keccak-256
 * 3. Take last 20 bytes as Ethereum address
 * 4. Apply EIP-55 checksum
 */
export function publicKeyToAddress(x: Uint8Array, y: Uint8Array): string {
  // Ensure coordinates are 32 bytes each
  if (x.length !== 32 || y.length !== 32) {
    throw new Error('Public key coordinates must be 32 bytes each');
  }

  // Create uncompressed public key (0x04 || x || y)
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);

  // Hash with Keccak-256
  const hash = keccak256(uncompressed);

  // Take last 20 bytes (40 hex chars) as address
  const address = '0x' + hash.slice(-40);

  // Apply EIP-55 checksum and return
  return getAddress(address);
}

/**
 * Convert public key to uncompressed hex format
 */
export function publicKeyToHex(x: Uint8Array, y: Uint8Array): string {
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);

  return '0x' + Array.from(uncompressed)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Format public key for display
 */
export function formatPublicKey(x: Uint8Array, y: Uint8Array): {
  x: string;
  y: string;
  uncompressed: string;
} {
  const xHex = '0x' + Array.from(x).map(b => b.toString(16).padStart(2, '0')).join('');
  const yHex = '0x' + Array.from(y).map(b => b.toString(16).padStart(2, '0')).join('');

  return {
    x: xHex,
    y: yHex,
    uncompressed: publicKeyToHex(x, y),
  };
}

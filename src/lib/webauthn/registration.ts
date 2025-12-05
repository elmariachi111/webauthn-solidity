/**
 * WebAuthn passkey registration (wallet creation)
 */

import { startRegistration } from '@simplewebauthn/browser';
import type { P256PublicKey, PasskeyCreationResult, WebAuthnErrorType } from '../types';
import { WebAuthnError } from '../types';
import { base64UrlToBuffer, bufferToBase64Url, generateChallenge, parseAuthenticatorData } from './utils';

/**
 * Parse COSE public key to extract P-256 coordinates
 * COSE format: https://www.iana.org/assignments/cose/cose.xhtml
 */
function parseCOSEPublicKey(coseKey: Uint8Array): P256PublicKey {
  // Parse CBOR-encoded COSE key
  // For P-256, we're looking for:
  // - kty (1): 2 (EC2)
  // - alg (3): -7 (ES256)
  // - crv (-1): 1 (P-256)
  // - x (-2): x coordinate (32 bytes)
  // - y (-3): y coordinate (32 bytes)

  const dataView = new DataView(coseKey.buffer, coseKey.byteOffset, coseKey.byteLength);
  let offset = 0;

  // Simple CBOR parser for COSE key structure
  // This is a simplified version - for production, use a proper CBOR library

  // Skip initial map header (0xa5 = map with 5 elements or 0xa4 = 4 elements)
  if (coseKey[offset] === 0xa5 || coseKey[offset] === 0xa4) {
    offset++;
  } else {
    throw new Error('Invalid COSE key format');
  }

  let x: Uint8Array | null = null;
  let y: Uint8Array | null = null;

  // Parse key-value pairs
  while (offset < coseKey.length && (!x || !y)) {
    // Read key
    const keyByte = coseKey[offset];

    if (keyByte === 0x01 || keyByte === 0x03) {
      // kty or alg - skip
      offset++;
      offset++; // skip value
    } else if (keyByte === 0x20) {
      // -1 (crv) as positive integer
      offset++;
      offset++; // skip value (should be 1 for P-256)
    } else if (keyByte === 0x21) {
      // -2 (x coordinate) as positive integer
      offset++;
      // Next byte should be 0x58 0x20 (byte string of length 32)
      if (coseKey[offset] === 0x58 && coseKey[offset + 1] === 0x20) {
        offset += 2;
        x = coseKey.slice(offset, offset + 32);
        offset += 32;
      } else {
        throw new Error('Invalid x coordinate format');
      }
    } else if (keyByte === 0x22) {
      // -3 (y coordinate) as positive integer
      offset++;
      // Next byte should be 0x58 0x20 (byte string of length 32)
      if (coseKey[offset] === 0x58 && coseKey[offset + 1] === 0x20) {
        offset += 2;
        y = coseKey.slice(offset, offset + 32);
        offset += 32;
      } else {
        throw new Error('Invalid y coordinate format');
      }
    } else {
      offset++;
    }
  }

  if (!x || !y) {
    throw new Error('Failed to extract P-256 coordinates from COSE key');
  }

  return { x, y };
}

/**
 * Extract public key from WebAuthn credential
 */
export function extractPublicKey(credential: PublicKeyCredential): P256PublicKey {
  const response = credential.response as AuthenticatorAttestationResponse;

  // Get attestation object
  const attestationObject = new Uint8Array(response.attestationObject);

  // Parse authenticator data
  const parsedAuthData = parseAuthenticatorData(attestationObject);

  if (!parsedAuthData.attestedCredentialData) {
    throw new Error('No attested credential data in authenticator response');
  }

  // Parse COSE public key
  const publicKey = parseCOSEPublicKey(parsedAuthData.attestedCredentialData.credentialPublicKey);

  return publicKey;
}

/**
 * Create a new passkey credential
 */
export async function createPasskey(
  username: string,
  displayName: string
): Promise<PasskeyCreationResult> {
  try {
    // Check if WebAuthn is supported
    if (!window.PublicKeyCredential) {
      throw new WebAuthnError(
        'NOT_SUPPORTED' as WebAuthnErrorType,
        'WebAuthn is not supported in this browser'
      );
    }

    // Check if platform authenticator is available
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!available) {
      throw new WebAuthnError(
        'NOT_SUPPORTED' as WebAuthnErrorType,
        'No platform authenticator available on this device'
      );
    }

    // Generate challenge
    const challenge = generateChallenge(32);

    // Create credential options
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: challenge as BufferSource,
        rp: {
          name: 'Passkey Wallet',
          id: typeof window !== 'undefined' ? window.location.hostname : 'localhost',
        },
        user: {
          id: new TextEncoder().encode(username) as BufferSource,
          name: username,
          displayName: displayName || username,
        },
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7, // ES256 (P-256)
          },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'required',
        },
        timeout: 60000,
        attestation: 'none',
      },
    }) as PublicKeyCredential | null;

    if (!credential) {
      throw new WebAuthnError(
        'USER_CANCELLED' as WebAuthnErrorType,
        'Credential creation was cancelled or failed'
      );
    }

    // Extract public key using simplewebauthn helper
    const response = credential.response as AuthenticatorAttestationResponse;
    const attestationObject = new Uint8Array(response.attestationObject);

    // Parse authenticator data to get public key
    const authData = parseAuthenticatorData(attestationObject);

    if (!authData.attestedCredentialData) {
      throw new Error('No credential data in attestation');
    }

    const publicKey = parseCOSEPublicKey(authData.attestedCredentialData.credentialPublicKey);

    // Import crypto utilities for address derivation
    const { publicKeyToAddress } = await import('../crypto/address');
    const address = publicKeyToAddress(publicKey.x, publicKey.y);

    return {
      credentialId: bufferToBase64Url(new Uint8Array(credential.rawId)),
      publicKey,
      address,
    };
  } catch (error) {
    if (error instanceof WebAuthnError) {
      throw error;
    }

    if (error instanceof Error) {
      if (error.name === 'NotAllowedError') {
        throw new WebAuthnError(
          'USER_CANCELLED' as WebAuthnErrorType,
          'User cancelled the credential creation',
          error
        );
      }
      if (error.name === 'NotSupportedError') {
        throw new WebAuthnError(
          'NOT_SUPPORTED' as WebAuthnErrorType,
          'WebAuthn operation not supported',
          error
        );
      }
      if (error.name === 'TimeoutError') {
        throw new WebAuthnError(
          'TIMEOUT' as WebAuthnErrorType,
          'Credential creation timed out',
          error
        );
      }
    }

    throw new WebAuthnError(
      'UNKNOWN' as WebAuthnErrorType,
      `Failed to create passkey: ${error instanceof Error ? error.message : 'Unknown error'}`,
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Check if WebAuthn is supported
 */
export function isWebAuthnSupported(): boolean {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window;
}

/**
 * Check if platform authenticator is available
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) {
    return false;
  }

  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/**
 * WebAuthn passkey registration (wallet creation)
 */

import { decode } from 'cbor-x';
import type { P256PublicKey, PasskeyCreationResult, WebAuthnErrorType } from '../types';
import { WebAuthnError } from '../types';
import { bufferToBase64Url, generateChallenge } from './utils';

/**
 * Parse public key from attestation object using proper CBOR decoding
 */
function parsePublicKeyFromAttestation(attestationObject: ArrayBuffer): P256PublicKey {
  // Decode CBOR attestation object
  const attestation = decode(new Uint8Array(attestationObject));

  // Extract the authData
  const authData = attestation.authData;

  // The credential public key starts after:
  // - rpIdHash: 32 bytes
  // - flags: 1 byte
  // - signCount: 4 bytes
  // - aaguid: 16 bytes
  // - credentialIdLength: 2 bytes
  // - credentialId: credentialIdLength bytes

  let offset = 32 + 1 + 4 + 16;

  // Read credential ID length (big-endian uint16)
  const credentialIdLength = (authData[offset] << 8) | authData[offset + 1];
  offset += 2 + credentialIdLength;

  // The rest is the COSE key (CBOR-encoded)
  const coseKeyBytes = authData.slice(offset);
  const coseKey = decode(coseKeyBytes);

  // COSE key format for P-256:
  // {
  //   1: 2,        // kty: EC2
  //   3: -7,       // alg: ES256
  //   -1: 1,       // crv: P-256
  //   -2: x,       // x coordinate (32 bytes)
  //   -3: y        // y coordinate (32 bytes)
  // }

  let x: Uint8Array, y: Uint8Array;

  if (coseKey instanceof Map) {
    x = coseKey.get(-2);
    y = coseKey.get(-3);
  } else if (typeof coseKey === 'object') {
    x = coseKey[-2] || coseKey['-2'];
    y = coseKey[-3] || coseKey['-3'];
  } else {
    throw new Error('Invalid COSE key format');
  }

  if (!x || !y) {
    throw new Error('Failed to extract P-256 coordinates from COSE key');
  }

  return { x: new Uint8Array(x), y: new Uint8Array(y) };
}

/**
 * Authenticate with an existing passkey (for returning users)
 * This uses the browser's native passkey picker to select from available passkeys
 */
export async function authenticateWithPasskey(): Promise<PasskeyCreationResult> {
  try {
    // Check if WebAuthn is supported
    if (!window.PublicKeyCredential) {
      throw new WebAuthnError(
        'NOT_SUPPORTED' as WebAuthnErrorType,
        'WebAuthn is not supported in this browser'
      );
    }

    // Generate a challenge for authentication
    const challenge = generateChallenge(32);

    // Get credential - WITHOUT allowCredentials to show native picker
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: challenge as BufferSource,
        rpId: typeof window !== 'undefined' ? window.location.hostname : 'localhost',
        userVerification: 'required',
        timeout: 60000,
      },
    }) as PublicKeyCredential | null;

    if (!assertion) {
      throw new WebAuthnError(
        'USER_CANCELLED' as WebAuthnErrorType,
        'Authentication was cancelled or failed'
      );
    }

    // For authentication, we need to get the public key from the stored credential
    // Since we can't extract it from the assertion, we'll need to look it up

    // Use assertion.id (already base64url encoded) to match what we stored
    // Note: assertion.id is the base64url-encoded version of assertion.rawId
    return {
      credentialId: assertion.id,
      publicKey: { x: new Uint8Array(0), y: new Uint8Array(0) }, // Placeholder - will be filled from storage
      address: '', // Will be filled from storage
    };
  } catch (error) {
    if (error instanceof WebAuthnError) {
      throw error;
    }

    if (error instanceof Error) {
      if (error.name === 'NotAllowedError') {
        throw new WebAuthnError(
          'USER_CANCELLED' as WebAuthnErrorType,
          'User cancelled the authentication',
          error
        );
      }
    }

    throw new WebAuthnError(
      'UNKNOWN' as WebAuthnErrorType,
      `Failed to authenticate with passkey: ${error instanceof Error ? error.message : 'Unknown error'}`,
      error instanceof Error ? error : undefined
    );
  }
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
            alg: -7, // ES256 (P-256) - Primary algorithm
          },
          {
            type: 'public-key',
            alg: -257, // RS256 - Included for compatibility
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

    // Extract public key from attestation object
    const response = credential.response as AuthenticatorAttestationResponse;
    const publicKey = parsePublicKeyFromAttestation(response.attestationObject);

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

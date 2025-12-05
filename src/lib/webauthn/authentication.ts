/**
 * WebAuthn passkey authentication (signing)
 */

import type { WebAuthnSignature, WebAuthnErrorType } from '../types';
import { WebAuthnError } from '../types';
import { base64UrlToBuffer, bufferToBase64Url, findChallengeOffset } from './utils';

/**
 * Pad byte array to 32 bytes
 */
function padTo32Bytes(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 32) {
    return bytes;
  }

  if (bytes.length > 32) {
    // Should not happen for P-256, but handle it
    return bytes.slice(bytes.length - 32);
  }

  // Pad with leading zeros
  const padded = new Uint8Array(32);
  padded.set(bytes, 32 - bytes.length);
  return padded;
}

/**
 * Parse DER-encoded signature to extract r and s values with malleability normalization
 * DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
 */
function parseDERSignature(derSig: Uint8Array): { r: Uint8Array; s: Uint8Array } {
  let offset = 0;

  // Check sequence tag (0x30)
  if (derSig[offset] !== 0x30) {
    throw new Error('Invalid DER signature: missing sequence tag');
  }
  offset++;

  // Skip total length
  offset++;

  // Parse r value
  if (derSig[offset] !== 0x02) {
    throw new Error('Invalid DER signature: missing r integer tag');
  }
  offset++;

  let rLength = derSig[offset];
  offset++;

  // Extract r (skip leading zero if present)
  let rOffset = offset;
  if (derSig[rOffset] === 0x00) {
    rOffset++;
    rLength--;
  }

  const r = derSig.slice(rOffset, rOffset + rLength);
  offset = rOffset + rLength;

  // Parse s value
  if (derSig[offset] !== 0x02) {
    throw new Error('Invalid DER signature: missing s integer tag');
  }
  offset++;

  let sLength = derSig[offset];
  offset++;

  // Extract s (skip leading zero if present)
  let sOffset = offset;
  if (derSig[sOffset] === 0x00) {
    sOffset++;
    sLength--;
  }

  const s = derSig.slice(sOffset, sOffset + sLength);

  // Pad to 32 bytes if needed
  const rPadded = padTo32Bytes(r);
  let sPadded = padTo32Bytes(s);

  // Normalize s to prevent signature malleability
  // If s > N/2, replace with N - s
  // secp256r1 curve order N
  const N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
  const N_half = N / 2n;

  const sBigInt = BigInt('0x' + Array.from(sPadded).map(b => b.toString(16).padStart(2, '0')).join(''));

  if (sBigInt > N_half) {
    const sNormalized = N - sBigInt;
    const sNormalizedHex = sNormalized.toString(16).padStart(64, '0');
    sPadded = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      sPadded[i] = parseInt(sNormalizedHex.slice(i * 2, i * 2 + 2), 16);
    }
  }

  return { r: rPadded, s: sPadded };
}

/**
 * Sign data with a passkey
 */
export async function signWithPasskey(
  challenge: Uint8Array,
  credentialId: string
): Promise<WebAuthnSignature> {
  try {
    // Convert credential ID to buffer
    const credentialIdBuffer = base64UrlToBuffer(credentialId);

    // Request authentication
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: challenge as BufferSource,
        rpId: typeof window !== 'undefined' ? window.location.hostname : 'localhost',
        allowCredentials: [
          {
            id: credentialIdBuffer as BufferSource,
            type: 'public-key',
          },
        ],
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

    const response = assertion.response as AuthenticatorAssertionResponse;

    // Extract signature components
    const signature = new Uint8Array(response.signature);
    const { r, s } = parseDERSignature(signature);

    // Extract authenticator data
    const authenticatorData = new Uint8Array(response.authenticatorData);

    // Extract client data JSON
    const clientDataJSON = new TextDecoder().decode(response.clientDataJSON);

    // Find challenge offset in clientDataJSON
    const challengeOffset = findChallengeOffset(clientDataJSON, challenge);

    return {
      r,
      s,
      authenticatorData,
      clientDataJSON,
      challengeOffset,
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
          'Authentication timed out',
          error
        );
      }
    }

    throw new WebAuthnError(
      'UNKNOWN' as WebAuthnErrorType,
      `Failed to sign with passkey: ${error instanceof Error ? error.message : 'Unknown error'}`,
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Format signature for blockchain verification
 */
export function formatSignatureForChain(signature: WebAuthnSignature): {
  r: string;
  s: string;
  authenticatorData: string;
  clientDataJSON: string;
  challengeOffset: number;
} {
  return {
    r: '0x' + Array.from(signature.r).map(b => b.toString(16).padStart(2, '0')).join(''),
    s: '0x' + Array.from(signature.s).map(b => b.toString(16).padStart(2, '0')).join(''),
    authenticatorData: '0x' + Array.from(signature.authenticatorData).map(b => b.toString(16).padStart(2, '0')).join(''),
    clientDataJSON: signature.clientDataJSON,
    challengeOffset: signature.challengeOffset,
  };
}

/**
 * Sign a message with passkey
 */
export async function signMessage(
  message: string,
  credentialId: string
): Promise<WebAuthnSignature> {
  // Hash the message to use as challenge
  const encoder = new TextEncoder();
  const data = encoder.encode(message);

  // Use message hash as challenge
  const challenge = await crypto.subtle.digest('SHA-256', data);

  return signWithPasskey(new Uint8Array(challenge), credentialId);
}

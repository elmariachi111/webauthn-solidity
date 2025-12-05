/**
 * WebAuthn passkey authentication (signing)
 */

import type { WebAuthnSignature, WebAuthnErrorType } from '../types';
import { WebAuthnError } from '../types';
import { base64UrlToBuffer, bufferToBase64Url, findChallengeOffset } from './utils';

/**
 * Parse DER-encoded signature to extract r and s values
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
  const totalLength = derSig[offset];
  offset++;

  // Parse r value
  if (derSig[offset] !== 0x02) {
    throw new Error('Invalid DER signature: missing r integer tag');
  }
  offset++;

  const rLength = derSig[offset];
  offset++;

  let r = derSig.slice(offset, offset + rLength);
  offset += rLength;

  // Remove leading zero if present (added for sign bit)
  if (r.length === 33 && r[0] === 0x00) {
    r = r.slice(1);
  }

  // Pad to 32 bytes if needed
  if (r.length < 32) {
    const padded = new Uint8Array(32);
    padded.set(r, 32 - r.length);
    r = padded;
  }

  // Parse s value
  if (derSig[offset] !== 0x02) {
    throw new Error('Invalid DER signature: missing s integer tag');
  }
  offset++;

  const sLength = derSig[offset];
  offset++;

  let s = derSig.slice(offset, offset + sLength);

  // Remove leading zero if present
  if (s.length === 33 && s[0] === 0x00) {
    s = s.slice(1);
  }

  // Pad to 32 bytes if needed
  if (s.length < 32) {
    const padded = new Uint8Array(32);
    padded.set(s, 32 - s.length);
    s = padded;
  }

  return { r, s };
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

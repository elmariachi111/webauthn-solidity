/**
 * WebAuthn passkey authentication (signing)
 */

import { keccak256, toBytes } from 'viem';
import type { WebAuthnSignature, WebAuthnErrorType } from '../types';
import { WebAuthnError } from '../types';
import { base64UrlToBuffer, findChallengeOffset } from './utils';

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
function parseDERSignature(derSig: Uint8Array, normalize: boolean = true): { r: Uint8Array; s: Uint8Array } {
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
    const credentialIdBuffer = base64UrlToBuffer(credentialId);

    // Request user authentication to sign the challenge with their passkey
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

    // Parse DER-encoded signature and normalize s-value to prevent malleability
    const signature = new Uint8Array(response.signature);
    const { r, s } = parseDERSignature(signature, true);

    const authenticatorData = new Uint8Array(response.authenticatorData);

    // Store both raw bytes and string representation of client data JSON
    // Raw bytes are preferred for verification to avoid encoding inconsistencies
    const clientDataJSONBytes = new Uint8Array(response.clientDataJSON);
    const clientDataJSON = new TextDecoder().decode(clientDataJSONBytes);

    // Calculate challenge offset for efficient on-chain verification
    const challengeOffset = findChallengeOffset(clientDataJSON, challenge);

    return {
      r,
      s,
      authenticatorData,
      clientDataJSON,
      clientDataJSONBytes,
      challengeOffset,
      originalDER: signature,
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
 * Convert r and s values to DER-encoded signature
 */
function toDERSignature(r: Uint8Array, s: Uint8Array): Uint8Array {
  // Helper to encode an integer in DER format
  const encodeInteger = (value: Uint8Array): Uint8Array => {
    // Remove leading zeros, but keep one if the value would be negative (high bit set)
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) {
      start++;
    }
    const trimmed = value.slice(start);

    // Add leading zero if high bit is set (to keep it positive)
    const needsPadding = trimmed[0] >= 0x80;
    const length = trimmed.length + (needsPadding ? 1 : 0);

    const result = new Uint8Array(2 + length);
    result[0] = 0x02; // INTEGER tag
    result[1] = length;
    if (needsPadding) {
      result[2] = 0x00;
      result.set(trimmed, 3);
    } else {
      result.set(trimmed, 2);
    }

    return result;
  };

  const rEncoded = encodeInteger(r);
  const sEncoded = encodeInteger(s);

  // SEQUENCE tag + length + r + s
  const totalLength = rEncoded.length + sEncoded.length;
  const result = new Uint8Array(2 + totalLength);
  result[0] = 0x30; // SEQUENCE tag
  result[1] = totalLength;
  result.set(rEncoded, 2);
  result.set(sEncoded, 2 + rEncoded.length);

  return result;
}

/**
 * Verify a WebAuthn P-256 signature
 */
export async function verifySignature(
  message: string,
  signature: { r: Uint8Array; s: Uint8Array; authenticatorData: Uint8Array; clientDataJSON: string; clientDataJSONBytes?: Uint8Array; originalDER?: Uint8Array },
  publicKey: { x: Uint8Array; y: Uint8Array }
): Promise<boolean> {
  try {
    const encoder = new TextEncoder();

    // Prefer raw bytes if available to avoid encoding issues during string round-trip
    const clientDataJSONBytes = signature.clientDataJSONBytes || encoder.encode(signature.clientDataJSON);

    // Hash the client data JSON as per WebAuthn spec
    const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSONBytes as BufferSource);

    // WebAuthn signatures are computed over: authenticatorData || SHA-256(clientDataJSON)
    // This is what the authenticator actually signed
    const signedData = new Uint8Array(signature.authenticatorData.length + clientDataHash.byteLength);
    signedData.set(signature.authenticatorData, 0);
    signedData.set(new Uint8Array(clientDataHash), signature.authenticatorData.length);

    // Import the P-256 public key in uncompressed point format: 0x04 || x || y
    const publicKeyBytes = new Uint8Array(65);
    publicKeyBytes[0] = 0x04; // Uncompressed point indicator
    publicKeyBytes.set(publicKey.x, 1);
    publicKeyBytes.set(publicKey.y, 33);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false,
      ['verify']
    );

    // Convert signature to raw format (r||s) as required by Web Crypto API
    // WebAuthn returns DER-encoded signatures, but crypto.subtle.verify expects IEEE P1363 format
    // For P-256: exactly 64 bytes (32 bytes r + 32 bytes s)
    const rawSignature = new Uint8Array(64);
    rawSignature.set(signature.r, 0);
    rawSignature.set(signature.s, 32);

    // Verify the signature
    // crypto.subtle.verify will hash signedData with SHA-256 before verifying
    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      cryptoKey,
      rawSignature as BufferSource,
      signedData
    );

    return isValid;
  } catch (error) {
    console.error('Signature verification failed with error:', error);
    return false;
  }
}

/**
 * Sign a message with passkey
 */
export async function signMessage(
  message: string,
  credentialId: string
): Promise<WebAuthnSignature> {
  // Hash the message with keccak256 to use as challenge (EVM-compatible)
  const messageHash = keccak256(toBytes(message));

  // Convert hex string to Uint8Array (remove '0x' prefix)
  const challenge = new Uint8Array(
    messageHash.slice(2).match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
  );

  return signWithPasskey(challenge, credentialId);
}

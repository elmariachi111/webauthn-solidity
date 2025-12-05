/**
 * WebAuthn passkey authentication (signing)
 */

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
    const { r, s } = parseDERSignature(signature, true);

    // Extract authenticator data
    const authenticatorData = new Uint8Array(response.authenticatorData);

    // Extract client data JSON - store both string and raw bytes
    const clientDataJSONBytes = new Uint8Array(response.clientDataJSON);
    const clientDataJSON = new TextDecoder().decode(clientDataJSONBytes);

    // Find challenge offset in clientDataJSON
    const challengeOffset = findChallengeOffset(clientDataJSON, challenge);

    return {
      r,
      s,
      authenticatorData,
      clientDataJSON,
      clientDataJSONBytes, // Store raw bytes for verification
      challengeOffset,
      originalDER: signature, // Store original DER for verification
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
    console.log('=== SIGNATURE VERIFICATION DEBUG ===');
    console.log('1. Original message:', message);

    // Hash the message (same as when signing)
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const messageHash = await crypto.subtle.digest('SHA-256', data);
    const messageHashHex = '0x' + Array.from(new Uint8Array(messageHash)).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('2. Message hash (SHA-256):', messageHashHex);

    // WebAuthn signatures are over: SHA-256(authenticatorData || SHA-256(clientDataJSON))
    // First, hash the clientDataJSON
    // Use raw bytes if available, otherwise re-encode the string
    const clientDataJSONBytes = signature.clientDataJSONBytes || encoder.encode(signature.clientDataJSON);

    // Compare if we have both
    if (signature.clientDataJSONBytes) {
      const reencoded = encoder.encode(signature.clientDataJSON);
      const match = Array.from(signature.clientDataJSONBytes).every((b, i) => b === reencoded[i]) &&
                    signature.clientDataJSONBytes.length === reencoded.length;
      console.log('3. Client data JSON bytes match after string round-trip?', match);
      if (!match) {
        console.log('   Original bytes:', '0x' + Array.from(signature.clientDataJSONBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
        console.log('   Re-encoded bytes:', '0x' + Array.from(reencoded).map(b => b.toString(16).padStart(2, '0')).join(''));
      }
    }

    const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSONBytes as BufferSource);
    console.log('3a. Client data JSON:', signature.clientDataJSON);

    // Verify the challenge in clientDataJSON matches our message hash
    const clientData = JSON.parse(signature.clientDataJSON);
    const challengeBase64Url = clientData.challenge;
    console.log('3b. Challenge from clientDataJSON (base64url):', challengeBase64Url);

    // Decode base64url to hex
    const base64 = challengeBase64Url.replace(/-/g, '+').replace(/_/g, '/');
    const challengeBytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    const challengeHex = '0x' + Array.from(challengeBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('3c. Challenge decoded to hex:', challengeHex);
    console.log('3d. Challenges match?', challengeHex === messageHashHex);

    console.log('4. Client data hash:', '0x' + Array.from(new Uint8Array(clientDataHash)).map(b => b.toString(16).padStart(2, '0')).join(''));

    // Concatenate authenticatorData || clientDataHash
    const signedData = new Uint8Array(signature.authenticatorData.length + clientDataHash.byteLength);
    signedData.set(signature.authenticatorData, 0);
    signedData.set(new Uint8Array(clientDataHash), signature.authenticatorData.length);
    console.log('5. Signed data (authenticatorData || clientDataHash) length:', signedData.length);
    console.log('5a. Signed data hex:', '0x' + Array.from(signedData).map(b => b.toString(16).padStart(2, '0')).join(''));

    // This is what will be hashed by crypto.subtle.verify()
    // The authenticator signs: SHA-256(authenticatorData || SHA-256(clientDataJSON))
    // crypto.subtle.verify will compute the final SHA-256 itself
    const expectedHash = await crypto.subtle.digest('SHA-256', signedData);
    const expectedHashHex = '0x' + Array.from(new Uint8Array(expectedHash)).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('6. Expected hash (what authenticator signed):', expectedHashHex);

    // Import the P-256 public key
    // Format: 0x04 || x || y (uncompressed point)
    console.log('7a. Public key X length:', publicKey.x.length);
    console.log('7b. Public key Y length:', publicKey.y.length);
    console.log('7c. Public key X:', '0x' + Array.from(publicKey.x).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('7d. Public key Y:', '0x' + Array.from(publicKey.y).map(b => b.toString(16).padStart(2, '0')).join(''));

    const publicKeyBytes = new Uint8Array(65);
    publicKeyBytes[0] = 0x04;
    publicKeyBytes.set(publicKey.x, 1);
    publicKeyBytes.set(publicKey.y, 33);
    console.log('7e. Public key (uncompressed):', '0x' + Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join(''));

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true, // Make extractable for debugging
      ['verify']
    );

    // Verify the key was imported correctly
    const exportedKey = await crypto.subtle.exportKey('raw', cryptoKey);
    const exportedHex = '0x' + Array.from(new Uint8Array(exportedKey)).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('7f. Re-exported public key:', exportedHex);
    console.log('7g. Keys match after round-trip?', exportedHex === '0x' + Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join(''));

    console.log('8. Signature r:', '0x' + Array.from(signature.r).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('9. Signature s:', '0x' + Array.from(signature.s).map(b => b.toString(16).padStart(2, '0')).join(''));

    // CRITICAL FIX: crypto.subtle.verify expects raw format (r||s), NOT DER format!
    // WebAuthn returns DER-encoded signatures, but Web Crypto API expects IEEE P1363 format
    // For P-256, this is exactly 64 bytes: 32 bytes r + 32 bytes s
    const rawSignature = new Uint8Array(64);
    rawSignature.set(signature.r, 0);
    rawSignature.set(signature.s, 32);

    console.log('10. Raw signature (r||s) length:', rawSignature.length);
    console.log('10a. Raw signature (hex):', '0x' + Array.from(rawSignature).map(b => b.toString(16).padStart(2, '0')).join(''));

    // Double-check what we're verifying
    console.log('11a. About to verify:');
    console.log('  - Signature format: RAW (r||s, IEEE P1363)');
    console.log('  - Signature (raw):', '0x' + Array.from(rawSignature).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('  - Data to verify (will be hashed with SHA-256):', '0x' + Array.from(signedData).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('  - Data length:', signedData.length);

    // Manually compute what the hash will be
    const manualHash = await crypto.subtle.digest('SHA-256', signedData);
    const manualHashHex = '0x' + Array.from(new Uint8Array(manualHash)).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log('  - Hash of data (should match step 6):', manualHashHex);
    console.log('  - Matches expected hash?', manualHashHex === expectedHashHex);

    // Verify the signature
    // Pass the unhashed signedData - crypto.subtle.verify will hash it with SHA-256
    // IMPORTANT: Use raw signature (r||s), not DER format!
    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      cryptoKey,
      rawSignature as BufferSource,
      signedData
    );

    console.log('11b. Verification result:', isValid);
    console.log('=== END VERIFICATION DEBUG ===');

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
  // Hash the message to use as challenge
  const encoder = new TextEncoder();
  const data = encoder.encode(message);

  // Use message hash as challenge
  const challenge = await crypto.subtle.digest('SHA-256', data);

  return signWithPasskey(new Uint8Array(challenge), credentialId);
}

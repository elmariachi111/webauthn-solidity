/**
 * On-chain verification utilities
 */

import { createPublicClient, http, type Hex } from 'viem';
import type { WebAuthnSignature } from '../types';

/**
 * WebAuthnAuth struct matching the Solidity contract
 */
interface WebAuthnAuthStruct {
  r: Hex;
  s: Hex;
  challengeIndex: bigint;
  typeIndex: bigint;
  authenticatorData: Hex;
  clientDataJSON: string;
}

/**
 * Contract ABI for the verifyWebauthn function (from P256Verifier.sol)
 */
const P256_VERIFIER_ABI = [
  {
    inputs: [
      { name: 'challenge', type: 'bytes' },
      {
        name: 'auth',
        type: 'tuple',
        components: [
          { name: 'r', type: 'bytes32' },
          { name: 's', type: 'bytes32' },
          { name: 'challengeIndex', type: 'uint256' },
          { name: 'typeIndex', type: 'uint256' },
          { name: 'authenticatorData', type: 'bytes' },
          { name: 'clientDataJSON', type: 'string' },
        ],
      },
      { name: 'qx', type: 'bytes32' },
      { name: 'qy', type: 'bytes32' },
    ],
    name: 'verifyWebauthn',
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function',
  },
] as const;

/**
 * Get RPC URL from environment or default to localhost
 */
function getRpcUrl(): string {
  return process.env.NEXT_PUBLIC_RPC_URL || 'http://localhost:8545';
}

/**
 * Get contract address from environment
 */
function getContractAddress(): Hex | null {
  const address = process.env.NEXT_PUBLIC_WEBAUTHN_VERIFIER_ADDRESS;
  if (!address) {
    return null;
  }
  return address as Hex;
}

/**
 * Verify a WebAuthn signature on-chain
 */
export async function verifyOnChain(
  message: string,
  signature: WebAuthnSignature,
  publicKeyX: Uint8Array,
  publicKeyY: Uint8Array
): Promise<{ success: boolean; error?: string }> {
  try {
    // Get contract address
    const contractAddress = getContractAddress();
    if (!contractAddress) {
      return {
        success: false,
        error: 'Contract address not configured. Please set NEXT_PUBLIC_WEBAUTHN_VERIFIER_ADDRESS in .env',
      };
    }

    // Create public client
    const client = createPublicClient({
      transport: http(getRpcUrl()),
    });

    // Convert Uint8Array to Hex
    const toHex = (bytes: Uint8Array): Hex => {
      return ('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')) as Hex;
    };

    const toHex32 = (bytes: Uint8Array): Hex => {
      const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      return ('0x' + hex.padStart(64, '0')) as Hex;
    };

    // Prepare the challenge (message bytes)
    const encoder = new TextEncoder();
    const challengeBytes = encoder.encode(message);
    const challenge = toHex(challengeBytes);

    // Prepare the WebAuthnAuth struct
    const auth: WebAuthnAuthStruct = {
      r: toHex32(signature.r),
      s: toHex32(signature.s),
      challengeIndex: BigInt(signature.challengeIndex),
      typeIndex: BigInt(signature.typeIndex),
      authenticatorData: toHex(signature.authenticatorData),
      clientDataJSON: signature.clientDataJSON,
    };

    // Prepare public key coordinates
    const qx = toHex32(publicKeyX);
    const qy = toHex32(publicKeyY);

    // Call the contract
    const result = (await client.readContract({
      address: contractAddress,
      abi: P256_VERIFIER_ABI,
      functionName: 'verifyWebauthn',
      // @ts-expect-error - viem type inference is too strict for complex tuple types
      args: [challenge, auth, qx, qy],
    })) as boolean;

    return {
      success: result,
      error: result ? undefined : 'Signature verification failed on-chain',
    };
  } catch (error) {
    console.error('On-chain verification error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error during on-chain verification',
    };
  }
}

/**
 * Check if on-chain verification is configured
 */
export function isOnChainVerificationAvailable(): boolean {
  return getContractAddress() !== null;
}

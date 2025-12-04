/**
 * Core type definitions for the Passkey Wallet application
 */

/**
 * Represents a stored WebAuthn credential
 */
export interface Credential {
  /** The credential ID (base64url encoded) */
  id: string;
  /** Public key coordinates */
  publicKey: {
    /** X coordinate of the P-256 public key */
    x: Uint8Array;
    /** Y coordinate of the P-256 public key */
    y: Uint8Array;
  };
  /** Ethereum address derived from public key */
  address: string;
  /** Timestamp when credential was created */
  createdAt: number;
  /** Timestamp when credential was last used */
  lastUsed: number;
}

/**
 * Represents a WebAuthn signature for blockchain verification
 */
export interface WebAuthnSignature {
  /** R component of the P-256 signature (32 bytes) */
  r: Uint8Array;
  /** S component of the P-256 signature (32 bytes) */
  s: Uint8Array;
  /** Authenticator data from the WebAuthn response */
  authenticatorData: Uint8Array;
  /** Client data JSON from the WebAuthn response */
  clientDataJSON: string;
  /** Byte offset of the challenge in clientDataJSON */
  challengeOffset: number;
}

/**
 * Represents a wallet account
 */
export interface WalletAccount {
  /** Ethereum address */
  address: string;
  /** Associated credential ID */
  credentialId: string;
  /** Public key coordinates */
  publicKey: {
    x: Uint8Array;
    y: Uint8Array;
  };
  /** Display name or identifier */
  name?: string;
}

/**
 * Options for creating a passkey
 */
export interface CreatePasskeyOptions {
  /** User identifier (email, username, etc.) */
  userId: string;
  /** User's display name */
  displayName: string;
  /** Optional challenge (will be generated if not provided) */
  challenge?: Uint8Array;
}

/**
 * Options for signing with a passkey
 */
export interface SignWithPasskeyOptions {
  /** The credential ID to use for signing */
  credentialId: string;
  /** The challenge/message to sign */
  challenge: Uint8Array;
  /** Relying party ID (domain) */
  rpId?: string;
}

/**
 * Result from creating a passkey
 */
export interface CreatePasskeyResult {
  /** The credential ID */
  credentialId: string;
  /** Public key coordinates */
  publicKey: {
    x: Uint8Array;
    y: Uint8Array;
  };
  /** Derived Ethereum address */
  address: string;
  /** The raw credential response */
  rawCredential: PublicKeyCredential;
}

/**
 * Core types for the passkey wallet application
 */

/**
 * Stored credential information
 */
export interface Credential {
  /** Base64URL-encoded credential ID */
  id: string;
  /** P-256 public key X coordinate */
  publicKeyX: Uint8Array;
  /** P-256 public key Y coordinate */
  publicKeyY: Uint8Array;
  /** Base64-encoded public key identifier (NOT an Ethereum address) */
  identifier: string;
  /** Timestamp when credential was created */
  createdAt: number;
  /** Timestamp when credential was last used */
  lastUsed: number;
}

/**
 * WebAuthn signature components for blockchain verification
 */
export interface WebAuthnSignature {
  /** P-256 signature r value (32 bytes) */
  r: Uint8Array;
  /** P-256 signature s value (32 bytes) */
  s: Uint8Array;
  /** Authenticator data from WebAuthn response */
  authenticatorData: Uint8Array;
  /** Client data JSON from WebAuthn response */
  clientDataJSON: string;
  /** Client data JSON raw bytes (for verification) */
  clientDataJSONBytes: Uint8Array;
  /** Offset of challenge in clientDataJSON */
  challengeOffset: number;
  /** Original DER-encoded signature from authenticator (for debugging) */
  originalDER?: Uint8Array;
}

/**
 * Wallet account combining credential and public key identifier
 */
export interface WalletAccount {
  /** Base64-encoded public key identifier (NOT an Ethereum address) */
  identifier: string;
  /** Credential ID reference */
  credentialId: string;
  /** P-256 public key X coordinate */
  publicKeyX: Uint8Array;
  /** P-256 public key Y coordinate */
  publicKeyY: Uint8Array;
  /** When this account was created */
  createdAt: number;
  /** When this account was last used for signing */
  lastUsed: number;
}

/**
 * Public key in raw P-256 format
 */
export interface P256PublicKey {
  /** X coordinate (32 bytes) */
  x: Uint8Array;
  /** Y coordinate (32 bytes) */
  y: Uint8Array;
}

/**
 * Result from passkey creation
 */
export interface PasskeyCreationResult {
  /** The credential ID */
  credentialId: string;
  /** The public key */
  publicKey: P256PublicKey;
  /** Base64-encoded public key identifier (NOT an Ethereum address) */
  identifier: string;
}

/**
 * Error types for WebAuthn operations
 */
export enum WebAuthnErrorType {
  NOT_SUPPORTED = 'NOT_SUPPORTED',
  NOT_ALLOWED = 'NOT_ALLOWED',
  USER_CANCELLED = 'USER_CANCELLED',
  TIMEOUT = 'TIMEOUT',
  UNKNOWN = 'UNKNOWN',
}

/**
 * Custom WebAuthn error
 */
export class WebAuthnError extends Error {
  constructor(
    public type: WebAuthnErrorType,
    message: string,
    public originalError?: Error
  ) {
    super(message);
    this.name = 'WebAuthnError';
  }
}

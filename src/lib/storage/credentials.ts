/**
 * Credential storage operations
 */

import type { Credential, WalletAccount } from '../types';
import { db } from './db';

/**
 * Save a credential to IndexedDB
 */
export async function saveCredential(credential: Credential): Promise<void> {
  await db.credentials.put(credential);
}

/**
 * Get a credential by ID
 */
export async function getCredential(id: string): Promise<Credential | undefined> {
  return await db.credentials.get(id);
}

/**
 * Get all credentials
 */
export async function getAllCredentials(): Promise<Credential[]> {
  return await db.credentials.toArray();
}

/**
 * Delete a credential
 */
export async function deleteCredential(id: string): Promise<void> {
  await db.credentials.delete(id);
}

/**
 * Update last used timestamp for a credential
 */
export async function updateLastUsed(id: string): Promise<void> {
  await db.credentials.update(id, { lastUsed: Date.now() });
}

/**
 * Get the default (most recently used) account
 */
export async function getDefaultAccount(): Promise<WalletAccount | null> {
  const credentials = await db.credentials.orderBy('lastUsed').reverse().toArray();

  if (credentials.length === 0) {
    return null;
  }

  const credential = credentials[0];

  return {
    address: credential.address,
    credentialId: credential.id,
    publicKeyX: credential.publicKeyX,
    publicKeyY: credential.publicKeyY,
    createdAt: credential.createdAt,
    lastUsed: credential.lastUsed,
  };
}

/**
 * List all wallet accounts
 */
export async function listAllAccounts(): Promise<WalletAccount[]> {
  const credentials = await db.credentials.orderBy('createdAt').reverse().toArray();

  return credentials.map((credential) => ({
    address: credential.address,
    credentialId: credential.id,
    publicKeyX: credential.publicKeyX,
    publicKeyY: credential.publicKeyY,
    createdAt: credential.createdAt,
    lastUsed: credential.lastUsed,
  }));
}

/**
 * Check if any credentials exist
 */
export async function hasCredentials(): Promise<boolean> {
  const count = await db.credentials.count();
  return count > 0;
}

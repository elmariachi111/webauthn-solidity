/**
 * IndexedDB database setup using Dexie
 */

import Dexie, { type Table } from 'dexie';
import type { Credential } from '../types';

/**
 * Passkey Wallet Database
 */
export class PasskeyWalletDB extends Dexie {
  credentials!: Table<Credential, string>;

  constructor() {
    super('PasskeyWalletDB');

    // Version 1: Initial schema with 'address' field (deprecated)
    this.version(1).stores({
      credentials: 'id, address, createdAt, lastUsed',
    });

    // Version 2: Updated schema with 'identifier' field instead of 'address'
    this.version(2).stores({
      credentials: 'id, identifier, createdAt, lastUsed',
    });
  }
}

// Create singleton instance
export const db = new PasskeyWalletDB();

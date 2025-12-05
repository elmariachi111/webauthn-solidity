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

    this.version(1).stores({
      credentials: 'id, address, createdAt, lastUsed',
    });
  }
}

// Create singleton instance
export const db = new PasskeyWalletDB();

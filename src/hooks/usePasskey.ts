/**
 * React hook for passkey wallet operations
 */

'use client';

import { useState, useEffect } from 'react';
import type { WalletAccount, WebAuthnSignature } from '@/lib/types';
import { createPasskey, isPlatformAuthenticatorAvailable, isWebAuthnSupported } from '@/lib/webauthn/registration';
import { signMessage } from '@/lib/webauthn/authentication';
import { saveCredential, getDefaultAccount, updateLastUsed } from '@/lib/storage/credentials';

export function usePasskey() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [currentAccount, setCurrentAccount] = useState<WalletAccount | null>(null);
  const [isSupported, setIsSupported] = useState(false);
  const [isAvailable, setIsAvailable] = useState(false);

  // Check support on mount
  useEffect(() => {
    const checkSupport = async () => {
      setIsSupported(isWebAuthnSupported());
      if (isWebAuthnSupported()) {
        const available = await isPlatformAuthenticatorAvailable();
        setIsAvailable(available);
      }
    };
    checkSupport();
  }, []);

  // Load current account
  useEffect(() => {
    const loadAccount = async () => {
      try {
        const account = await getDefaultAccount();
        setCurrentAccount(account);
      } catch (err) {
        console.error('Failed to load account:', err);
      }
    };
    loadAccount();
  }, []);

  /**
   * Create a new wallet
   */
  const createWallet = async (username: string): Promise<WalletAccount> => {
    setLoading(true);
    setError(null);

    try {
      const result = await createPasskey(username, username);

      // Save to IndexedDB
      const credential = {
        id: result.credentialId,
        publicKeyX: result.publicKey.x,
        publicKeyY: result.publicKey.y,
        address: result.address,
        createdAt: Date.now(),
        lastUsed: Date.now(),
      };

      await saveCredential(credential);

      // Update current account
      const account: WalletAccount = {
        address: result.address,
        credentialId: result.credentialId,
        publicKeyX: result.publicKey.x,
        publicKeyY: result.publicKey.y,
        createdAt: credential.createdAt,
        lastUsed: credential.lastUsed,
      };

      setCurrentAccount(account);
      return account;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to create wallet');
      setError(error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  /**
   * Sign a message
   */
  const sign = async (message: string): Promise<WebAuthnSignature> => {
    if (!currentAccount) {
      throw new Error('No wallet account available');
    }

    setLoading(true);
    setError(null);

    try {
      const signature = await signMessage(message, currentAccount.credentialId);

      // Update last used timestamp
      await updateLastUsed(currentAccount.credentialId);

      return signature;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to sign message');
      setError(error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  return {
    loading,
    error,
    currentAccount,
    isSupported,
    isAvailable,
    createWallet,
    signMessage: sign,
  };
}

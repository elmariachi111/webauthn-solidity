/**
 * React hook for passkey wallet operations
 */

'use client';

import { useState, useEffect } from 'react';
import type { WalletAccount, WebAuthnSignature } from '@/lib/types';
import { createPasskey, authenticateWithPasskey, isPlatformAuthenticatorAvailable, isWebAuthnSupported } from '@/lib/webauthn/registration';
import { signMessage } from '@/lib/webauthn/authentication';
import { saveCredential, getDefaultAccount, updateLastUsed, getCredential } from '@/lib/storage/credentials';

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
   * Sign in with existing passkey (shows native picker)
   */
  const discoverPasskey = async (): Promise<WalletAccount> => {
    setLoading(true);
    setError(null);

    try {
      // Authenticate with existing passkey - this shows the native picker
      const result = await authenticateWithPasskey();

      // Look up the credential in IndexedDB
      const credential = await getCredential(result.credentialId);

      if (!credential) {
        throw new Error('Passkey found but not registered in this app. Please create a new wallet.');
      }

      // Update last used
      await updateLastUsed(result.credentialId);

      // Create account from stored credential
      const account: WalletAccount = {
        identifier: credential.identifier,
        credentialId: credential.id,
        publicKeyX: credential.publicKeyX,
        publicKeyY: credential.publicKeyY,
        createdAt: credential.createdAt,
        lastUsed: Date.now(),
      };

      setCurrentAccount(account);
      return account;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to sign in with passkey');
      setError(error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  /**
   * Create a new wallet
   */
  const createWallet = async (username: string): Promise<WalletAccount> => {
    setLoading(true);
    setError(null);

    try {
      // Don't use excludeCredentials - allow multiple wallets with different usernames
      // The authenticator will handle preventing true duplicates (same username)
      const result = await createPasskey(username, username);

      // Save to IndexedDB
      const credential = {
        id: result.credentialId,
        publicKeyX: result.publicKey.x,
        publicKeyY: result.publicKey.y,
        identifier: result.identifier,
        createdAt: Date.now(),
        lastUsed: Date.now(),
      };

      await saveCredential(credential);

      // Update current account
      const account: WalletAccount = {
        identifier: result.identifier,
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

  /**
   * Logout - clear current session
   */
  const logout = () => {
    setCurrentAccount(null);
    setError(null);
  };

  return {
    loading,
    error,
    currentAccount,
    isSupported,
    isAvailable,
    createWallet,
    discoverPasskey,
    signMessage: sign,
    logout,
  };
}

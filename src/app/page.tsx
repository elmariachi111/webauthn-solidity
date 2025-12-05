/**
 * Home Page - Main entry point for the passkey wallet
 */

'use client';

import { useEffect, useState } from 'react';
import { CreateWallet } from '@/components/wallet/CreateWallet';
import { WalletDashboard } from '@/components/wallet/WalletDashboard';
import { CompatibilityCheck } from '@/components/wallet/CompatibilityCheck';
import { hasCredentials, getDefaultAccount } from '@/lib/storage/credentials';
import type { WalletAccount } from '@/lib/types';

export default function Home() {
  const [loading, setLoading] = useState(true);
  const [account, setAccount] = useState<WalletAccount | null>(null);

  const loadAccount = async () => {
    setLoading(true);
    try {
      const hasWallet = await hasCredentials();
      if (hasWallet) {
        const defaultAccount = await getDefaultAccount();
        setAccount(defaultAccount);
      }
    } catch (err) {
      console.error('Failed to load account:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAccount();
  }, []);

  const handleLogout = () => {
    setAccount(null);
  };

  if (loading) {
    return (
      <div className="max-w-2xl mx-auto space-y-6">
        <CompatibilityCheck />
        <div className="text-center py-12 text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <CompatibilityCheck />

      {account ? (
        <WalletDashboard account={account} onLogout={handleLogout} />
      ) : (
        <CreateWallet onWalletCreated={loadAccount} />
      )}
    </div>
  );
}

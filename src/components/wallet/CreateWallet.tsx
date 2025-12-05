/**
 * Create Wallet Component
 */

'use client';

import { useState } from 'react';
import { toast } from 'sonner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { usePasskey } from '@/hooks/usePasskey';

interface CreateWalletProps {
  onWalletCreated?: () => void;
}

export function CreateWallet({ onWalletCreated }: CreateWalletProps) {
  const [username, setUsername] = useState('');
  const { createWallet, discoverPasskey, loading, error } = usePasskey();
  const [createdAddress, setCreatedAddress] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!username.trim()) {
      toast.error('Please enter a username');
      return;
    }

    try {
      toast.loading('Creating wallet...', { id: 'create-wallet' });

      const account = await createWallet(username);

      toast.success('Wallet created successfully!', { id: 'create-wallet' });
      setCreatedAddress(account.address);
      setUsername('');

      if (onWalletCreated) {
        onWalletCreated();
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create wallet', {
        id: 'create-wallet',
      });
    }
  };

  const handleSignIn = async () => {
    try {
      toast.loading('Signing in with passkey...', { id: 'sign-in' });

      const account = await discoverPasskey();

      toast.success('Signed in successfully!', { id: 'sign-in' });
      setCreatedAddress(account.address);

      if (onWalletCreated) {
        onWalletCreated();
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to sign in', {
        id: 'sign-in',
      });
    }
  };

  if (createdAddress) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Wallet Created!</CardTitle>
          <CardDescription>Your passkey wallet has been successfully created</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label>Ethereum Address</Label>
            <div className="mt-2 p-3 bg-muted rounded-md font-mono text-sm break-all">
              {createdAddress}
            </div>
          </div>
          <Badge variant="outline" className="text-green-600 border-green-600">
            ✓ Secured with biometric authentication
          </Badge>
          <Button
            onClick={() => setCreatedAddress(null)}
            variant="outline"
            className="w-full"
          >
            Create Another Wallet
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Passkey Wallet</CardTitle>
        <CardDescription>
          Create a new wallet or sign in with an existing passkey
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Sign In Button */}
          <div className="space-y-2">
            <Button
              onClick={handleSignIn}
              className="w-full"
              disabled={loading}
              variant="default"
            >
              {loading ? 'Signing In...' : 'Sign In with Existing Passkey'}
            </Button>
            <p className="text-sm text-muted-foreground text-center">
              Use your saved passkey from this device or iCloud Keychain
            </p>
          </div>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-background px-2 text-muted-foreground">Or create new</span>
            </div>
          </div>

          {/* Create New Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username / Email</Label>
              <Input
                id="username"
                type="text"
                placeholder="your@email.com"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={loading}
              />
              <p className="text-sm text-muted-foreground">
                This will be used to identify your new passkey
              </p>
            </div>

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error.message}</AlertDescription>
              </Alert>
            )}

            <Button type="submit" className="w-full" disabled={loading} variant="outline">
              {loading ? 'Creating Wallet...' : 'Create New Wallet'}
            </Button>

            <div className="text-sm text-muted-foreground space-y-1">
              <p>✓ Private key stored in secure hardware</p>
              <p>✓ No seed phrase to manage</p>
              <p>✓ Sign with Face ID / Touch ID / fingerprint</p>
            </div>
          </form>
        </div>
      </CardContent>
    </Card>
  );
}

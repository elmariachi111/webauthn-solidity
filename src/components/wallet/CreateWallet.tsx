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
  const { createWallet, loading, error } = usePasskey();
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
        <CardTitle>Create Passkey Wallet</CardTitle>
        <CardDescription>
          Create a new Ethereum wallet secured by your device&apos;s biometric authentication
        </CardDescription>
      </CardHeader>
      <CardContent>
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
              This will be used to identify your passkey
            </p>
          </div>

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error.message}</AlertDescription>
            </Alert>
          )}

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? 'Creating Wallet...' : 'Create Wallet'}
          </Button>

          <div className="text-sm text-muted-foreground space-y-1">
            <p>✓ Private key stored in secure hardware</p>
            <p>✓ No seed phrase to manage</p>
            <p>✓ Sign with Face ID / Touch ID / fingerprint</p>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

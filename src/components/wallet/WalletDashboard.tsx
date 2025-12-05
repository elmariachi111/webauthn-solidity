/**
 * Wallet Dashboard Component
 */

'use client';

import { useState } from 'react';
import { toast } from 'sonner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import type { WalletAccount } from '@/lib/types';
import { formatPublicKey } from '@/lib/crypto/address';
import { SignMessage } from './SignMessage';

interface WalletDashboardProps {
  account: WalletAccount;
}

export function WalletDashboard({ account }: WalletDashboardProps) {
  const [showSignMessage, setShowSignMessage] = useState(false);

  const publicKey = formatPublicKey(account.publicKeyX, account.publicKeyY);

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`${label} copied to clipboard`);
    } catch (err) {
      toast.error('Failed to copy to clipboard');
    }
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Your Passkey Wallet</CardTitle>
          <CardDescription>Secured with biometric authentication</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Ethereum Address */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Ethereum Address</span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => copyToClipboard(account.address, 'Address')}
              >
                Copy
              </Button>
            </div>
            <div className="p-3 bg-muted rounded-md font-mono text-sm break-all">
              {account.address}
            </div>
          </div>

          <Separator />

          {/* Public Key */}
          <div className="space-y-2">
            <span className="text-sm font-medium">Public Key</span>
            <div className="space-y-2">
              <div>
                <div className="text-xs text-muted-foreground mb-1">X Coordinate</div>
                <div className="p-2 bg-muted rounded-md font-mono text-xs break-all">
                  {publicKey.x}
                </div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Y Coordinate</div>
                <div className="p-2 bg-muted rounded-md font-mono text-xs break-all">
                  {publicKey.y}
                </div>
              </div>
            </div>
          </div>

          <Separator />

          {/* Metadata */}
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Created</span>
              <span className="font-medium">{formatDate(account.createdAt)}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Last Used</span>
              <span className="font-medium">{formatDate(account.lastUsed)}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Credential ID</span>
              <span className="font-mono text-xs truncate max-w-[200px]">
                {account.credentialId}
              </span>
            </div>
          </div>

          <Separator />

          {/* Actions */}
          <div className="space-y-2">
            <Button onClick={() => setShowSignMessage(true)} className="w-full">
              Sign Message
            </Button>
            <div className="flex gap-2">
              <Button
                variant="outline"
                className="flex-1"
                onClick={() => copyToClipboard(account.address, 'Address')}
              >
                Copy Address
              </Button>
              <Button
                variant="outline"
                className="flex-1"
                onClick={() => copyToClipboard(publicKey.uncompressed, 'Public Key')}
              >
                Copy Public Key
              </Button>
            </div>
          </div>

          {/* Security Badge */}
          <div className="flex justify-center">
            <Badge variant="outline" className="text-green-600 border-green-600">
              🔒 Hardware-Secured P-256 Key
            </Badge>
          </div>
        </CardContent>
      </Card>

      {showSignMessage && (
        <SignMessage
          account={account}
          onClose={() => setShowSignMessage(false)}
        />
      )}
    </>
  );
}

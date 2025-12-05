/**
 * Sign Message Component
 */

'use client';

import { useState } from 'react';
import { toast } from 'sonner';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import type { WalletAccount, WebAuthnSignature } from '@/lib/types';
import { usePasskey } from '@/hooks/usePasskey';
import { formatSignatureForChain } from '@/lib/webauthn/authentication';

interface SignMessageProps {
  account: WalletAccount;
  onClose: () => void;
}

export function SignMessage({ account, onClose }: SignMessageProps) {
  const [message, setMessage] = useState('');
  const [signature, setSignature] = useState<WebAuthnSignature | null>(null);
  const { signMessage, loading } = usePasskey();

  const handleSign = async () => {
    if (!message.trim()) {
      toast.error('Please enter a message to sign');
      return;
    }

    try {
      toast.loading('Please authenticate with your biometric...', { id: 'sign' });

      const sig = await signMessage(message);

      toast.success('Message signed successfully!', { id: 'sign' });
      setSignature(sig);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to sign message', {
        id: 'sign',
      });
    }
  };

  const copySignature = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`${label} copied to clipboard`);
    } catch (err) {
      toast.error('Failed to copy to clipboard');
    }
  };

  const copyFullSignature = async () => {
    if (!signature) return;

    const formatted = formatSignatureForChain(signature);
    const json = JSON.stringify(formatted, null, 2);

    try {
      await navigator.clipboard.writeText(json);
      toast.success('Full signature copied to clipboard');
    } catch (err) {
      toast.error('Failed to copy to clipboard');
    }
  };

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Sign Message</DialogTitle>
          <DialogDescription>
            Sign a message using your passkey wallet
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Message Input */}
          {!signature && (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="message">Message to Sign</Label>
                <Input
                  id="message"
                  type="text"
                  placeholder="Enter your message..."
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  disabled={loading}
                />
              </div>

              <Button onClick={handleSign} className="w-full" disabled={loading}>
                {loading ? 'Signing...' : 'Sign Message'}
              </Button>
            </div>
          )}

          {/* Signature Display */}
          {signature && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold">Signature</h3>
                <Button onClick={copyFullSignature} variant="outline" size="sm">
                  Copy All
                </Button>
              </div>

              <Card>
                <CardContent className="pt-6 space-y-4">
                  {/* R Value */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">r value</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          copySignature(
                            '0x' +
                              Array.from(signature.r)
                                .map((b) => b.toString(16).padStart(2, '0'))
                                .join(''),
                            'r value'
                          )
                        }
                      >
                        Copy
                      </Button>
                    </div>
                    <code className="block p-3 bg-muted rounded-md text-xs break-all">
                      0x
                      {Array.from(signature.r)
                        .map((b) => b.toString(16).padStart(2, '0'))
                        .join('')}
                    </code>
                  </div>

                  <Separator />

                  {/* S Value */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">s value</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          copySignature(
                            '0x' +
                              Array.from(signature.s)
                                .map((b) => b.toString(16).padStart(2, '0'))
                                .join(''),
                            's value'
                          )
                        }
                      >
                        Copy
                      </Button>
                    </div>
                    <code className="block p-3 bg-muted rounded-md text-xs break-all">
                      0x
                      {Array.from(signature.s)
                        .map((b) => b.toString(16).padStart(2, '0'))
                        .join('')}
                    </code>
                  </div>

                  <Separator />

                  {/* Authenticator Data */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Authenticator Data</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          copySignature(
                            '0x' +
                              Array.from(signature.authenticatorData)
                                .map((b) => b.toString(16).padStart(2, '0'))
                                .join(''),
                            'Authenticator Data'
                          )
                        }
                      >
                        Copy
                      </Button>
                    </div>
                    <code className="block p-3 bg-muted rounded-md text-xs break-all">
                      0x
                      {Array.from(signature.authenticatorData)
                        .map((b) => b.toString(16).padStart(2, '0'))
                        .join('')}
                    </code>
                  </div>

                  <Separator />

                  {/* Client Data JSON */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Client Data JSON</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copySignature(signature.clientDataJSON, 'Client Data')}
                      >
                        Copy
                      </Button>
                    </div>
                    <code className="block p-3 bg-muted rounded-md text-xs break-all whitespace-pre-wrap">
                      {JSON.stringify(JSON.parse(signature.clientDataJSON), null, 2)}
                    </code>
                  </div>

                  <Separator />

                  {/* Challenge Offset */}
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Challenge Offset</span>
                    <span className="font-mono">{signature.challengeOffset}</span>
                  </div>
                </CardContent>
              </Card>

              <div className="flex gap-2">
                <Button onClick={() => setSignature(null)} variant="outline" className="flex-1">
                  Sign Another Message
                </Button>
                <Button onClick={onClose} variant="default" className="flex-1">
                  Close
                </Button>
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

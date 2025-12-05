/**
 * Sign Message Component
 */

'use client';

import { useState } from 'react';
import { keccak256, toBytes } from 'viem';
import { toast } from 'sonner';
import { CheckCircle2 } from 'lucide-react';
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
import { Alert, AlertDescription } from '@/components/ui/alert';
import type { WalletAccount, WebAuthnSignature } from '@/lib/types';
import { usePasskey } from '@/hooks/usePasskey';
import { formatSignatureForChain, verifySignature } from '@/lib/webauthn/authentication';

interface SignMessageProps {
  account: WalletAccount;
  onClose: () => void;
}

export function SignMessage({ account, onClose }: SignMessageProps) {
  const [message, setMessage] = useState('');
  const [signedMessage, setSignedMessage] = useState('');
  const [messageHash, setMessageHash] = useState('');
  const [signature, setSignature] = useState<WebAuthnSignature | null>(null);
  const [verificationStatus, setVerificationStatus] = useState<'pending' | 'verified' | 'failed' | null>(null);
  const { signMessage, loading } = usePasskey();

  const handleSign = async () => {
    if (!message.trim()) {
      toast.error('Please enter a message to sign');
      return;
    }

    try {
      toast.loading('Please authenticate with your biometric...', { id: 'sign' });

      const sig = await signMessage(message);

      // Calculate message hash using keccak256 (EVM-compatible)
      const hashHex = keccak256(toBytes(message));

      setSignedMessage(message);
      setMessageHash(hashHex);
      setSignature(sig);
      setVerificationStatus(null);

      toast.success('Message signed successfully!', { id: 'sign' });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to sign message', {
        id: 'sign',
      });
    }
  };

  const handleVerify = async () => {
    if (!signature || !signedMessage) return;

    try {
      setVerificationStatus('pending');

      const isValid = await verifySignature(
        signedMessage,
        {
          r: signature.r,
          s: signature.s,
          authenticatorData: signature.authenticatorData,
          clientDataJSON: signature.clientDataJSON,
          clientDataJSONBytes: signature.clientDataJSONBytes,
          originalDER: signature.originalDER,
        },
        { x: account.publicKeyX, y: account.publicKeyY }
      );

      if (isValid) {
        setVerificationStatus('verified');
        toast.success('Signature verified successfully!');
      } else {
        setVerificationStatus('failed');
        toast.error('Signature verification failed!');
      }
    } catch (err) {
      console.error('Verification error:', err);
      setVerificationStatus('failed');
      toast.error('Failed to verify signature');
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
                <div className="flex gap-2">
                  <Button
                    onClick={handleVerify}
                    variant="default"
                    size="sm"
                    disabled={verificationStatus === 'pending'}
                  >
                    {verificationStatus === 'pending' ? 'Verifying...' : 'Verify Signature'}
                  </Button>
                  <Button onClick={copyFullSignature} variant="outline" size="sm">
                    Copy All
                  </Button>
                </div>
              </div>

              {/* Verification Result */}
              {verificationStatus === 'verified' && (
                <Alert className="bg-green-50 border-green-200">
                  <CheckCircle2 className="h-4 w-4 text-green-600" />
                  <AlertDescription className="text-green-800">
                    <div className="space-y-1">
                      <p className="font-medium">Signature verified successfully!</p>
                      <p className="text-sm">
                        The message was rightfully signed by P-256 public key:
                      </p>
                      <code className="text-xs break-all block mt-1">
                        {account.identifier}
                      </code>
                    </div>
                  </AlertDescription>
                </Alert>
              )}

              {verificationStatus === 'failed' && (
                <Alert className="bg-red-50 border-red-200">
                  <AlertDescription className="text-red-800">
                    Signature verification failed! The signature does not match the message or public key.
                  </AlertDescription>
                </Alert>
              )}

              <Card>
                <CardContent className="pt-6 space-y-4">
                  {/* Signed Message */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Signed Message</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copySignature(signedMessage, 'Message')}
                      >
                        Copy
                      </Button>
                    </div>
                    <code className="block p-3 bg-muted rounded-md text-xs break-all">
                      {signedMessage}
                    </code>
                  </div>

                  <Separator />

                  {/* Message Hash */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">Message Hash (keccak256)</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copySignature(messageHash, 'Message Hash')}
                      >
                        Copy
                      </Button>
                    </div>
                    <code className="block p-3 bg-muted rounded-md text-xs break-all">
                      {messageHash}
                    </code>
                  </div>

                  <Separator />

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
                <Button
                  onClick={() => {
                    setSignature(null);
                    setVerificationStatus(null);
                    setSignedMessage('');
                    setMessageHash('');
                  }}
                  variant="outline"
                  className="flex-1"
                >
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

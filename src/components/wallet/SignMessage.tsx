/**
 * Sign Message Component
 */

'use client';

import { useState } from 'react';
import { encodeAbiParameters, parseAbiParameters, toBytes, toHex } from 'viem';
import { toast } from 'sonner';
import { CheckCircle2, Link as LinkIcon } from 'lucide-react';
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
import { verifyOnChain, isOnChainVerificationAvailable } from '@/lib/verification/onchain';

interface SignMessageProps {
  account: WalletAccount;
  onClose: () => void;
}

export function SignMessage({ account, onClose }: SignMessageProps) {
  const [message, setMessage] = useState('');
  const [signedMessage, setSignedMessage] = useState('');
  const [signature, setSignature] = useState<WebAuthnSignature | null>(null);
  const [verificationStatus, setVerificationStatus] = useState<'pending' | 'verified' | 'failed' | null>(null);
  const [onChainVerificationStatus, setOnChainVerificationStatus] = useState<'pending' | 'verified' | 'failed' | null>(null);
  const { signMessage, loading } = usePasskey();

  const handleSign = async () => {
    if (!message.trim()) {
      toast.error('Please enter a message to sign');
      return;
    }

    try {
      toast.loading('Please authenticate with your biometric...', { id: 'sign' });

      const sig = await signMessage(message);

      setSignedMessage(message);
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

  const handleVerifyOnChain = async () => {
    if (!signature || !signedMessage) return;

    try {
      setOnChainVerificationStatus('pending');
      toast.loading('Verifying signature on-chain...', { id: 'onchain-verify' });

      const result = await verifyOnChain(
        signedMessage,
        signature,
        account.publicKeyX,
        account.publicKeyY
      );

      if (result.success) {
        setOnChainVerificationStatus('verified');
        toast.success('Signature verified on-chain successfully!', { id: 'onchain-verify' });
      } else {
        setOnChainVerificationStatus('failed');
        toast.error(result.error || 'On-chain verification failed!', { id: 'onchain-verify' });
      }
    } catch (err) {
      console.error('On-chain verification error:', err);
      setOnChainVerificationStatus('failed');
      toast.error('Failed to verify signature on-chain', { id: 'onchain-verify' });
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

  const getWebAuthnParameters = () => {
    if (!signature) return null;

    // Convert byte arrays to 0x hex strings
    const toHex = (bytes: Uint8Array): string => {
      return '0x' + Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    };

    // Convert byte arrays to 0x hex strings (padded to 32 bytes / 64 hex chars)
    const toHex32 = (bytes: Uint8Array): string => {
      return '0x' + Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .padStart(64, '0');
    };

    return {
      challenge: `"${signedMessage}"`,
      r: toHex32(signature.r),
      s: toHex32(signature.s),
      challengeIndex: signature.challengeIndex.toString(),
      typeIndex: signature.typeIndex.toString(),
      authenticatorData: toHex(signature.authenticatorData),
      clientDataJSON: signature.clientDataJSON,
      qx: toHex32(account.publicKeyX),
      qy: toHex32(account.publicKeyY),
    };
  };

  const copyWebAuthnParameters = async () => {
    const params = getWebAuthnParameters();
    if (!params) return;

    const formatted = JSON.stringify(params, null, 2);

    try {
      await navigator.clipboard.writeText(formatted);
      toast.success('WebAuthn parameters copied to clipboard');
    } catch (err) {
      toast.error('Failed to copy to clipboard');
    }
  };

  const getAbiEncodedParameters = () => {
    if (!signature) return null;

    // Convert Uint8Array to Hex with proper padding
    const toHex32 = (bytes: Uint8Array): `0x${string}` => {
      const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      return ('0x' + hex.padStart(64, '0')) as `0x${string}`;
    };

    const toHexBytes = (bytes: Uint8Array): `0x${string}` => {
      return ('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')) as `0x${string}`;
    };

    // Prepare values exactly as viem does for the contract call
    const challengeBytes = toBytes(signedMessage);
    const challenge = toHexBytes(challengeBytes);

    const authStruct = {
      r: toHex32(signature.r),
      s: toHex32(signature.s),
      challengeIndex: BigInt(signature.challengeIndex),
      typeIndex: BigInt(signature.typeIndex),
      authenticatorData: toHexBytes(signature.authenticatorData),
      clientDataJSON: signature.clientDataJSON,
    };

    const qx = toHex32(account.publicKeyX);
    const qy = toHex32(account.publicKeyY);

    // Encode individual parameters
    const encodedChallenge = encodeAbiParameters(
      parseAbiParameters('bytes'),
      [challenge]
    );

    const encodedAuth = encodeAbiParameters(
      parseAbiParameters('(bytes32,bytes32,uint256,uint256,bytes,string)'),
      [[authStruct.r, authStruct.s, authStruct.challengeIndex, authStruct.typeIndex, authStruct.authenticatorData, authStruct.clientDataJSON]]
    );

    const encodedQx = encodeAbiParameters(
      parseAbiParameters('bytes32'),
      [qx]
    );

    const encodedQy = encodeAbiParameters(
      parseAbiParameters('bytes32'),
      [qy]
    );

    // Format for Etherscan (array format)
    const authEtherscanFormat = `["${authStruct.r}","${authStruct.s}",${authStruct.challengeIndex},${authStruct.typeIndex},"${authStruct.authenticatorData}","${authStruct.clientDataJSON.replace(/"/g, '\\"')}"]`;

    // Log the displayed parameters for comparison
    console.group('📋 Displayed ABI Parameters');
    console.log('Challenge (raw):', challenge);
    console.log('Auth Struct:', authStruct);
    console.log('Auth (Etherscan format):', authEtherscanFormat);
    console.log('Auth (ABI encoded):', encodedAuth);
    console.log('qx:', qx);
    console.log('qy:', qy);
    console.groupEnd();

    return {
      challenge: encodedChallenge,
      auth: encodedAuth,
      qx: encodedQx,
      qy: encodedQy,
      // Raw values for Etherscan
      challengeRaw: challenge,
      authEtherscan: authEtherscanFormat,
      qxRaw: qx,
      qyRaw: qy,
    };
  };

  const copyAbiParameter = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label} copied to clipboard`);
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
              <div className="space-y-3">
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
                  {isOnChainVerificationAvailable() && (
                    <Button
                      onClick={handleVerifyOnChain}
                      variant="default"
                      size="sm"
                      disabled={onChainVerificationStatus === 'pending'}
                    >
                      <LinkIcon className="h-4 w-4 mr-1" />
                      {onChainVerificationStatus === 'pending' ? 'Verifying...' : 'Verify On-Chain'}
                    </Button>
                  )}
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

              {/* On-Chain Verification Result */}
              {onChainVerificationStatus === 'verified' && (
                <Alert className="bg-green-50 border-green-200">
                  <CheckCircle2 className="h-4 w-4 text-green-600" />
                  <AlertDescription className="text-green-800">
                    <div className="space-y-1">
                      <p className="font-medium">Signature verified on-chain successfully!</p>
                      <p className="text-sm">
                        The signature was verified using the P256Verifier contract at{' '}
                        {process.env.NEXT_PUBLIC_BLOCK_EXPLORER_URL ? (
                          <a
                            href={`${process.env.NEXT_PUBLIC_BLOCK_EXPLORER_URL}/address/${process.env.NEXT_PUBLIC_WEBAUTHN_VERIFIER_ADDRESS}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="underline hover:text-green-900 font-mono"
                          >
                            {process.env.NEXT_PUBLIC_WEBAUTHN_VERIFIER_ADDRESS}
                          </a>
                        ) : (
                          <span className="font-mono">{process.env.NEXT_PUBLIC_WEBAUTHN_VERIFIER_ADDRESS}</span>
                        )}
                      </p>
                    </div>
                  </AlertDescription>
                </Alert>
              )}

              {onChainVerificationStatus === 'failed' && (
                <Alert className="bg-red-50 border-red-200">
                  <AlertDescription className="text-red-800">
                    On-chain verification failed! Check that the contract is deployed and RPC is accessible.
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

              {/* OpenZeppelin WebAuthn Parameters */}
              <Card className="border-blue-200 bg-blue-50/50">
                <CardContent className="pt-6 space-y-4">
                  <div className="flex items-center justify-between mb-2">
                    <div>
                      <h4 className="text-sm font-semibold text-blue-900">
                        OpenZeppelin WebAuthn Parameters
                      </h4>
                      <p className="text-xs text-blue-700 mt-1">
                        Use these parameters with OpenZeppelin's WebAuthn library
                      </p>
                    </div>
                    <Button
                      onClick={copyWebAuthnParameters}
                      variant="outline"
                      size="sm"
                      className="border-blue-300 hover:bg-blue-100"
                    >
                      Copy JSON
                    </Button>
                  </div>

                  {(() => {
                    const params = getWebAuthnParameters();
                    if (!params) return null;

                    return (
                      <div className="space-y-2">
                        <code className="block p-4 bg-white rounded-md text-xs break-all font-mono whitespace-pre-wrap">
                          {JSON.stringify(params, null, 2)}
                        </code>
                      </div>
                    );
                  })()}
                </CardContent>
              </Card>

              {/* ABI Encoded Parameters */}
              <Card className="border-purple-200 bg-purple-50/50">
                <CardContent className="pt-6 space-y-4">
                  <div>
                    <h4 className="text-sm font-semibold text-purple-900 mb-1">
                      ABI Encoded Parameters
                    </h4>
                    <p className="text-xs text-purple-700">
                      Copy these encoded parameters for CLI tools (cast, chisel, etc.)
                    </p>
                  </div>

                  {(() => {
                    const encoded = getAbiEncodedParameters();
                    if (!encoded) return null;

                    return (
                      <div className="space-y-4">
                        {/* Challenge */}
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-purple-900">
                              challenge (bytes)
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyAbiParameter(encoded.challenge, 'challenge')}
                            >
                              Copy
                            </Button>
                          </div>
                          <code className="block p-3 bg-white rounded-md text-xs break-all font-mono">
                            {encoded.challenge}
                          </code>
                        </div>

                        <Separator />

                        {/* Auth Struct - Etherscan Format */}
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-purple-900">
                              auth (WebAuthnAuth) - For Etherscan
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyAbiParameter(encoded.authEtherscan, 'auth struct (Etherscan format)')}
                            >
                              Copy
                            </Button>
                          </div>
                          <code className="block p-3 bg-white rounded-md text-xs break-all font-mono">
                            {encoded.authEtherscan}
                          </code>
                          <p className="text-xs text-purple-600 mt-1">
                            Paste this directly into Etherscan's tuple field
                          </p>
                        </div>

                        <Separator />

                        {/* Auth Struct - ABI Encoded */}
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-purple-900">
                              auth (ABI Encoded)
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyAbiParameter(encoded.auth, 'auth struct (ABI encoded)')}
                            >
                              Copy
                            </Button>
                          </div>
                          <code className="block p-3 bg-white rounded-md text-xs break-all font-mono">
                            {encoded.auth}
                          </code>
                        </div>

                        <Separator />

                        {/* qx */}
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-purple-900">
                              qx (bytes32)
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyAbiParameter(encoded.qx, 'qx')}
                            >
                              Copy
                            </Button>
                          </div>
                          <code className="block p-3 bg-white rounded-md text-xs break-all font-mono">
                            {encoded.qx}
                          </code>
                        </div>

                        <Separator />

                        {/* qy */}
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-purple-900">
                              qy (bytes32)
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyAbiParameter(encoded.qy, 'qy')}
                            >
                              Copy
                            </Button>
                          </div>
                          <code className="block p-3 bg-white rounded-md text-xs break-all font-mono">
                            {encoded.qy}
                          </code>
                        </div>
                      </div>
                    );
                  })()}
                </CardContent>
              </Card>

              <div className="flex gap-2">
                <Button
                  onClick={() => {
                    setSignature(null);
                    setVerificationStatus(null);
                    setOnChainVerificationStatus(null);
                    setSignedMessage('');
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

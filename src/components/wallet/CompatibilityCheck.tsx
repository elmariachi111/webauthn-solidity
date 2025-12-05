/**
 * WebAuthn Compatibility Check Component
 */

'use client';

import { useEffect, useState } from 'react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { isWebAuthnSupported, isPlatformAuthenticatorAvailable } from '@/lib/webauthn/registration';

export function CompatibilityCheck() {
  const [supported, setSupported] = useState(false);
  const [available, setAvailable] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkCompatibility = async () => {
      const isSupported = isWebAuthnSupported();
      setSupported(isSupported);

      if (isSupported) {
        const isAvailable = await isPlatformAuthenticatorAvailable();
        setAvailable(isAvailable);
      }

      setLoading(false);
    };

    checkCompatibility();
  }, []);

  if (loading) {
    return null;
  }

  // Fully supported
  if (supported && available) {
    return (
      <Alert className="border-green-600/20 bg-green-50 dark:bg-green-950/20">
        <AlertDescription className="flex items-center gap-2">
          <Badge variant="outline" className="text-green-600 border-green-600">
            ✓ Compatible
          </Badge>
          <span className="text-green-600">
            Your device supports passkey wallets with biometric authentication
          </span>
        </AlertDescription>
      </Alert>
    );
  }

  // Supported but no platform authenticator
  if (supported && !available) {
    return (
      <Alert variant="default">
        <AlertDescription className="space-y-2">
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-yellow-600 border-yellow-600">
              ⚠ Limited Support
            </Badge>
            <span className="text-yellow-600">
              WebAuthn is supported but no platform authenticator detected
            </span>
          </div>
          <p className="text-sm text-muted-foreground">
            You can use an external security key, but biometric authentication (Touch ID, Face ID)
            may not be available on this device.
          </p>
        </AlertDescription>
      </Alert>
    );
  }

  // Not supported
  return (
    <Alert variant="destructive">
      <AlertDescription className="space-y-2">
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="border-current">
            ✗ Not Supported
          </Badge>
          <span>WebAuthn is not supported in this browser</span>
        </div>
        <p className="text-sm">
          Please use a modern browser like Chrome, Safari, Firefox, or Edge to use passkey wallets.
        </p>
      </AlertDescription>
    </Alert>
  );
}

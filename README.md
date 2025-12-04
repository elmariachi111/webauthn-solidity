# Passkey Wallet - WebAuthn Crypto Wallet

A browser-based crypto wallet that uses WebAuthn (passkeys) to sign blockchain transactions. Users authenticate using biometrics (fingerprint/Face ID) or device PIN instead of managing private keys or seed phrases.

## Project Status

✅ **Phase 1: Project Scaffold - COMPLETED**

- Next.js 15 + TypeScript configured with strict mode
- shadcn/ui setup with New York style and slate theme
- Tailwind CSS configured with animations
- Core dependencies installed
- Directory structure created
- Core type definitions established

## Tech Stack

- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript (strict mode)
- **Styling**: Tailwind CSS + shadcn/ui
- **WebAuthn**: @simplewebauthn/browser
- **Blockchain**: viem
- **Storage**: dexie (IndexedDB)
- **Icons**: lucide-react

## Project Structure

```
.
├── app/                      # Next.js app directory
│   ├── layout.tsx           # Root layout
│   ├── page.tsx             # Home page
│   ├── globals.css          # Global styles
│   └── test/                # Testing pages
├── components/
│   ├── ui/                  # shadcn/ui components
│   └── wallet/              # Wallet-specific components
├── hooks/                   # React hooks
├── lib/
│   ├── webauthn/           # WebAuthn operations
│   ├── crypto/             # Cryptographic utilities
│   ├── storage/            # IndexedDB storage
│   ├── types.ts            # Core type definitions
│   └── utils.ts            # Utility functions
└── ...config files
```

## Getting Started

### Install Dependencies

```bash
npm install
```

### Run Development Server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Testing with Chrome Virtual Authenticator

1. Open Chrome DevTools (F12)
2. Go to **Application** tab
3. Find **WebAuthn** section in the sidebar
4. Click **Enable virtual authenticator environment**
5. Click **Add authenticator**
6. Select settings:
   - Protocol: ctap2
   - Transport: internal
   - ✓ Supports resident keys
   - ✓ Supports user verification

## Next Steps

The following phases are ready to be implemented:

- **Phase 2**: WebAuthn Core Library (registration, authentication, signature parsing)
- **Phase 3**: Cryptographic Utilities (address derivation, message hashing)
- **Phase 4**: Local Storage Layer (IndexedDB for credentials)
- **Phase 5**: React Hooks (usePasskey, useWalletAccounts, useSignature)
- **Phase 6**: UI Components (wallet creation, dashboard, signing)
- **Phase 7**: Integration & Main App
- **Phase 8**: Testing & Validation

See `BROWSER_IMPLEMENTATION_EPIC.md` for detailed implementation tasks.

## Key Concepts

### WebAuthn & Passkeys

This wallet leverages WebAuthn for secure key management:

- Private keys are generated and stored in hardware (Secure Enclave, TPM, etc.)
- Keys never leave the secure hardware
- Biometric authentication (Touch ID, Face ID, Windows Hello)
- No seed phrases to manage
- Phishing-resistant (origin-bound credentials)

### P-256 Curve

Uses the secp256r1 (P-256) elliptic curve, which is:

- Natively supported by WebAuthn authenticators
- Compatible with Ethereum's Fusaka fork (secp256r1 precompile)
- NIST standardized and widely supported

## Documentation

- [Implementation Plan](./IMPLEMENTATION_PLAN.md) - Comprehensive technical guide
- [Epic Plan](./BROWSER_IMPLEMENTATION_EPIC.md) - Step-by-step action plan
- [WebAuthn Guide](https://webauthn.guide/) - WebAuthn tutorial
- [shadcn/ui Docs](https://ui.shadcn.com/) - UI component documentation

## License

MIT

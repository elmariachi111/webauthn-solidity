# Browser Implementation Epic - Passkey Crypto Wallet

## Context
This is a condensed action plan for implementing the browser client-side of a passkey-based crypto wallet. For complete technical context, architecture decisions, and boundary conditions, see [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md).

**Critical Reading**: Before starting, read the "Fundamental Boundary Conditions" section in the main plan to understand how WebAuthn keys work.

## Scope: Browser Client MVP

**What we're building**:
- TypeScript library for WebAuthn operations (passkey creation & signing)
- Simple React UI for wallet creation and transaction signing
- Local storage for public keys and credential metadata
- Signature formatting for blockchain verification

**What we're NOT building** (yet):
- Smart contract integration (handled separately)
- ERC-4337 bundler integration
- Token transfers, NFTs, or complex features
- Production-ready error handling

**Success criteria**:
- User can create a passkey (wallet)
- User can sign arbitrary messages with biometric/PIN
- Signatures are properly formatted for P-256 verification
- Works in Chrome with virtual authenticator
- Code is modular and reusable

---

## Epic Breakdown

### Phase 1: Project Setup & Dependencies
**Goal**: Set up TypeScript project with all necessary dependencies

#### Task 1.1: Initialize Next.js + TypeScript Project
- [ ] Run `npx create-next-app@latest passkey-wallet --typescript --tailwind --app`
- [ ] Configure `tsconfig.json` with strict mode
- [ ] Set up directory structure:
  ```
  src/
  ├── lib/
  │   ├── webauthn/
  │   ├── crypto/
  │   └── storage/
  ├── components/
  ├── hooks/
  └── app/
  ```

#### Task 1.2: Install Core Dependencies
- [ ] Initialize shadcn/ui: `npx shadcn@latest init`
  - [ ] Choose "New York" or "Default" style
  - [ ] Choose base color (slate recommended)
  - [ ] Enable CSS variables: Yes
- [ ] Install shadcn components: `npx shadcn@latest add button card input dialog sonner badge form label separator alert spinner`
- [ ] Install Web3 libraries: `npm install viem`
- [ ] Install utility libraries: `npm install @simplewebauthn/browser @simplewebauthn/typescript-types`
- [ ] Install storage: `npm install dexie` (IndexedDB wrapper)
- [ ] Install dev dependencies: `npm install -D @types/node`

#### Task 1.3: Configure TypeScript Types
- [ ] Create `src/lib/types.ts` with core type definitions:
  - `Credential` type (id, publicKey, createdAt)
  - `WebAuthnSignature` type (r, s, authenticatorData, clientDataJSON)
  - `WalletAccount` type (address, credentialId, publicKey)

**Deliverable**: Clean project structure with all dependencies installed

---

### Phase 2: WebAuthn Core Library
**Goal**: Build low-level WebAuthn wrapper functions

#### Task 2.1: Implement Passkey Registration
**File**: `src/lib/webauthn/registration.ts`

- [ ] Implement `createPasskey()` function:
  - [ ] Generate random challenge (32 bytes)
  - [ ] Call `navigator.credentials.create()` with proper options:
    - `alg: -7` (ES256 / P-256)
    - `authenticatorAttachment: "platform"`
    - `userVerification: "required"`
    - `residentKey: "required"`
  - [ ] Handle user cancellation gracefully
  - [ ] Return credential object

- [ ] Implement `extractPublicKey()` function:
  - [ ] Parse `attestationObject` using CBOR decoder
  - [ ] Extract `authData` from attestation
  - [ ] Locate `credentialPublicKey` in COSE format
  - [ ] Decode COSE to get P-256 coordinates (x, y)
  - [ ] Return public key as `{ x: Uint8Array, y: Uint8Array }`

- [ ] Add error handling:
  - [ ] Detect if WebAuthn not supported
  - [ ] Handle `NotAllowedError` (user cancelled)
  - [ ] Handle `NotSupportedError` (no authenticator)

**Test**: Create a passkey in Chrome DevTools virtual authenticator and extract public key

#### Task 2.2: Implement Passkey Authentication (Signing)
**File**: `src/lib/webauthn/authentication.ts`

- [ ] Implement `signWithPasskey()` function:
  - [ ] Accept `challenge: Uint8Array` and `credentialId: string`
  - [ ] Call `navigator.credentials.get()` with options:
    - `challenge` (the data to sign)
    - `allowCredentials: [{ id: credentialId }]`
    - `userVerification: "required"`
  - [ ] Return `AuthenticatorAssertionResponse`

- [ ] Implement `parseSignature()` function:
  - [ ] Extract `signature` from assertion response (DER-encoded)
  - [ ] Parse DER format to extract `r` and `s` values
  - [ ] Extract `authenticatorData` (binary blob)
  - [ ] Extract `clientDataJSON` (JSON string)
  - [ ] Return structured signature object

- [ ] Implement `formatSignatureForChain()` function:
  - [ ] Convert r, s to 32-byte big-endian format
  - [ ] Encode authenticatorData as hex
  - [ ] Find challenge offset in clientDataJSON
  - [ ] Return object ready for smart contract verification

**Test**: Sign a test message and verify signature format

#### Task 2.3: Utility Functions
**File**: `src/lib/webauthn/utils.ts`

- [ ] Implement `bufferToHex(buffer: Uint8Array): string`
- [ ] Implement `hexToBuffer(hex: string): Uint8Array`
- [ ] Implement `base64UrlToBuffer(base64url: string): Uint8Array`
- [ ] Implement `bufferToBase64Url(buffer: Uint8Array): string`
- [ ] Implement `generateChallenge(): Uint8Array` (crypto.getRandomValues)
- [ ] Implement `parseAuthenticatorData(authData: Uint8Array)`:
  - Extract RP ID hash (32 bytes)
  - Extract flags (1 byte)
  - Extract signature counter (4 bytes)

**Test**: Convert between formats, parse authenticator data

**Deliverable**: Complete WebAuthn library with registration, signing, and utilities

---

### Phase 3: Cryptographic Utilities
**Goal**: Handle blockchain-specific cryptography

#### Task 3.1: Public Key to Address Derivation
**File**: `src/lib/crypto/address.ts`

- [ ] Implement `publicKeyToAddress(x: Uint8Array, y: Uint8Array): string`:
  - [ ] Concatenate x and y coordinates (uncompressed format: 0x04 || x || y)
  - [ ] Hash with Keccak-256
  - [ ] Take last 20 bytes as Ethereum address
  - [ ] Return checksummed address (use viem's `getAddress`)

- [ ] Implement `publicKeyToHex(x: Uint8Array, y: Uint8Array): string`:
  - [ ] Return full uncompressed public key as hex string

**Test**: Verify address derivation with known test vectors

#### Task 3.2: Message Hashing
**File**: `src/lib/crypto/hashing.ts`

- [ ] Implement `hashMessage(message: string): Uint8Array`:
  - [ ] Apply EIP-191 prefix: `\x19Ethereum Signed Message:\n${length}${message}`
  - [ ] Hash with Keccak-256
  - [ ] Return as Uint8Array

- [ ] Implement `hashTypedData(domain, types, message)`:
  - [ ] Implement EIP-712 structured data hashing
  - [ ] Use viem's helper functions if available
  - [ ] Return hash as Uint8Array

**Test**: Hash test messages and compare with expected outputs

#### Task 3.3: Signature Encoding
**File**: `src/lib/crypto/signature.ts`

- [ ] Implement `parseDERSignature(derSig: Uint8Array): { r: Uint8Array, s: Uint8Array }`:
  - [ ] Parse DER structure (SEQUENCE -> INTEGER r, INTEGER s)
  - [ ] Handle variable-length integers
  - [ ] Pad to 32 bytes if needed

- [ ] Implement `encodeWebAuthnSignature(sig: WebAuthnSignature): string`:
  - [ ] ABI-encode the signature structure for smart contract
  - [ ] Include r, s, authenticatorData, clientDataJSON, challengeOffset
  - [ ] Return as hex string

**Test**: Parse DER signatures from WebAuthn, encode for blockchain

**Deliverable**: Crypto utilities for address derivation and signature handling

---

### Phase 4: Local Storage Layer
**Goal**: Persist credentials and wallet metadata

#### Task 4.1: IndexedDB Schema
**File**: `src/lib/storage/db.ts`

- [ ] Set up Dexie database with schema:
  ```typescript
  credentials: {
    id: string (credentialId, primary key)
    publicKeyX: Uint8Array
    publicKeyY: Uint8Array
    address: string
    createdAt: number
    lastUsed: number
  }
  ```

- [ ] Implement database initialization
- [ ] Add indexes for efficient queries (address, createdAt)

#### Task 4.2: Credential Storage Operations
**File**: `src/lib/storage/credentials.ts`

- [ ] Implement `saveCredential(credential: Credential): Promise<void>`
- [ ] Implement `getCredential(id: string): Promise<Credential | null>`
- [ ] Implement `getAllCredentials(): Promise<Credential[]>`
- [ ] Implement `deleteCredential(id: string): Promise<void>`
- [ ] Implement `updateLastUsed(id: string): Promise<void>`

#### Task 4.3: Wallet Account Management
**File**: `src/lib/storage/accounts.ts`

- [ ] Implement `getDefaultAccount(): Promise<WalletAccount | null>`
- [ ] Implement `setDefaultAccount(credentialId: string): Promise<void>`
- [ ] Implement `listAllAccounts(): Promise<WalletAccount[]>`

**Test**: Store and retrieve credentials, verify data persistence

**Deliverable**: Persistent storage for wallet credentials

---

### Phase 5: React Hooks & State Management
**Goal**: Create reusable hooks for wallet operations

#### Task 5.1: usePasskey Hook
**File**: `src/hooks/usePasskey.ts`

- [ ] Implement hook with methods:
  - `createWallet(username: string): Promise<WalletAccount>`
  - `signMessage(message: string): Promise<WebAuthnSignature>`
  - `isSupported(): boolean`
  - `isAvailable(): Promise<boolean>`

- [ ] Track state:
  - `loading: boolean`
  - `error: Error | null`
  - `currentAccount: WalletAccount | null`

- [ ] Handle side effects:
  - Save credential to IndexedDB after creation
  - Update lastUsed timestamp after signing

**Test**: Use hook in test component, verify state updates

#### Task 5.2: useWalletAccounts Hook
**File**: `src/hooks/useWalletAccounts.ts`

- [ ] Implement hook for managing multiple accounts:
  - `accounts: WalletAccount[]`
  - `defaultAccount: WalletAccount | null`
  - `loadAccounts(): Promise<void>`
  - `setDefault(credentialId: string): Promise<void>`
  - `deleteAccount(credentialId: string): Promise<void>`

- [ ] Use React Query or SWR for caching (optional)

**Test**: Load accounts, switch default account

#### Task 5.3: useSignature Hook
**File**: `src/hooks/useSignature.ts`

- [ ] Implement hook for signing operations:
  - `signMessage(message: string): Promise<WebAuthnSignature>`
  - `signTransaction(txData: object): Promise<WebAuthnSignature>`
  - `formatForChain(signature: WebAuthnSignature): string`

- [ ] Track signing state:
  - `signing: boolean`
  - `signature: WebAuthnSignature | null`
  - `error: Error | null`

**Test**: Sign messages, format signatures

**Deliverable**: Reusable React hooks for wallet operations

---

### Phase 6: UI Components
**Goal**: Build minimal user interface

#### Task 6.1: Create Wallet Component
**File**: `src/components/wallet/CreateWallet.tsx`

- [ ] Use shadcn `Card` component as container
- [ ] Build form using shadcn `Form` components:
  - [ ] Use `Input` with `Label` for username/email
  - [ ] Use `Button` component for "Create Wallet" action
  - [ ] Add `Spinner` component for loading state

- [ ] On submit:
  - [ ] Validate input
  - [ ] Call `createWallet()` from usePasskey hook
  - [ ] Show loading state with `Spinner` during WebAuthn prompt
  - [ ] Display created address in `Card` on success
  - [ ] Use `Badge` to show status (creating, success)
  - [ ] Handle errors with `Alert` component

**Test**: Create wallet in browser, verify passkey creation

#### Task 6.2: Wallet Dashboard Component
**File**: `src/components/wallet/WalletDashboard.tsx`

- [ ] Use shadcn `Card` components with `CardHeader`, `CardContent`
- [ ] Display current account info:
  - [ ] Ethereum address with shadcn `Button` (copy to clipboard)
  - [ ] Public key coordinates in formatted code blocks
  - [ ] Created date with `Badge` component

- [ ] Show credential metadata using `Separator` to divide sections:
  - [ ] Credential ID
  - [ ] Last used timestamp

- [ ] Add action buttons using shadcn `Button`:
  - [ ] "Sign Test Message" (primary variant)
  - [ ] "Copy Address" (secondary variant)

**Test**: View wallet info, copy address

#### Task 6.3: Sign Message Component
**File**: `src/components/wallet/SignMessage.tsx`

- [ ] Use shadcn `Dialog` component for modal signing interface
- [ ] Build form with shadcn components:
  - [ ] `Input` component for message text
  - [ ] `Button` with loading state for "Sign Message"
  - [ ] Add `Spinner` during WebAuthn prompt

- [ ] On submit:
  - [ ] Trigger WebAuthn authentication
  - [ ] Show loading spinner during biometric prompt
  - [ ] Display signature output in `Card` component
  - [ ] Use `Button` variant="outline" for "Copy Signature"
  - [ ] Format signature for blockchain

- [ ] Show signature breakdown using `Card` with sections:
  - [ ] r value (hex) - use code formatting
  - [ ] s value (hex) - use code formatting
  - [ ] Authenticator data (hex)
  - [ ] Client data JSON (decoded)
  - [ ] Add `Separator` between sections

**Test**: Sign messages, verify signature format

#### Task 6.4: Error Boundary & Toast Notifications
**File**: `src/components/ui/ErrorBoundary.tsx`, `src/app/layout.tsx`

- [ ] Implement error boundary for component errors
- [ ] Add shadcn `Sonner` toast provider to root layout
- [ ] Use `toast()` from sonner throughout the app:
  - [ ] `toast.success()` for wallet created, message signed
  - [ ] `toast.error()` for user cancelled, no authenticator
  - [ ] `toast.info()` for copied to clipboard
  - [ ] `toast.loading()` for async operations

**Test**: Trigger toasts in different scenarios, verify display

#### Task 6.5: Wallet Compatibility Check
**File**: `src/components/wallet/CompatibilityCheck.tsx`

- [ ] Check WebAuthn support:
  - [ ] `PublicKeyCredential` in window
  - [ ] `isUserVerifyingPlatformAuthenticatorAvailable()`

- [ ] Display compatibility status using shadcn `Alert` component:
  - [ ] ✅ Fully supported - use `Alert` with success styling
  - [ ] ⚠️ Supported but no platform authenticator - use `Alert` with warning styling
  - [ ] ❌ Not supported - use `Alert` with destructive styling

- [ ] Show helpful messages for unsupported browsers/devices
- [ ] Use `Badge` components to show feature availability

**Test**: Check compatibility on different browsers

**Deliverable**: Functional UI for wallet creation and message signing

---

### Phase 7: Integration & Main App
**Goal**: Wire everything together in Next.js app

#### Task 7.1: Home Page
**File**: `src/app/page.tsx`

- [ ] Check if wallet exists (query IndexedDB)
- [ ] If no wallet: Show CreateWallet component
- [ ] If wallet exists: Show WalletDashboard component
- [ ] Add compatibility check at top using CompatibilityCheck component
- [ ] Use shadcn components for layout structure

#### Task 7.2: Layout & Navigation
**File**: `src/app/layout.tsx`

- [ ] Add basic header with app title
- [ ] Include shadcn `Sonner` Toaster component for notifications
- [ ] Add global styles (shadcn CSS variables included)
- [ ] Include error boundary
- [ ] Import and configure fonts (shadcn handles this)

#### Task 7.3: Testing Page
**File**: `src/app/test/page.tsx`

- [ ] Create developer testing page with:
  - [ ] Button to create test passkey
  - [ ] Input to sign arbitrary messages
  - [ ] Display raw signature data
  - [ ] Show formatted signature for blockchain
  - [ ] Test vectors comparison

**Deliverable**: Complete Next.js app with wallet functionality

---

### Phase 8: Testing & Validation
**Goal**: Ensure everything works correctly

#### Task 8.1: Manual Testing Checklist
- [ ] Test in Chrome with virtual authenticator:
  - [ ] Enable virtual authenticator in DevTools
  - [ ] Create passkey successfully
  - [ ] Sign multiple messages
  - [ ] Verify signature format

- [ ] Test error scenarios:
  - [ ] User cancels WebAuthn prompt
  - [ ] No authenticator available
  - [ ] Invalid credential ID
  - [ ] Browser refresh (persistence)

- [ ] Test data formats:
  - [ ] Public key coordinates are valid P-256 points
  - [ ] Addresses are valid Ethereum addresses (checksummed)
  - [ ] Signatures have correct r, s values (32 bytes each)
  - [ ] AuthenticatorData is properly formatted

#### Task 8.2: Real Device Testing
- [ ] Test on real devices (if available):
  - [ ] macOS Safari with Touch ID
  - [ ] iOS Safari with Face ID/Touch ID
  - [ ] Android Chrome with fingerprint
  - [ ] Windows with Windows Hello

#### Task 8.3: Signature Verification Mock
**File**: `src/lib/crypto/verify.ts`

- [ ] Implement client-side signature verification (for testing):
  - [ ] Reconstruct signed message from authenticatorData + clientDataJSON
  - [ ] Use Web Crypto API to verify P-256 signature
  - [ ] Compare with expected result

- [ ] Add verification to test page

**Test**: Create signature and verify it locally

#### Task 8.4: Documentation
**File**: `README.md`

- [ ] Write setup instructions:
  - [ ] Install dependencies
  - [ ] Run development server
  - [ ] Enable Chrome virtual authenticator

- [ ] Document API usage:
  - [ ] How to use hooks
  - [ ] Signature format explanation
  - [ ] Integration examples

- [ ] Add troubleshooting section

**Deliverable**: Fully tested browser implementation with documentation

---

## Success Metrics

### Must Have (MVP)
✅ User can create a passkey wallet
✅ User can sign messages with biometric authentication
✅ Public key correctly extracted from WebAuthn credential
✅ Ethereum address correctly derived from P-256 public key
✅ Signatures properly formatted for blockchain verification
✅ Data persists across browser sessions
✅ Works in Chrome DevTools virtual authenticator

### Nice to Have (V1)
⭐ Multiple wallet support
⭐ Transaction preview before signing
⭐ Export public key in various formats
⭐ QR code display for address
⭐ Real device testing (iOS/Android)

### Future (V2)
🚀 Smart contract integration
🚀 ERC-4337 UserOperation building
🚀 Gas estimation
🚀 Transaction history
🚀 DApp connection (WalletConnect)

---

## Tech Stack Summary

**Core**:
- Next.js 14+ (App Router)
- TypeScript (strict mode)
- React 18+

**WebAuthn**:
- `@simplewebauthn/browser` - WebAuthn helpers
- Native Web Crypto API - Signature parsing

**Blockchain**:
- `viem` - Ethereum utilities (address, hashing, encoding)

**Storage**:
- `dexie` - IndexedDB wrapper

**UI**:
- shadcn/ui - Component library (built on Radix UI + Tailwind CSS)
- Sonner - Toast notifications
- Tailwind CSS - Utility-first styling (included with shadcn)

**Dev Tools**:
- Chrome DevTools Virtual Authenticator

---

## Getting Started Command Sequence

```bash
# 1. Initialize Next.js project
npx create-next-app@latest passkey-wallet --typescript --tailwind --app
cd passkey-wallet

# 2. Initialize shadcn/ui
npx shadcn@latest init
# Choose: New York style, slate base color, CSS variables: Yes

# 3. Add shadcn components
npx shadcn@latest add button card input dialog sonner badge form label separator alert spinner

# 4. Install additional dependencies
npm install viem @simplewebauthn/browser @simplewebauthn/typescript-types dexie
npm install -D @types/node

# 5. Create directory structure
mkdir -p src/lib/webauthn src/lib/crypto src/lib/storage src/hooks src/components/wallet

# 6. Start implementing tasks in order (Phase 1 → Phase 8)

# 7. Run dev server
npm run dev

# 8. Open Chrome DevTools → Application → WebAuthn → Enable Virtual Authenticator
```

---

## Notes for Specialized Agent

1. **Work sequentially**: Complete each phase before moving to the next
2. **Test as you go**: Don't accumulate untested code
3. **Keep it simple**: This is MVP - avoid over-engineering
4. **Focus on browser**: Ignore smart contract integration for now
5. **Reference main plan**: Check `IMPLEMENTATION_PLAN.md` for detailed context when needed
6. **Use TypeScript strictly**: Proper types prevent bugs
7. **Handle errors gracefully**: WebAuthn has many failure modes
8. **Log everything**: Console.log signature data during development
9. **shadcn/ui usage**: Components are copied into your project (in `src/components/ui/`), so you can customize them freely. Import like: `import { Button } from "@/components/ui/button"`

**Key Files to Refer Back To**:
- `IMPLEMENTATION_PLAN.md` - Full technical context
- Phase 2, Task 2.1 in main plan - Detailed WebAuthn registration
- Phase 2, Task 2.2 in main plan - Detailed WebAuthn authentication
- "Fundamental Boundary Conditions" section - Critical constraints

**When Stuck**:
1. Read the "Fundamental Boundary Conditions" section
2. Check MDN WebAuthn documentation
3. Use Chrome DevTools to inspect WebAuthn objects
4. Test with virtual authenticator before real devices
5. Verify signature format matches expected blockchain format

Good luck! 🚀

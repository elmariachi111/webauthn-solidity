# Passkey Crypto Wallet - Browser Client Implementation Plan

## Overview
Build a browser-based crypto wallet that uses WebAuthn (passkeys) to sign blockchain transactions. Users authenticate using biometrics (fingerprint/Face ID) or device PIN instead of managing private keys or seed phrases.

## Technical Foundation

### Core Technology: WebAuthn API
- **Standard**: FIDO2/WebAuthn protocol
- **Curve**: P-256 (secp256r1) - natively supported by WebAuthn authenticators
- **Browser Support**: Chrome, Safari, Firefox, Edge (all modern versions)
- **On-chain**: Ethereum Fusaka fork provides native secp256r1 precompile

### Key Advantages
- Private keys never leave secure hardware (Secure Enclave, TPU, etc.)
- Biometric authentication (Touch ID, Face ID, Windows Hello)
- No seed phrases to manage or lose
- Phishing-resistant (origin-bound credentials)
- Cross-device sync via platform providers (iCloud Keychain, Google Password Manager)

## Fundamental Boundary Conditions: How WebAuthn Keys Work

**CRITICAL UNDERSTANDING**: Before implementing any crypto wallet using WebAuthn, you must understand where keys are created, stored, and how they're unlocked. This is fundamentally different from traditional crypto wallets.

### Key Generation: Where and How

**Location**: Keys are generated **inside the authenticator**, NOT in the browser or JavaScript.

When you call `navigator.credentials.create()`:
1. The browser forwards the request to the **platform authenticator** (built into the device)
2. The authenticator's **hardware security module** generates the key pair:
   - iOS devices: **Secure Enclave** (dedicated cryptographic coprocessor)
   - macOS: **Secure Enclave** in T2 or Apple Silicon chips
   - Windows: **TPM (Trusted Platform Module)** chip
   - Android: **Hardware-backed Keystore** / TEE (Trusted Execution Environment)
3. Key generation happens in **secure hardware** isolated from the main processor
4. The **private key never leaves** this secure environment - not even to the OS or browser

**What the browser receives**:
- The **public key** (in COSE format within the attestationObject)
- A **credential ID** (randomly generated identifier)
- An **attestation signature** (proving the key was created by legitimate hardware)

**What stays in hardware**:
- The **private key** (permanently stored in secure enclave/TPM)
- Any secrets used for key derivation

### Key Storage: Physical Security Guarantees

**Storage Location**: Private keys are stored in **tamper-resistant hardware**:

| Platform | Storage Location | Security Features |
|----------|-----------------|-------------------|
| iOS/macOS | Secure Enclave | - Isolated from main CPU<br>- Encrypted storage<br>- Physical tamper detection<br>- Keys never accessible to software |
| Windows | TPM 2.0 | - Hardware-isolated cryptoprocessor<br>- Secure key storage<br>- Platform integrity verification |
| Android | Hardware Keystore | - TEE (Trusted Execution Environment)<br>- Isolated secure processor<br>- StrongBox (on supported devices) |

**Key Characteristics**:
- **Non-extractable**: Private keys cannot be exported or copied
- **Device-bound**: Keys are tied to specific hardware (for platform authenticators)
- **Persistence**: Keys survive app uninstalls, browser cache clears, etc.
- **Isolation**: Even with root/admin access, private keys cannot be extracted

**Synced Passkeys** (Important Exception):
- Modern platforms (iOS 16+, macOS Ventura+, Android 14+) support **passkey syncing**
- Synced via: iCloud Keychain (Apple) or Google Password Manager (Android/Chrome)
- Keys are encrypted before sync using platform-specific E2E encryption
- This enables multi-device access but sacrifices pure device-binding

### Key Unlocking: User Verification Process

**User Verification**: The process of proving the legitimate user is present.

When you call `navigator.credentials.get()` with `userVerification: "required"`:
1. Browser forwards the signing request to the authenticator
2. Authenticator **prompts for user verification**:
   - **Biometric**: Fingerprint (Touch ID, Windows Hello), Face recognition (Face ID)
   - **PIN**: Local device PIN (fallback when biometric fails)
   - **Password**: Device password (rare, least convenient)
3. **Verification happens in hardware** - biometric data never leaves the secure enclave
4. If verification succeeds, authenticator **uses private key to sign** the challenge
5. Authenticator returns the **signature** (not the key!) to the browser

**Important Security Notes**:
- **Biometric data is never transmitted** - it stays in the secure enclave
- Biometrics are just a **local unlock mechanism** for the private key
- **PIN is mandatory**: You cannot have biometric-only; PIN is required as fallback
- User verification settings:
  - `"required"`: Always prompt for biometric/PIN (recommended for crypto)
  - `"preferred"`: Prompt if available, skip if not
  - `"discouraged"`: Don't verify user (just test device presence)

### Browser vs Authenticator Roles

**What the Browser Does**:
- Provides JavaScript API (`navigator.credentials`)
- Mediates communication between web app and authenticator
- Enforces **origin binding** (credentials tied to your domain)
- Handles CORS and security contexts (HTTPS requirement)
- Formats requests/responses according to WebAuthn spec

**What the Browser CANNOT Do**:
- Access or extract private keys
- Perform signing operations directly
- Override authenticator security policies
- Access biometric data

**What the Authenticator Does**:
- Generate cryptographic keys in secure hardware
- Store private keys securely
- Perform all cryptographic operations (signing)
- Verify user identity (biometrics/PIN)
- Enforce security policies

**What the Authenticator CANNOT Do**:
- Be bypassed by software (even with root access)
- Export private keys
- Sign without user verification (when required)

### Critical Implications for Crypto Wallet Implementation

#### 1. **You Never Handle Private Keys**
```javascript
// ❌ WRONG - This never happens with WebAuthn
const privateKey = generatePrivateKey();
storePrivateKey(privateKey);
const signature = sign(message, privateKey);

// ✅ CORRECT - You request operations from the authenticator
const credential = await navigator.credentials.create({...});
const publicKey = extractPublicKey(credential); // You only get the public key
// Later, when signing:
const signature = await navigator.credentials.get({challenge: message});
```

#### 2. **Signing is Always Async and User-Interactive**
- Every signature requires user verification (biometric/PIN)
- Users see a system dialog (you can't bypass or customize it)
- Signing takes 1-5 seconds (human interaction time)
- Cannot "batch sign" multiple transactions without multiple prompts

#### 3. **Keys are Opaque References**
```javascript
// You work with credential IDs (references), not keys
const credentialId = credential.id; // A random identifier
// Store this ID to reference the key later
// The actual private key is in hardware, inaccessible
```

#### 4. **Origin Binding is Enforced**
- Keys created on `wallet.example.com` only work on `wallet.example.com`
- Cannot be used on `wallet.example.org` or `attacker.com`
- This prevents phishing but means you need consistent domain/subdomain strategy

#### 5. **No "Export Seed Phrase" Feature**
- Private keys are non-extractable by design
- Cannot implement traditional crypto wallet backup/recovery
- Must rely on:
  - Platform passkey sync (iCloud/Google)
  - Multi-device registration (register passkeys on multiple devices)
  - Smart contract recovery mechanisms (guardians, social recovery)

#### 6. **Signature Format is Fixed**
WebAuthn produces a specific signature format:
```javascript
// What you sign (constructed by authenticator):
SHA256(authenticatorData || SHA256(clientDataJSON))
// NOT just SHA256(yourMessage)
```
Your smart contract must verify this exact structure.

#### 7. **Platform Compatibility Considerations**
- All modern browsers (2025) support WebAuthn
- All modern devices have secure hardware (Secure Enclave/TPM)
- BUT: Older devices (pre-2016) may lack hardware authenticators
- Detection strategy needed: `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`

### Development and Testing Considerations

**Virtual Authenticators**:
- Chrome DevTools includes virtual authenticator for testing
- Simulates secure hardware without physical device
- Useful for development but test on real devices before production

**Testing Real Hardware**:
- iOS Safari: Test Touch ID / Face ID flows
- macOS Safari: Test Touch ID on MacBook Pro
- Windows: Test Windows Hello (fingerprint or face)
- Android Chrome: Test fingerprint on Android devices

**Edge Cases to Handle**:
- User cancels biometric prompt → Graceful error handling
- No authenticator available → Show helpful error message
- Biometric fails multiple times → System falls back to PIN
- Device doesn't support platform authenticator → Suggest security key alternative

### Key Takeaways for Implementation

✅ **Your application's job**:
- Request credential creation/authentication from the browser
- Extract and store public keys and credential IDs
- Format transaction data as WebAuthn challenges
- Parse signatures and send to blockchain
- Provide clear UX explaining what user is signing

❌ **What you cannot do**:
- Access or manage private keys
- Sign without user interaction
- Bypass biometric/PIN verification
- Use credentials across different domains
- Export keys for traditional wallet backup

🔒 **Security guarantees you get for free**:
- Hardware-protected key storage
- Phishing resistance (origin binding)
- No key exposure to malware
- Physical user presence required for signing
- Biometric/PIN verification

This fundamental understanding shapes every implementation decision. Unlike traditional crypto wallets where you manage keys in software, WebAuthn wallets delegate all key operations to secure hardware, trading flexibility for security and UX.

---

## Implementation Phases

### Phase 1: WebAuthn Integration & Key Management

#### 1.1 Passkey Registration (Account Creation)
**Goal**: Generate a new passkey credential for the user

**Implementation**:
```javascript
// Use navigator.credentials.create() to generate new passkey
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: randomChallenge,
    rp: {
      name: "Your Wallet Name",
      id: "yourdomain.com"
    },
    user: {
      id: userIdentifier,
      name: userEmail,
      displayName: userDisplayName
    },
    pubKeyCredParams: [
      { alg: -7, type: "public-key" }  // ES256 (P-256)
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",  // Use device authenticator
      userVerification: "required",
      residentKey: "required"  // Enables discoverable credentials
    },
    timeout: 60000
  }
});
```

**Extract Public Key**:
- Parse the `credential.response.attestationObject`
- Extract the COSE-encoded public key
- Convert to raw P-256 coordinates (x, y)
- Derive Ethereum address from public key

**Store Metadata**:
- Credential ID (for future authentication)
- Public key (x, y coordinates)
- Associated Ethereum address
- Store in local database (IndexedDB)

#### 1.2 Passkey Authentication (Signing)
**Goal**: Use existing passkey to sign transaction data

**Implementation**:
```javascript
// Use navigator.credentials.get() to sign data
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: messageHash,  // The data to sign
    rpId: "yourdomain.com",
    allowCredentials: [{
      id: credentialId,
      type: "public-key"
    }],
    userVerification: "required",
    timeout: 60000
  }
});
```

**Extract Signature**:
- Parse `assertion.response.signature` (DER-encoded)
- Extract r and s values
- Format for Ethereum verification (r, s, v)
- Include authenticatorData and clientDataJSON for full WebAuthn verification

### Phase 2: Blockchain Transaction Signing

#### 2.1 Message Formatting
**Goal**: Format blockchain transactions for WebAuthn signing

**Key Considerations**:
- WebAuthn signs: `SHA256(authenticatorData || SHA256(clientDataJSON))`
- Smart contract needs to verify this exact structure
- Challenge field in clientDataJSON contains our transaction hash

**Implementation Strategy**:
```javascript
// 1. Create transaction data
const txData = {
  to: recipientAddress,
  value: amount,
  nonce: accountNonce,
  // ... other tx fields
};

// 2. Hash the transaction
const txHash = keccak256(encodeTxData(txData));

// 3. Use txHash as WebAuthn challenge
const challenge = txHash;

// 4. Get signature via WebAuthn
const signature = await signWithPasskey(challenge, credentialId);

// 5. Package for smart contract
const signaturePackage = {
  r: signature.r,
  s: signature.s,
  authenticatorData: signature.authenticatorData,
  clientDataJSON: signature.clientDataJSON,
  challengeOffset: signature.challengeOffset,
  txData: txData
};
```

#### 2.2 Signature Verification Data
**What the smart contract needs**:
- `r`, `s`: P-256 signature components
- `authenticatorData`: Binary blob from authenticator
- `clientDataJSON`: JSON string containing challenge
- `challengeOffset`: Position of challenge in clientDataJSON
- Transaction data to verify

### Phase 3: Account Abstraction Integration (ERC-4337)

#### 3.1 Smart Contract Wallet Setup
**Architecture**:
- Smart contract account (not EOA)
- Implements ERC-4337 `validateUserOp`
- Uses Fusaka's secp256r1 precompile for verification

**Key Benefits**:
- Gas sponsorship (gasless transactions)
- Batched operations
- Social recovery
- Spending limits and other policies

#### 3.2 UserOperation Construction
**Goal**: Build ERC-4337 UserOperations signed by passkey

```javascript
// Construct UserOperation
const userOp = {
  sender: smartAccountAddress,
  nonce: await account.getNonce(),
  initCode: "0x",
  callData: encodedFunctionCall,
  callGasLimit: estimatedGas,
  // ... other fields
};

// Sign UserOperation with passkey
const userOpHash = getUserOpHash(userOp, entryPoint, chainId);
const signature = await signWithPasskey(userOpHash, credentialId);

// Add WebAuthn signature to userOp
userOp.signature = encodeWebAuthnSignature(signature);
```

### Phase 4: User Experience & Client Application

#### 4.1 Application Architecture
**Tech Stack Suggestions**:
- **Framework**: React or Next.js (TypeScript)
- **State Management**: Zustand or Redux
- **Web3 Library**: viem or ethers.js
- **Storage**: IndexedDB (via Dexie.js)
- **UI Components**: shadcn/ui or similar

**Directory Structure**:
```
src/
├── lib/
│   ├── webauthn/
│   │   ├── registration.ts      # Passkey creation
│   │   ├── authentication.ts    # Passkey signing
│   │   ├── utils.ts             # COSE parsing, DER decoding
│   │   └── types.ts
│   ├── blockchain/
│   │   ├── account.ts           # Smart account interaction
│   │   ├── transactions.ts      # Transaction building
│   │   ├── userops.ts           # ERC-4337 UserOps
│   │   └── signature.ts         # Signature formatting
│   ├── storage/
│   │   ├── db.ts                # IndexedDB setup
│   │   └── credentials.ts       # Credential management
│   └── utils/
│       ├── crypto.ts            # Hashing, encoding
│       └── encoding.ts          # ABI encoding, etc.
├── components/
│   ├── wallet/
│   │   ├── CreateWallet.tsx
│   │   ├── WalletDashboard.tsx
│   │   ├── SendTransaction.tsx
│   │   └── TransactionHistory.tsx
│   └── ui/                      # Reusable UI components
├── hooks/
│   ├── usePasskey.ts
│   ├── useSmartAccount.ts
│   └── useTransactions.ts
└── app/                         # Next.js pages/routes
```

#### 4.2 Core User Flows

**Flow 1: Create Wallet**
1. User clicks "Create Wallet"
2. Prompt for name/email (user metadata)
3. Trigger WebAuthn registration
4. User authenticates with biometric/PIN
5. Extract public key from credential
6. Deploy smart contract account (or deterministic address)
7. Store credential info locally
8. Show wallet address & success message

**Flow 2: Send Transaction**
1. User enters recipient & amount
2. Build transaction data
3. Estimate gas & show preview
4. User confirms
5. Trigger WebAuthn authentication with tx hash
6. User authenticates with biometric/PIN
7. Build UserOperation with signature
8. Submit to bundler
9. Show pending status
10. Confirm on-chain & update UI

**Flow 3: Sign Message**
1. DApp requests message signature
2. Show message to user
3. User confirms
4. Hash message (EIP-191 or EIP-712)
5. Sign with passkey
6. Return signature to DApp

#### 4.3 Error Handling & Edge Cases
- **No Authenticator Available**: Detect and show helpful message
- **User Cancels**: Handle gracefully, don't show errors
- **Credential Not Found**: Guide user to re-register
- **Network Errors**: Retry logic with exponential backoff
- **Transaction Failures**: Parse and display readable errors

### Phase 5: Security Considerations

#### 5.1 Best Practices
- **Origin Binding**: WebAuthn credentials are bound to your domain
- **User Verification**: Always require `userVerification: "required"`
- **Resident Keys**: Use `residentKey: "required"` for discoverable credentials
- **HTTPS Only**: WebAuthn requires secure context
- **Challenge Randomness**: Use cryptographically secure random challenges

#### 5.2 Attack Mitigations
- **Phishing**: Origin-bound credentials prevent phishing
- **MITM**: HTTPS + origin binding
- **Replay Attacks**: Use nonces in transactions
- **Social Engineering**: Clear UIs showing what's being signed

### Phase 6: Testing & Development

#### 6.1 Development Environment
- **Local Testing**: Use `localhost` (allowed by WebAuthn)
- **Virtual Authenticators**: Chrome DevTools supports virtual authenticators
- **Test Network**: Deploy smart contracts to Sepolia or local fork
- **Bundler**: Run local ERC-4337 bundler for testing

#### 6.2 Testing Checklist
- [ ] Passkey registration flow
- [ ] Multiple credentials per user
- [ ] Signature verification matches on-chain logic
- [ ] Transaction simulation before signing
- [ ] Error handling for all edge cases
- [ ] Cross-browser testing (Chrome, Safari, Firefox)
- [ ] Mobile device testing (iOS, Android)
- [ ] Recovery scenarios (lost device, etc.)

## Technical Challenges & Solutions

### Challenge 1: WebAuthn Signature Format
**Problem**: WebAuthn produces complex signature structure
**Solution**:
- Parse authenticatorData and clientDataJSON
- Reconstruct signing message on-chain
- Use FreshCryptoLib or Daimo's p256-verifier patterns

### Challenge 2: Public Key Extraction
**Problem**: Public key is COSE-encoded in attestation object
**Solution**:
- Use CBOR library to parse attestationObject
- Extract public key coordinates (x, y)
- Convert to Ethereum address format

### Challenge 3: Transaction Previewing
**Problem**: Users need to see what they're signing
**Solution**:
- Decode transaction data before signing
- Show human-readable transaction details
- Simulate transaction to predict outcome

### Challenge 4: Multi-Device Support
**Problem**: User wants to access wallet from multiple devices
**Solution** (Options):
1. **Passkey Sync**: Rely on iCloud/Google sync (easiest)
2. **Multi-Credential**: Register passkeys on multiple devices
3. **Recovery Mechanism**: Guardian wallets or social recovery

## Implementation Priorities

### MVP (Minimum Viable Product)
1. ✅ WebAuthn registration (create passkey)
2. ✅ WebAuthn authentication (sign data)
3. ✅ Basic smart contract wallet
4. ✅ Send ETH transaction
5. ✅ Simple UI for wallet creation & sending

### V1 (Enhanced Experience)
6. Multi-credential support (multiple passkeys)
7. Transaction history & status tracking
8. Token transfers (ERC-20)
9. Gas estimation & optimization
10. Better error handling & UX

### V2 (Advanced Features)
11. Batch transactions
12. Session keys for DApp interactions
13. Spending limits & policies
14. Social recovery
15. NFT support

## Next Steps

1. **Set up project structure** (React/Next.js with TypeScript)
2. **Implement WebAuthn wrapper library** (`lib/webauthn/`)
3. **Build registration flow** (create passkey + extract public key)
4. **Build authentication flow** (sign arbitrary data)
5. **Create simple UI** (wallet creation page)
6. **Test in browser** (Chrome DevTools virtual authenticator)
7. **Integrate with smart contract** (once deployed)

## Resources & References

### Documentation
- [WebAuthn Guide](https://webauthn.guide/) - Comprehensive WebAuthn tutorial
- [MDN Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) - Official API docs
- [MDN Attestation and Assertion](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion) - Key generation process
- [W3C WebAuthn Level 2 Spec](https://www.w3.org/TR/webauthn-2/) - Official specification
- [Stackup Passkeys Guide](https://www.stackup.fi/resources/passkeys-webauthn-erc4337) - ERC-4337 + WebAuthn
- [Daimo P256 Verifier](https://daimo.com/blog/p256verifier) - Audited Solidity implementation
- [Corbado: What Is a Secure Enclave in WebAuthn](https://www.corbado.com/glossary/secure-enclave) - Hardware security details
- [Corbado: Passkeys & WebAuthn PRF for E2E Encryption](https://www.corbado.com/blog/passkeys-prf-webauthn) - Advanced features
- [Microsoft Learn: Passkeys (FIDO2) in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passkeys-fido2) - Platform implementation

### Open Source Examples
- [passkeys-4337/smart-wallet](https://github.com/passkeys-4337/smart-wallet) - ERC-4337 passkey wallet
- [daimo-eth/p256-verifier](https://github.com/daimo-eth/p256-verifier) - P-256 verification in Solidity
- [base/webauthn-sol](https://github.com/base/webauthn-sol) - Base's WebAuthn Solidity library
- [wevm/webauthn-p256](https://github.com/wevm/webauthn-p256) - P-256 utilities for WebAuthn

### Technical Articles
- [Solana Passkeys by Helius](https://www.helius.dev/blog/solana-passkeys)
- [Medium: WebAuthn and Passkey for Crypto Users](https://medium.com/@poporuii/webauthn-and-passkey-key-management-for-daily-crypto-users-ea13c918c10c)
- [TokenSight: ERC-4337 WebAuthn Accounts](https://tokensight.medium.com/research-erc-4337-webauthn-accounts-ab99aff199ea)

---

**Ready to build!** This plan provides a comprehensive roadmap for implementing the browser client-side of your passkey wallet. The next step is to start with Phase 1 (WebAuthn Integration) and build iteratively.

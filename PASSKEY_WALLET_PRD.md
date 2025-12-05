# Passkey Wallet - Product Requirements Document

## Overview

A decentralized Ethereum wallet secured by WebAuthn passkeys (P-256 keys in Secure Enclave/TPM) with on-chain public key storage via smart contract wallets.

## Current State

### What Works
- ✅ WebAuthn passkey creation using P-256 (ES256) algorithm
- ✅ Private keys stored in hardware security modules (Secure Enclave, TPM)
- ✅ Passkeys sync across devices via iCloud Keychain / platform authenticators
- ✅ Signature generation using biometric authentication
- ✅ Signature malleability protection (secp256r1 normalization)
- ✅ Public key extraction from attestation object using CBOR decoding
- ✅ Ethereum address derivation from P-256 public key

### Current Limitations
- ❌ Public key stored in IndexedDB (browser-local storage)
- ❌ Not portable: clearing browser data loses wallet access
- ❌ New device requires IndexedDB to have the public key mapping
- ❌ No on-chain verification of ownership
- ❌ Centralized trust in client-side storage

## Problem Statement

**WebAuthn only returns the public key during passkey creation, not during authentication.**

When a user authenticates with an existing passkey (especially on a new device):
1. The Secure Enclave provides the credential ID and signature
2. The public key is NOT provided by the authenticator
3. The app has no way to know which Ethereum address corresponds to this passkey

**Current workaround (IndexedDB) fails because:**
- Browser storage is not portable across devices
- Clearing browser data = losing wallet access forever
- Not suitable for a production crypto wallet

## Proposed Solution: On-Chain Public Key Storage

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Flow                               │
└─────────────────────────────────────────────────────────────┘

1. CREATE WALLET
   ┌──────────────┐
   │ User creates │ → Biometric prompt
   │   passkey    │
   └──────┬───────┘
          │
          ├─→ Secure Enclave generates P-256 key pair
          │   └─→ Private key: stays in secure hardware
          │   └─→ Public key: returned in attestation object
          │
          ├─→ App deploys Smart Contract Wallet
          │   └─→ constructor(bytes32 credentialId, uint256[2] publicKey)
          │   └─→ Maps credentialId → publicKey on-chain
          │
          └─→ Wallet address = smart contract address

2. SIGN IN (New Device)
   ┌──────────────┐
   │ User enters  │
   │ credential   │ (optional: could use passkey picker)
   │     ID       │
   └──────┬───────┘
          │
          ├─→ Query blockchain: getPublicKey(credentialId)
          │   └─→ Returns public key from smart contract
          │
          ├─→ Derive Ethereum address from public key
          │
          ├─→ User authenticates with passkey (biometric)
          │   └─→ Secure Enclave signs challenge
          │
          └─→ Wallet restored with full functionality

3. SIGN TRANSACTION
   ┌──────────────┐
   │ User signs   │ → Biometric prompt
   │ transaction  │
   └──────┬───────┘
          │
          ├─→ Secure Enclave signs transaction hash
          │   └─→ Returns (r, s) signature components
          │
          ├─→ Smart contract verifies signature
          │   └─→ Uses stored public key for verification
          │   └─→ Executes transaction if valid
          │
          └─→ Transaction submitted to network
```

### Smart Contract Architecture

#### AccountWallet.sol (ERC-4337 Compatible)

```solidity
contract AccountWallet {
    // Credential ID → Public Key mapping
    mapping(bytes32 => PublicKey) public controllers;

    struct PublicKey {
        uint256 x;
        uint256 y;
        bool active;
    }

    // Primary controller (first passkey)
    bytes32 public primaryController;

    constructor(
        bytes32 credentialId,
        uint256 publicKeyX,
        uint256 publicKeyY
    ) {
        controllers[credentialId] = PublicKey({
            x: publicKeyX,
            y: publicKeyY,
            active: true
        });
        primaryController = credentialId;
    }

    // Verify WebAuthn signature
    function verifySignature(
        bytes32 credentialId,
        bytes32 messageHash,
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint256 r,
        uint256 s
    ) public view returns (bool) {
        PublicKey memory pubKey = controllers[credentialId];
        require(pubKey.active, "Controller not found");

        // Reconstruct signed message per WebAuthn spec
        bytes32 clientDataHash = sha256(bytes(clientDataJSON));
        bytes32 signedMessage = sha256(
            abi.encodePacked(authenticatorData, clientDataHash)
        );

        // Verify P-256 signature using precompile or library
        return verifyP256Signature(
            signedMessage,
            r, s,
            pubKey.x, pubKey.y
        );
    }

    // Add additional passkey (recovery/multi-device)
    function addController(
        bytes32 credentialId,
        uint256 publicKeyX,
        uint256 publicKeyY
    ) external {
        require(msg.sender == address(this), "Only self");
        controllers[credentialId] = PublicKey({
            x: publicKeyX,
            y: publicKeyY,
            active: true
        });
    }

    // Execute transaction (ERC-4337 compatible)
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external {
        require(msg.sender == address(this), "Only self");
        (bool success, ) = dest.call{value: value}(func);
        require(success, "Execution failed");
    }
}
```

#### WalletFactory.sol

```solidity
contract WalletFactory {
    event WalletCreated(
        address indexed wallet,
        bytes32 indexed credentialId,
        address indexed owner
    );

    mapping(bytes32 => address) public walletsByCredential;

    function createWallet(
        bytes32 credentialId,
        uint256 publicKeyX,
        uint256 publicKeyY
    ) external returns (address) {
        require(
            walletsByCredential[credentialId] == address(0),
            "Wallet already exists for this credential"
        );

        AccountWallet wallet = new AccountWallet(
            credentialId,
            publicKeyX,
            publicKeyY
        );

        address walletAddress = address(wallet);
        walletsByCredential[credentialId] = walletAddress;

        emit WalletCreated(walletAddress, credentialId, msg.sender);

        return walletAddress;
    }

    function getWallet(bytes32 credentialId)
        external
        view
        returns (address)
    {
        return walletsByCredential[credentialId];
    }

    function getPublicKey(bytes32 credentialId)
        external
        view
        returns (uint256 x, uint256 y)
    {
        address wallet = walletsByCredential[credentialId];
        require(wallet != address(0), "Wallet not found");

        AccountWallet walletContract = AccountWallet(wallet);
        (uint256 pkX, uint256 pkY, bool active) = walletContract.controllers(credentialId);
        require(active, "Controller inactive");

        return (pkX, pkY);
    }
}
```

## User Flows

### 1. First-Time User (Create Wallet)

```
Step 1: User enters username/email
Step 2: Click "Create New Wallet"
Step 3: Browser shows passkey creation prompt
        → "Save passkey for yourapp.com?"
        → Face ID / Touch ID / Fingerprint scan
Step 4: App extracts public key from attestation
Step 5: App deploys smart contract wallet
        → credentialId = hash of rawId
        → publicKey = (x, y) coordinates
        → Wallet address = contract address
Step 6: Show user their wallet address
        → Store credentialId in localStorage (optional)
        → User can now send funds to this address
```

### 2. Returning User (Same Device)

```
Step 1: User clicks "Sign In with Existing Passkey"
Step 2: Browser shows passkey picker (native UI)
        → Lists all passkeys for this domain
        → Stored in Secure Enclave / iCloud Keychain
Step 3: User selects passkey + biometric auth
Step 4: App receives credentialId from authenticator
Step 5: App queries blockchain:
        → walletFactory.getPublicKey(credentialId)
        → Returns (x, y) public key coordinates
Step 6: App derives Ethereum address from public key
Step 7: Wallet restored - user can sign transactions
```

### 3. New Device (Same iCloud Keychain)

```
Step 1: User has passkey synced via iCloud Keychain
Step 2: User enters credentialId OR uses passkey picker
        Option A: User provides credentialId (from another device)
        Option B: User clicks "Sign In" → passkey picker
Step 3: Biometric authentication
Step 4: App receives credentialId from authenticator
Step 5: App queries blockchain for public key
        → walletFactory.getPublicKey(credentialId)
Step 6: Wallet restored on new device
        → Same address
        → Same public key
        → Can sign transactions immediately
```

### 4. Sign Transaction

```
Step 1: User initiates transaction (send ETH, call contract)
Step 2: App constructs transaction data
Step 3: App creates WebAuthn challenge from tx hash
Step 4: User authenticates with biometric
Step 5: Secure Enclave returns signature (r, s)
Step 6: App submits to smart contract wallet:
        → wallet.execute(dest, value, data, signature)
Step 7: Contract verifies signature on-chain
        → Uses stored public key
        → Checks authenticatorData, clientDataJSON
Step 8: If valid, contract executes transaction
```

## Technical Implementation

### Frontend Changes

#### 1. Registration Flow (Create Wallet)

```typescript
async function createWallet(username: string) {
  // 1. Create passkey (existing)
  const { credentialId, publicKey } = await createPasskey(username);

  // 2. Deploy smart contract wallet
  const walletAddress = await deploySmartWallet({
    credentialId: credentialIdToBytes32(credentialId),
    publicKeyX: publicKey.x,
    publicKeyY: publicKey.y,
  });

  // 3. Optional: Store credentialId in localStorage for convenience
  localStorage.setItem('lastCredentialId', credentialId);

  return {
    walletAddress,
    credentialId,
    publicKey,
  };
}
```

#### 2. Authentication Flow (Sign In)

```typescript
async function signInWithPasskey(credentialId?: string) {
  // 1. Authenticate with passkey
  let actualCredentialId: string;

  if (credentialId) {
    // User provided credential ID
    await authenticateWithCredential(credentialId);
    actualCredentialId = credentialId;
  } else {
    // Use passkey picker
    const result = await authenticateWithPasskey();
    actualCredentialId = result.credentialId;
  }

  // 2. Query blockchain for public key
  const publicKey = await walletFactory.getPublicKey(
    credentialIdToBytes32(actualCredentialId)
  );

  // 3. Derive wallet address
  const walletAddress = await walletFactory.getWallet(
    credentialIdToBytes32(actualCredentialId)
  );

  return {
    walletAddress,
    credentialId: actualCredentialId,
    publicKey,
  };
}
```

#### 3. Remove IndexedDB Dependency

```typescript
// BEFORE: Store in IndexedDB
await saveCredential({
  id: credentialId,
  publicKeyX: publicKey.x,
  publicKeyY: publicKey.y,
  address: walletAddress,
});

// AFTER: Query from blockchain
const publicKey = await walletFactory.getPublicKey(credentialId);
const walletAddress = await walletFactory.getWallet(credentialId);
```

### Smart Contract Deployment

#### Network Support
- Ethereum Mainnet
- Optimism (cheaper gas for verification)
- Arbitrum (cheaper gas for verification)
- Base (recommended: cheap + good UX)
- Polygon (fallback option)

#### Gas Optimization
- Use CREATE2 for deterministic addresses
- Batch verification in one call
- Cache public keys in contract storage
- Consider EIP-7212 (native P-256 verification) when available

#### P-256 Signature Verification

**Option 1: Use RIP-7212 Precompile (if available)**
```solidity
function verifyP256Signature(
    bytes32 message,
    uint256 r,
    uint256 s,
    uint256 x,
    uint256 y
) internal view returns (bool) {
    bytes memory args = abi.encodePacked(
        message, r, s, x, y
    );

    (bool success, bytes memory result) =
        address(0x100).staticcall(args);

    return success && abi.decode(result, (bool));
}
```

**Option 2: Use Library (Daimo's p256-verifier)**
```solidity
import {P256} from "p256-verifier/P256.sol";

function verifyP256Signature(...) internal view returns (bool) {
    return P256.verify(message, r, s, x, y);
}
```

## Security Considerations

### 1. Credential ID → Public Key Binding
- ✅ Immutable: Once set in constructor, cannot be changed
- ✅ On-chain: Tamper-proof, cryptographically verifiable
- ✅ No single point of failure

### 2. Signature Verification
- ✅ All verification happens on-chain
- ✅ WebAuthn authenticatorData prevents replay attacks
- ✅ Signature malleability protection (s normalization)

### 3. Recovery Scenarios

**Lost Device:**
- ✅ Passkey synced via iCloud Keychain
- ✅ Can access from any Apple device with same account
- ✅ Can add additional passkeys for redundancy

**Cleared Browser Data:**
- ✅ No problem - public key is on-chain
- ✅ Just need to remember credentialId OR use passkey picker

**Compromised Passkey:**
- Add new controller passkey via multi-sig
- Revoke old controller
- Transfer funds to new wallet if necessary

### 4. Attack Vectors & Mitigations

**Phishing:**
- ✅ WebAuthn binds to origin (rpId)
- ✅ Cannot be phished across different domains
- ✅ Secure Enclave validates origin

**Man-in-the-Middle:**
- ✅ Signature includes clientDataJSON with origin
- ✅ Authenticator validates TLS certificate

**Replay Attacks:**
- ✅ Challenge is one-time use
- ✅ authenticatorData includes signCount

## Data Storage Summary

### What's Stored Where

| Data | Secure Enclave | Blockchain | Client (Optional) |
|------|----------------|------------|-------------------|
| Private Key | ✅ (never leaves) | ❌ | ❌ |
| Public Key | ❌ | ✅ (source of truth) | ✅ (cache) |
| Credential ID | ✅ | ✅ (as mapping key) | ✅ (convenience) |
| Wallet Address | ❌ | ✅ (contract address) | ✅ (cache) |
| Signature | ✅ (generated) | ❌ | ❌ |

### Client Storage (Optional)
```typescript
// LocalStorage: Convenience only, not required
{
  "lastCredentialId": "base64url...",
  "knownWallets": [
    {
      "credentialId": "base64url...",
      "address": "0x...",
      "label": "My Main Wallet"
    }
  ]
}
```

## User Experience Improvements

### 1. Credential ID Management

**Option A: User Never Sees It**
- Use passkey picker exclusively
- Browser manages all credentials
- Most user-friendly

**Option B: Export for Cross-Platform**
- Show QR code with credentialId
- Scan on mobile device
- Sign in on new platform

**Option C: Human-Readable Identifier**
- Hash credentialId to 6-word mnemonic
- "apple-bridge-sunset-ocean-mountain-river"
- Easier to communicate between devices

### 2. Multi-Device Setup Flow

```
Device 1 (Desktop):
  "Your wallet is ready! To use on mobile:"
  [Show QR Code] → Contains credentialId

Device 2 (Mobile):
  [Scan QR Code]
  "Sign in with Face ID to access your wallet"
  → Same wallet address
  → Same balance
  → Full functionality
```

### 3. Progressive Web App (PWA)

- Install as app on mobile
- Credential ID persists across app updates
- Native-like biometric experience

## Future Enhancements

### Phase 2: Multi-Factor Recovery
- Social recovery (3-of-5 friends can recover)
- Time-locked recovery (wait 7 days to claim)
- Hardware key backup (YubiKey as 2nd factor)

### Phase 3: Account Abstraction (ERC-4337)
- Gasless transactions (paymaster)
- Batched operations
- Session keys for dApps

### Phase 4: Cross-Chain
- Deploy same wallet on multiple chains
- Bridge assets between chains
- Unified balance view

### Phase 5: Advanced Features
- Spending limits per dApp
- Automatic allowance management
- Transaction simulations before signing

## Success Metrics

### Technical
- ✅ 100% wallet recovery rate across devices
- ✅ < 2 second sign-in time
- ✅ < $0.50 wallet creation cost (L2)
- ✅ Zero private key exposure

### User Experience
- ✅ No seed phrases to manage
- ✅ Works across all user's Apple devices
- ✅ Biometric auth only (no passwords)
- ✅ Wallet never "lost" due to cleared browser data

## Comparison with Current Approach

| Aspect | IndexedDB (Current) | On-Chain (Proposed) |
|--------|---------------------|---------------------|
| **Portability** | ❌ Browser-only | ✅ Any device |
| **Data Loss Risk** | ❌ High (clear data) | ✅ None |
| **Trust Model** | ❌ Client-side | ✅ Blockchain |
| **Recovery** | ❌ Impossible | ✅ Always possible |
| **Cost** | ✅ Free | ⚠️ Gas for deploy |
| **Verification** | ❌ Client-only | ✅ On-chain |
| **Multi-device** | ❌ Requires sync | ✅ Native |

## Implementation Phases

### Phase 1: Smart Contract (Week 1-2)
- [ ] Write AccountWallet.sol
- [ ] Write WalletFactory.sol
- [ ] Add P-256 verification (library or precompile)
- [ ] Unit tests (Foundry)
- [ ] Deploy to testnet

### Phase 2: Frontend Integration (Week 2-3)
- [ ] Add wallet deployment flow
- [ ] Add blockchain query for public key
- [ ] Remove IndexedDB dependency
- [ ] Update sign-in flow
- [ ] Add transaction signing

### Phase 3: Testing & Security (Week 3-4)
- [ ] E2E tests (cross-device)
- [ ] Security audit (smart contracts)
- [ ] Gas optimization
- [ ] Edge case testing

### Phase 4: Production (Week 4+)
- [ ] Deploy to mainnet
- [ ] User documentation
- [ ] Monitor wallet creation costs
- [ ] Collect user feedback

## Open Questions

1. **Gas Costs:** What's acceptable for wallet creation?
   - Estimated: $5-20 on mainnet, $0.10-1.00 on L2

2. **Credential ID Format:** Bytes32 enough?
   - Current: base64url string
   - On-chain: keccak256(credentialId) → bytes32

3. **Multiple Passkeys:** How to handle?
   - One wallet per passkey?
   - One wallet, multiple controller passkeys?

4. **Paymaster:** Who pays for wallet creation?
   - User pays (needs ETH first)
   - Sponsored creation (free for users)
   - Refundable deposit model

## Conclusion

By storing public keys on-chain via smart contract wallets:
- ✅ Wallets become truly portable
- ✅ No dependency on browser storage
- ✅ Same wallet across all devices
- ✅ Cryptographically verifiable ownership
- ✅ Aligns with Web3 decentralization principles

The blockchain becomes the single source of truth for the credential ID → public key mapping, making the wallet as portable as the passkey itself.

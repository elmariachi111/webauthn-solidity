# P-256 WebAuthn Signature Verification

Demonstration of P-256 (secp256r1) signature verification on Ethereum using WebAuthn passkeys and RIP-7212.

## Overview

This project proves that WebAuthn signatures can be verified on-chain using Ethereum's native P-256 precompile (RIP-7212). Users sign messages with biometric authentication (Face ID, Touch ID, Windows Hello), and signatures are verified both client-side and on-chain.

**Key Innovation**: Private keys never leave secure hardware (Secure Enclave, TPM), yet signatures are verifiable on Ethereum.

## Architecture

### Client-Side
- **WebAuthn API**: P-256 key generation and signing in hardware security modules
- **Next.js**: React-based UI for wallet creation and message signing
- **viem**: Ethereum interaction and ABI encoding
- **IndexedDB**: Local credential storage

### On-Chain
- **P256Verifier.sol**: Thin wrapper around OpenZeppelin's WebAuthn library
- **OpenZeppelin WebAuthn**: Validates authenticator data, client data JSON, and P-256 signatures
- **RIP-7212 Precompile**: Native secp256r1 verification at `0x0100`

## How It Works

### 1. Wallet Creation
```
User → Biometric Prompt → Secure Enclave generates P-256 keypair
                        → Browser receives public key + credential ID
                        → Public key stored in IndexedDB
```

### 2. Message Signing
```
Message → keccak256 → WebAuthn challenge → User authenticates
                                        → Secure Enclave signs
                                        → Returns r, s, authenticatorData, clientDataJSON
```

### 3. On-Chain Verification
```
Contract receives:
  - challenge: original message bytes
  - auth: { r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON }
  - qx, qy: public key coordinates

OpenZeppelin WebAuthn.verify():
  1. Validates clientDataJSON.type === "webauthn.get"
  2. Validates challenge matches
  3. Validates authenticator flags (UP, BE, BS)
  4. Computes hash: sha256(authenticatorData || sha256(clientDataJSON))
  5. Calls RIP-7212 precompile to verify P-256 signature
```

## Smart Contracts

### P256Verifier.sol
```solidity
function verifyWebauthn(
    bytes memory challenge,
    WebAuthn.WebAuthnAuth memory auth,
    bytes32 qx,
    bytes32 qy
) public view returns (bool)
```

Uses OpenZeppelin's battle-tested WebAuthn library for proper validation of:
- Type field verification
- Challenge matching
- User Present/Verified flags
- Backup Eligibility/State consistency
- P-256 signature via RIP-7212

## Features

- ✅ **Biometric Authentication**: Sign with Face ID/Touch ID
- ✅ **Hardware Security**: Keys never leave Secure Enclave/TPM
- ✅ **On-Chain Verification**: Verify signatures on Sepolia/mainnet
- ✅ **Client-Side Verification**: Browser validates signatures locally
- ✅ **Multi-Passkey Support**: Manage multiple hardware authenticators
- ✅ **Cross-Device Sync**: Passkeys sync via iCloud Keychain/platform providers
- ✅ **Etherscan Integration**: Copy parameters for manual verification

## Quick Start

```bash
# Install dependencies
npm install

# Set environment variables
cp .env.example .env

# Run development server
npm run dev

# Open browser
open http://localhost:3000
```

## Environment Variables

```env
NEXT_PUBLIC_RPC_URL=https://sepolia.drpc.org
NEXT_PUBLIC_WEBAUTHN_VERIFIER_ADDRESS=0x34db200e2f1349aceab09e363d4e4631a68657f1
NEXT_PUBLIC_BLOCK_EXPLORER_URL=https://sepolia.etherscan.io
```

## Deployment

The P256Verifier contract requires:
1. OpenZeppelin Contracts with WebAuthn library
2. RIP-7212 support (Ethereum mainnet, Sepolia, or compatible L2)

```bash
# Deploy with Foundry
forge create P256Verifier --via-ir --rpc-url $RPC_URL --private-key $PRIVATE_KEY --etherscan-api-key $ETHERSCAN_API_KEY --verify --broadcast
```

## Technical Deep Dive

### WebAuthn Signature Flow
1. Message encoded as UTF-8 bytes
2. Message bytes used as WebAuthn challenge
3. Challenge base64url-encoded and embedded in `clientDataJSON`
4. Authenticator signs: `sha256(authenticatorData || sha256(clientDataJSON))`
5. Browser receives DER-encoded signature, parsed to extract r, s

### On-Chain Verification
Contract reconstructs the same signed data:
```solidity
bytes32 messageHash = sha256(
    abi.encodePacked(
        authenticatorData,
        sha256(bytes(clientDataJSON))
    )
);
```

Then calls RIP-7212 precompile:
```solidity
abi.encodePacked(messageHash, r, s, qx, qy) → 0x0100
```

### Security Considerations
- ✅ Signature malleability protection (s-value normalization)
- ✅ Origin validation enforced by authenticators
- ✅ User Present flag required
- ✅ Backup state consistency checks
- ⚠️ IndexedDB storage (not production-ready for real wallets)
- ⚠️ No nonce/replay protection (demo only)

## Limitations

**Current Implementation:**
- Public keys stored in browser IndexedDB (not portable)
- Clearing browser data loses wallet access
- No on-chain public key registry
- No smart contract wallet integration

**For Production:**
- Implement ERC-4337 account abstraction
- Store public keys on-chain
- Add nonce/replay protection
- Implement session keys for UX
- Add key rotation mechanisms

## Browser Support

- ✅ Chrome 67+
- ✅ Safari 14+
- ✅ Firefox 60+
- ✅ Edge 18+

Requires platform authenticator (Secure Enclave, Windows Hello, etc.)

## Resources

- [RIP-7212 Specification](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md)
- [OpenZeppelin WebAuthn Library](https://docs.openzeppelin.com/contracts/5.x/api/utils#WebAuthn)
- [WebAuthn Standard](https://www.w3.org/TR/webauthn-2/)
- [Implementation Plan](./IMPLEMENTATION_PLAN.md)
- [Product Requirements](./PASSKEY_WALLET_PRD.md)

## License

MIT

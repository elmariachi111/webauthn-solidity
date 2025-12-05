// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/**
 * @title P256Verifier
 * @notice Simple contract to verify P-256 (secp256r1) signatures using RIP-7212 precompile
 * @dev Uses the P256VERIFY precompile at address 0x0100
 */
contract P256Verifier {

    /**
     * @notice Verifies a P-256 signature against a message hash and public key
     * @param messageHash The keccak256 hash of the message that was signed
     * @param r The r component of the signature (32 bytes)
     * @param s The s component of the signature (32 bytes)
     * @param px The x-coordinate of the public key (32 bytes)
     * @param py The y-coordinate of the public key (32 bytes)
     * @return True if the signature is valid, false otherwise
     */
    function verifySignature(bytes32 messageHash,bytes32 r,bytes32 s,bytes32 px,bytes32 py) public view returns (bool) {
      return P256.verify(messageHash, r, s, px, py);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title P256Verifier
 * @notice Simple contract to verify P-256 (secp256r1) signatures using RIP-7212 precompile
 * @dev Uses the P256VERIFY precompile at address 0x0100
 */
contract P256Verifier {
    /// @notice Address of the RIP-7212 P256VERIFY precompile
    address private constant P256_VERIFIER = address(0x0100);

    /**
     * @notice Verifies a P-256 signature against a message hash and public key
     * @param messageHash The keccak256 hash of the message that was signed
     * @param r The r component of the signature (32 bytes)
     * @param s The s component of the signature (32 bytes)
     * @param px The x-coordinate of the public key (32 bytes)
     * @param py The y-coordinate of the public key (32 bytes)
     * @return True if the signature is valid, false otherwise
     */
    function verifySignature(
        bytes32 messageHash,
        uint256 r,
        uint256 s,
        uint256 px,
        uint256 py
    ) public view returns (bool) {
        // Prepare input data for the precompile (160 bytes total)
        // Format: messageHash (32) || r (32) || s (32) || x (32) || y (32)
        bytes memory input = abi.encodePacked(
            messageHash,
            r,
            s,
            px,
            py
        );

        // Call the P256VERIFY precompile
        (bool success, bytes memory result) = P256_VERIFIER.staticcall(input);

        // Precompile returns success=true with result=0x01 (32 bytes) if signature is valid
        // Returns success=true with empty result if signature is invalid
        // Returns success=false if there's an error (shouldn't happen with correct input)
        if (!success) {
            return false;
        }

        // Check if result is non-empty and equals 1
        if (result.length == 0) {
            return false;
        }

        // Decode the result as uint256 and check if it equals 1
        return abi.decode(result, (uint256)) == 1;
    }
}

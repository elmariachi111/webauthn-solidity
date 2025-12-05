// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

/**
 * @title P256Verifier
 */
contract P256Verifier {
    /**
     * @dev Performs standard verification of a WebAuthn Authentication Assertion.
     */
    function verifyWebauthn(bytes memory challenge, WebAuthn.WebAuthnAuth memory auth, bytes32 qx, bytes32 qy)
        public
        view
        returns (bool)
    {
        return WebAuthn.verify(challenge, auth, qx, qy);
    }
}

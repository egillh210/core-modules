// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { ContangoWebAuthnValidator } from
    "src/ContangoWebAuthnValidator/ContangoWebAuthnValidator.sol";

// utility contract to test the ContangoOwnableValidator
// exposes helper methods to do one operation at a time, yet always going through
// the updateConfig function to mimic how it would be used in a real life scenario
contract ContangoWebAuthnTestValidator is ContangoWebAuthnValidator {
    function addCredential(WebAuthnCredential memory newCredential) external {
        WebAuthnCredential[] memory ownersToAdd = new WebAuthnCredential[](1);
        ownersToAdd[0] = newCredential;
        super._updateConfig(this.thresholds(msg.sender), ownersToAdd, new bytes32[](0));
    }

    function setThreshold(uint256 newThreshold) external {
        super._updateConfig(newThreshold, new WebAuthnCredential[](0), new bytes32[](0));
    }

    function removeCredential(WebAuthnCredential memory credential) external {
        bytes32[] memory credentialsToRemove = new bytes32[](1);
        credentialsToRemove[0] = this.generateCredentialId(msg.sender, credential);
        super._updateConfig(
            this.thresholds(msg.sender), new WebAuthnCredential[](0), credentialsToRemove
        );
    }

    function updateConfig(
        uint256 newThreshold,
        WebAuthnCredential[] memory credentialsToAdd,
        bytes32[] memory credentialsToRemove
    )
        external
        override
    {
        super._updateConfig(newThreshold, credentialsToAdd, credentialsToRemove);
    }
}

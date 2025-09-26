// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { ContangoValidator } from "src/ContangoValidator/ContangoValidator.sol";

// utility contract to test the ContangoValidator
// exposes helper methods to do one operation at a time, yet always going through
// the updateConfig function to mimic how it would be used in a real life scenario
contract ContangoTestValidator is ContangoValidator {
    function addECDSAOwner(address newOwner) external {
        address[] memory ownersToAdd = new address[](1);
        ownersToAdd[0] = newOwner;
        CredentialUpdateConfig memory config = CredentialUpdateConfig({
            ecdsaOwnersToAdd: ownersToAdd,
            ecdsaOwnersToRemove: new address[](0),
            webAuthnCredentialsToAdd: new WebAuthnCredential[](0),
            webAuthnCredentialsToRemove: new bytes32[](0)
        });
        super._updateConfig(this.thresholds(msg.sender), config);
    }

    function addWebAuthnCredential(WebAuthnCredential memory newCredential) external {
        WebAuthnCredential[] memory credentialsToAdd = new WebAuthnCredential[](1);
        credentialsToAdd[0] = newCredential;
        CredentialUpdateConfig memory config = CredentialUpdateConfig({
            ecdsaOwnersToAdd: new address[](0),
            ecdsaOwnersToRemove: new address[](0),
            webAuthnCredentialsToAdd: credentialsToAdd,
            webAuthnCredentialsToRemove: new bytes32[](0)
        });
        super._updateConfig(this.thresholds(msg.sender), config);
    }

    function setThreshold(uint256 newThreshold) external {
        CredentialUpdateConfig memory config = CredentialUpdateConfig({
            ecdsaOwnersToAdd: new address[](0),
            ecdsaOwnersToRemove: new address[](0),
            webAuthnCredentialsToAdd: new WebAuthnCredential[](0),
            webAuthnCredentialsToRemove: new bytes32[](0)
        });
        super._updateConfig(newThreshold, config);
    }

    function removeECDSAOwner(address owner) external {
        address[] memory ownersToRemove = new address[](1);
        ownersToRemove[0] = owner;
        CredentialUpdateConfig memory config = CredentialUpdateConfig({
            ecdsaOwnersToAdd: new address[](0),
            ecdsaOwnersToRemove: ownersToRemove,
            webAuthnCredentialsToAdd: new WebAuthnCredential[](0),
            webAuthnCredentialsToRemove: new bytes32[](0)
        });
        super._updateConfig(this.thresholds(msg.sender), config);
    }

    function removeWebAuthnCredential(WebAuthnCredential memory credential) external {
        bytes32[] memory credentialsToRemove = new bytes32[](1);
        credentialsToRemove[0] = this.generateCredentialId(msg.sender, credential);
        CredentialUpdateConfig memory config = CredentialUpdateConfig({
            ecdsaOwnersToAdd: new address[](0),
            ecdsaOwnersToRemove: new address[](0),
            webAuthnCredentialsToAdd: new WebAuthnCredential[](0),
            webAuthnCredentialsToRemove: credentialsToRemove
        });
        super._updateConfig(this.thresholds(msg.sender), config);
    }

    function updateConfig(
        uint256 newThreshold,
        CredentialUpdateConfig calldata config
    )
        external
        override
    {
        super._updateConfig(newThreshold, config);
    }

    function isECDSAOwner(address account, address owner) external view returns (bool) {
        address[] memory owners = super.getECDSAOwners(account);
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == owner) return true;
        }
        return false;
    }

    function hasWebAuthnCredential(address account, WebAuthnCredential memory credential) external view returns (bool) {
        bytes32 credentialId = generateCredentialId(account, credential);
        ContangoValidator.WebAuthnCredential[] memory credentials = super.getWebAuthnCredentials(account);
        for (uint256 i = 0; i < credentials.length; i++) {
            bytes32 credId = generateCredentialId(account, credentials[i]);
            if (credId == credentialId) return true;
        }
        return false;
    }

    function hasWebAuthnCredentialById(address account, bytes32 credentialId) external view returns (bool) {
        ContangoValidator.WebAuthnCredential[] memory credentials = super.getWebAuthnCredentials(account);
        for (uint256 i = 0; i < credentials.length; i++) {
            bytes32 credId = generateCredentialId(account, credentials[i]);
            if (credId == credentialId) return true;
        }
        return false;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { ContangoOwnableValidator } from "src/ContangoOwnableValidator/ContangoOwnableValidator.sol";

// utility contract to test the ContangoOwnableValidator
// exposes helper methods to do one operation at a time, yet always going through
// the updateConfig function to mimic how it would be used in a real life scenario
contract ContangoOwnableTestValidator is ContangoOwnableValidator {
    function addOwner(address newOwner) external {
        address[] memory ownersToAdd = new address[](1);
        ownersToAdd[0] = newOwner;
        super._updateConfig(this.thresholds(msg.sender), ownersToAdd, new address[](0));
    }

    function setThreshold(uint256 newThreshold) external {
        super._updateConfig(newThreshold, new address[](0), new address[](0));
    }

    function removeOwner(address owner) external {
        address[] memory ownersToRemove = new address[](1);
        address[] memory ownersToAdd = new address[](0);
        ownersToRemove[0] = owner;
        super._updateConfig(this.thresholds(msg.sender), ownersToAdd, ownersToRemove);
    }

    function updateConfig(
        uint256 newThreshold,
        address[] memory ownersToAdd,
        address[] memory ownersToRemove
    )
        external
        override
    {
        super._updateConfig(newThreshold, ownersToAdd, ownersToRemove);
    }
}

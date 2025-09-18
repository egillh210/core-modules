// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { LibSort } from "solady/utils/LibSort.sol";
import { CheckSignatures } from "checknsignatures/CheckNSignatures.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { EnumerableSet } from "@erc7579/enumerablemap4337/EnumerableSet4337.sol";
import { MODULE_TYPE_STATELESS_VALIDATOR as TYPE_STATELESS_VALIDATOR } from
    "modulekit/module-bases/utils/ERC7579Constants.sol";

contract ContangoOwnableValidator is ERC7579ValidatorBase {

    using LibSort for *;
    using EnumerableSet for EnumerableSet.AddressSet;

    // maximum number of owners per account
    uint256 constant MAX_OWNERS = 32;
    uint256 constant MIN_OWNERS = 1;

    event ModuleInitialized(address indexed account);
    event ModuleUninitialized(address indexed account);
    event ThresholdSet(address indexed account, uint256 threshold);
    event OwnerAdded(address indexed account, address indexed owner);
    event OwnerRemoved(address indexed account, address indexed owner);

    error InvalidThreshold(uint256 threshold, uint256 minThreshold, uint256 maxThreshold);
    error InvalidOwnersCount(uint256 ownersCount, uint256 minOwnersCount, uint256 maxOwnersCount);
    error OwnerAlreadyExists(address owner);
    error OwnerDoesNotExist(address owner);

    EnumerableSet.AddressSet owners;
    mapping(address account => uint256) public thresholds;

    modifier moduleIsInitialized() {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        _;
    }

    modifier moduleIsNotInitialized() {
        require(!isInitialized(msg.sender), ModuleAlreadyInitialized(msg.sender));
        _;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    function _setThreshold(address account, uint256 _threshold) internal {
        thresholds[account] = _threshold;
        emit ThresholdSet(account, _threshold);
    }

    /**
     * @dev EnumerableSet.add returns false if the item already exists
     */
    function _addOwner(address account, address owner) internal {
        if (!owners.add(account, owner)) revert OwnerAlreadyExists(owner);
        emit OwnerAdded(account, owner);
    }

    /**
     * @dev EnumerableSet.remove returns false if the item does not exist
     */
    function _removeOwner(address account, address owner) internal {
        if (!owners.remove(account, owner)) revert OwnerDoesNotExist(owner);
        emit OwnerRemoved(account, owner);
    }

    function _addOwners(address account, address[] memory newOwners) internal {
        for (uint256 i = 0; i < newOwners.length; i++) _addOwner(account, newOwners[i]);
    }

    function _removeOwners(address account, address[] memory ownersToRemove) internal {
        for (uint256 i = 0; i < ownersToRemove.length; i++) _removeOwner(account, ownersToRemove[i]);
    }

    function _checkInvariants(address account, uint256 minOwnersCount, uint256 maxOwnersCount) internal view {
        uint256 ownersCount = owners.length(account);
        uint256 threshold = thresholds[account];
        require(
            minOwnersCount <= ownersCount && ownersCount <= maxOwnersCount,
            InvalidOwnersCount(ownersCount, minOwnersCount, maxOwnersCount)
        );
        require(
            minOwnersCount <= threshold && threshold <= ownersCount,
            InvalidThreshold(threshold, minOwnersCount, ownersCount)
        );
    }

    // Default to the min and max value constants for the invariants
    function _checkInvariants(address account) internal view {
        _checkInvariants(account, MIN_OWNERS, MAX_OWNERS);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                PUBLIC
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Updates the config for the account.
     * This function is not idempotent.
     * @param newThreshold uint256 threshold to set
     * @param ownersToAdd address[] array of owners to add.
     * @param ownersToRemove address[] array of owners to remove.
     */
    function updateConfig(uint256 newThreshold, address[] calldata ownersToAdd, address[] calldata ownersToRemove) public moduleIsInitialized {
        address account = msg.sender;
        _removeOwners(account, ownersToRemove);
        _addOwners(account, ownersToAdd);
        _setThreshold(account, newThreshold);
        _checkInvariants(account);
    }

    function addOwner(address owner) external moduleIsInitialized {
        address account = msg.sender;
        _addOwner(account, owner);
        _checkInvariants(account);
    }
    
    function removeOwner(address owner) external moduleIsInitialized {
        address account = msg.sender;
        _removeOwner(account, owner);
        _checkInvariants(account);
    }

    function setThreshold(uint256 threshold) external moduleIsInitialized {
        address account = msg.sender;
        _setThreshold(account, threshold);
        _checkInvariants(account);
    }

    function replaceOwner(address prevOwner, address newOwner) external moduleIsInitialized {
        address account = msg.sender;
        _removeOwner(account, prevOwner);
        _addOwner(account, newOwner);
        _checkInvariants(account);
    }

    // ** CONFIG ** //

    function onInstall(bytes calldata data)
        external
        override
        moduleIsNotInitialized
    {
        address account = msg.sender;
        (uint256 threshold, address[] memory newOwners) = abi.decode(data, (uint256, address[]));

        _addOwners(account, newOwners);
        _setThreshold(account, threshold);
        _checkInvariants(account);

        emit ModuleInitialized(account);
    }

    function onUninstall(bytes calldata) external override {
        address account = msg.sender;
        _removeOwners(account, getOwners(account));
        _setThreshold(account, 0);
        _checkInvariants(account, 0, 0);

        emit ModuleUninitialized(msg.sender);
    }

    // ** VIEW FUNCTIONS ** //

    function isInitialized(address smartAccount) public view returns (bool) {
        return thresholds[smartAccount] != 0;
    }

    function getOwners(address account) public view returns (address[] memory ownersArray) {
        ownersArray = owners.values(account);
    }

    function isOwner(address account, address owner) public view returns (bool) {
        return owners.contains(account, owner);
    }

    function getOwnersCount(address account) public view returns (uint256) {
        return owners.length(account);
    }

    /*//////////////////////////////////////////////////////////////////////////////////////
            EVERYTHING BEYOND THIS POINT IS EXACTLY THE SAME AS THE OWNABLE VALIDATOR
    //////////////////////////////////////////////////////////////////////////////////////*/

    /**
     * Validates a user operation
     *
     * @param userOp PackedUserOperation struct containing the UserOperation
     * @param userOpHash bytes32 hash of the UserOperation
     *
     * @return ValidationData the UserOperation validation result
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        view
        override
        returns (ValidationData)
    {
        // validate the signature with the config
        bool isValid = _validateSignatureWithConfig(
            userOp.sender, ECDSA.toEthSignedMessageHash(userOpHash), userOp.signature
        );

        // return the result
        if (isValid) {
            return VALIDATION_SUCCESS;
        }
        return VALIDATION_FAILED;
    }

    /**
     * Validates an ERC-1271 signature with the sender
     *
     * @param hash bytes32 hash of the data
     * @param data bytes data containing the signatures
     *
     * @return bytes4 EIP1271_SUCCESS if the signature is valid, EIP1271_FAILED otherwise
     */
    function isValidSignatureWithSender(
        address,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        override
        returns (bytes4)
    {
        // validate the signature with the config
        bool isValid = _validateSignatureWithConfig(msg.sender, hash, data);

        // return the result
        if (isValid) {
            return EIP1271_SUCCESS;
        }
        return EIP1271_FAILED;
    }

    /**
     * Validates a signature with the data (stateless validation)
     *
     * @param hash bytes32 hash of the data
     * @param signature bytes data containing the signatures
     * @param data bytes data containing the data
     *
     * @return bool true if the signature is valid, false otherwise
     */
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata signature,
        bytes calldata data
    )
        external
        view
        returns (bool)
    {
        // decode the threshold and owners
        (uint256 _threshold, address[] memory _owners) = abi.decode(data, (uint256, address[]));

        // check that owners are sorted and uniquified
        if (!_owners.isSortedAndUniquified()) {
            return false;
        }

        // check that threshold is set
        if (_threshold == 0) {
            return false;
        }

        // recover the signers from the signatures
        address[] memory signers = CheckSignatures.recoverNSignatures(hash, signature, _threshold);

        // sort and uniquify the signers to make sure a signer is not reused
        signers.sort();
        signers.uniquifySorted();

        // check if the signers are owners
        uint256 validSigners;
        uint256 signersLength = signers.length;
        for (uint256 i = 0; i < signersLength; i++) {
            (bool found,) = _owners.searchSorted(signers[i]);
            if (found) {
                validSigners++;
            }
        }

        // check if the threshold is met and return the result
        if (validSigners >= _threshold) {
            // if the threshold is met, return true
            return true;
        }
        // if the threshold is not met, false
        return false;
    }

    function _validateSignatureWithConfig(
        address account,
        bytes32 hash,
        bytes calldata data
    )
        internal
        view
        returns (bool)
    {
        // get the threshold and check that its set
        uint256 _threshold = thresholds[account];
        if (_threshold == 0) {
            return false;
        }

        // recover the signers from the signatures
        address[] memory signers = CheckSignatures.recoverNSignatures(hash, data, _threshold);

        // sort and uniquify the signers to make sure a signer is not reused
        signers.sort();
        signers.uniquifySorted();

        // check if the signers are owners
        uint256 validSigners;
        uint256 signersLength = signers.length;
        for (uint256 i = 0; i < signersLength; i++) {
            if (owners.contains(account, signers[i])) {
                validSigners++;
            }
        }

        // check if the threshold is met and return the result
        if (validSigners >= _threshold) {
            // if the threshold is met, return true
            return true;
        }
        // if the threshold is not met, return false
        return false;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_STATELESS_VALIDATOR;
    }

    function name() external pure virtual returns (string memory) {
        return "ContangoOwnableValidator";
    }

    function version() external pure virtual returns (string memory) {
        return "1.0.0";
    }
}


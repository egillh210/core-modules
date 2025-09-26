// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Contracts
import { ERC7579HybridValidatorBase } from "modulekit/Modules.sol";

// Types
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";

// Libraries
import { EnumerableSet } from "@erc7579/enumerablemap4337/EnumerableSet4337.sol";
import { LibSort } from "solady/utils/LibSort.sol";
import { CheckSignatures } from "checknsignatures/CheckNSignatures.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { WebAuthn } from "@webauthn-sol/WebAuthn.sol";
import { MODULE_TYPE_STATELESS_VALIDATOR as TYPE_STATELESS_VALIDATOR } from
    "modulekit/module-bases/utils/ERC7579Constants.sol";

/// @title ContangoValidator
/// @notice A unified validator that combines ECDSA (Ownable) and WebAuthn credential support
/// @dev Allows smart accounts to authenticate using both ECDSA signatures and WebAuthn credentials
///     with a single threshold for all credential types
contract ContangoValidator is ERC7579HybridValidatorBase {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using LibSort for address[];
    using WebAuthn for bytes;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Structure holding WebAuthn credential information
    /// @param pubKeyX The X coordinate of the credential's public key on the P-256 curve
    /// @param pubKeyY The Y coordinate of the credential's public key on the P-256 curve
    /// @param requireUV Whether user verification (biometrics/PIN) is required for this credential
    struct WebAuthnCredential {
        uint256 pubKeyX;
        uint256 pubKeyY;
        bool requireUV;
    }

    /// @notice Configuration for updating credentials
    /// @param ecdsaOwnersToAdd Array of ECDSA owner addresses to add
    /// @param ecdsaOwnersToRemove Array of ECDSA owner addresses to remove
    /// @param webAuthnCredentialsToAdd Array of WebAuthn credentials to add
    /// @param webAuthnCredentialsToRemove Array of WebAuthn credential IDs to remove
    struct CredentialUpdateConfig {
        address[] ecdsaOwnersToAdd;
        address[] ecdsaOwnersToRemove;
        WebAuthnCredential[] webAuthnCredentialsToAdd;
        bytes32[] webAuthnCredentialsToRemove;
    }

    /// @notice WebAuthVerificationContext for stateless validation
    /// @dev Context for WebAuthn verification, including credential details and threshold
    /// @param threshold The number of signatures required for validation
    /// @param credentialData WebAuthn credential data
    struct WebAuthVerificationContext {
        uint256 threshold;
        WebAuthnCredential[] credentialData;
    }

    /// @notice Unified signature data structure
    /// @dev Contains both ECDSA and WebAuthn signature data
    /// @param ecdsaSignatureData Raw ECDSA signature data
    /// @param webAuthnCredentialIds Array of WebAuthn credential IDs used for signing
    /// @param webAuthnSignatureData WebAuthn signature data
    struct UnifiedSignatureData {
        bytes ecdsaSignatureData;
        bytes32[] webAuthnCredentialIds;
        WebAuthn.WebAuthnAuth[] webAuthnSignatureData;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the module is installed for an account
    event ModuleInitialized(address indexed account);

    /// @notice Emitted when the module is uninstalled for an account
    event ModuleUninitialized(address indexed account);

    /// @notice Emitted when a threshold is set for an account
    event ThresholdSet(address indexed account, uint256 threshold);

    /// @notice Emitted when an ECDSA owner is added to an account
    event ECDSAOwnerAdded(address indexed account, address indexed owner);

    /// @notice Emitted when an ECDSA owner is removed from an account
    event ECDSAOwnerRemoved(address indexed account, address indexed owner);

    /// @notice Emitted when a WebAuthn credential is added to an account
    event WebAuthnCredentialAdded(
        address indexed account, bytes32 indexed credentialId, WebAuthnCredential credential
    );

    /// @notice Emitted when a WebAuthn credential is removed from an account
    event WebAuthnCredentialRemoved(address indexed account, bytes32 indexed credentialId);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidThreshold(uint256 threshold, uint256 minThreshold, uint256 maxThreshold);
    error InvalidCredentialsCount(
        uint256 credentialsCount, uint256 minCredentialsCount, uint256 maxCredentialsCount
    );
    error AddECDSAOwnerError_OwnerAlreadyExists(address account, address owner);
    error RemoveECDSAOwnerError_OwnerDoesNotExist(address account, address owner);
    error AddWebAuthnCredentialError_CredentialAlreadyExists(
        address account, WebAuthnCredential credential
    );
    error RemoveWebAuthnCredentialError_CredentialDoesNotExist(
        address account, bytes32 credentialId
    );
    error InvalidPublicKey();

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum number of total credentials (ECDSA + WebAuthn) allowed per account
    uint256 constant MAX_TOTAL_CREDENTIALS = 32;
    uint256 constant MIN_TOTAL_CREDENTIALS = 1;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Enumerable set of ECDSA owners per account
    EnumerableSet.AddressSet ecdsaOwners;

    /// @notice Enumerable set of WebAuthn credential IDs per account
    EnumerableSet.Bytes32Set webAuthnCredentialIds;

    /// @notice Mapping of WebAuthn credential IDs to their respective credentials
    mapping(bytes32 credentialId => mapping(address account => WebAuthnCredential credential))
        public webAuthnCredentialDetails;

    /// @notice Threshold for each account (applies to both ECDSA and WebAuthn credentials)
    mapping(address account => uint256 threshold) public thresholds;

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    modifier moduleIsInitialized() {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        _;
    }

    modifier moduleIsNotInitialized() {
        require(!isInitialized(msg.sender), ModuleAlreadyInitialized(msg.sender));
        _;
    }

    modifier checkInvariants() {
        _;
        _checkInvariants(msg.sender, MIN_TOTAL_CREDENTIALS, MAX_TOTAL_CREDENTIALS);
    }

    function _checkInvariants(
        address account,
        uint256 minCredentialsCount,
        uint256 maxCredentialsCount
    )
        internal
        view
    {
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = getCredentialsCount(account);
        uint256 totalCredentialsCount = ecdsaOwnersCount + webAuthnCredentialsCount;
        uint256 threshold = thresholds[account];
        require(
            minCredentialsCount <= totalCredentialsCount
                && totalCredentialsCount <= maxCredentialsCount,
            InvalidCredentialsCount(totalCredentialsCount, minCredentialsCount, maxCredentialsCount)
        );
        require(
            minCredentialsCount <= threshold && threshold <= totalCredentialsCount,
            InvalidThreshold(threshold, minCredentialsCount, totalCredentialsCount)
        );
    }

    function _setThreshold(address account, uint256 _threshold) internal {
        thresholds[account] = _threshold;
        emit ThresholdSet(account, _threshold);
    }

    function _addECDSAOwners(address account, address[] memory newOwners) internal {
        for (uint256 i = 0; i < newOwners.length; i++) {
            if (ecdsaOwners.add(account, newOwners[i])) {
                emit ECDSAOwnerAdded(account, newOwners[i]);
            } else {
                revert AddECDSAOwnerError_OwnerAlreadyExists(account, newOwners[i]);
            }
        }
    }

    function _removeECDSAOwners(address account, address[] memory ownersToRemove) internal {
        for (uint256 i = 0; i < ownersToRemove.length; i++) {
            if (ecdsaOwners.remove(account, ownersToRemove[i])) {
                emit ECDSAOwnerRemoved(account, ownersToRemove[i]);
            } else {
                revert RemoveECDSAOwnerError_OwnerDoesNotExist(account, ownersToRemove[i]);
            }
        }
    }

    function _addWebAuthnCredentials(
        address account,
        WebAuthnCredential[] memory _credentials
    )
        internal
    {
        for (uint256 i = 0; i < _credentials.length; i++) {
            WebAuthnCredential memory credential = _credentials[i];
            bytes32 credentialId = generateCredentialId(account, credential);

            if (webAuthnCredentialIds.add(account, credentialId)) {
                webAuthnCredentialDetails[credentialId][account] = credential;
                emit WebAuthnCredentialAdded(account, credentialId, credential);
            } else {
                revert AddWebAuthnCredentialError_CredentialAlreadyExists(account, credential);
            }
        }
    }

    function _removeWebAuthnCredentials(
        address account,
        bytes32[] memory _credentialIds
    )
        internal
    {
        for (uint256 i = 0; i < _credentialIds.length; i++) {
            bytes32 credentialId = _credentialIds[i];

            if (webAuthnCredentialIds.remove(account, credentialId)) {
                delete webAuthnCredentialDetails[credentialId][account];
                emit WebAuthnCredentialRemoved(account, credentialId);
            } else {
                revert RemoveWebAuthnCredentialError_CredentialDoesNotExist(account, credentialId);
            }
        }
    }

    function _updateConfig(
        uint256 newThreshold,
        CredentialUpdateConfig memory config
    )
        internal
        moduleIsInitialized
        checkInvariants
    {
        address account = msg.sender;
        _setThreshold(account, newThreshold);
        _removeECDSAOwners(account, config.ecdsaOwnersToRemove);
        _addECDSAOwners(account, config.ecdsaOwnersToAdd);
        _removeWebAuthnCredentials(account, config.webAuthnCredentialsToRemove);
        _addWebAuthnCredentials(account, config.webAuthnCredentialsToAdd);
    }

    /*//////////////////////////////////////////////////////////////
                                PUBLIC
    //////////////////////////////////////////////////////////////*/

    /// @notice Updates the config for the account
    /// @dev Updates the threshold and credentials for the account
    /// @param newThreshold uint256 new threshold to set
    /// @param config CredentialUpdateConfig containing all credential updates
    function updateConfig(
        uint256 newThreshold,
        CredentialUpdateConfig calldata config
    )
        external
    {
        _updateConfig(newThreshold, config);
    }

    /// @notice Initializes the module with both ECDSA owners and WebAuthn credentials
    /// @dev Installs the validator with threshold and initial set of credentials
    /// @param data Encoded as: abi.encode(threshold, ecdsaOwners, webAuthnCredentials)
    function onInstall(bytes calldata data)
        external
        override
        moduleIsNotInitialized
        checkInvariants
    {
        address account = msg.sender;
        (
            uint256 _threshold,
            address[] memory _ecdsaOwners,
            WebAuthnCredential[] memory _webAuthnCredentials
        ) = abi.decode(data, (uint256, address[], WebAuthnCredential[]));

        _setThreshold(account, _threshold);
        _addECDSAOwners(account, _ecdsaOwners);
        _addWebAuthnCredentials(account, _webAuthnCredentials);

        emit ModuleInitialized(account);
    }

    /// @notice Handles the uninstallation of the module and clears all credentials
    /// @dev Removes all credentials and settings for the account
    function onUninstall(bytes calldata) external override moduleIsInitialized {
        address account = msg.sender;
        _removeECDSAOwners(account, ecdsaOwners.values(account));
        _removeWebAuthnCredentials(account, webAuthnCredentialIds.values(account));
        _setThreshold(account, 0);
        _checkInvariants(account, 0, 0);

        emit ModuleUninitialized(msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                                VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function isInitialized(address smartAccount) public view returns (bool) {
        return thresholds[smartAccount] != 0;
    }

    /// @notice Gets all ECDSA owners for an account
    function getECDSAOwners(address account) public view returns (address[] memory ownersArray) {
        return ecdsaOwners.values(account);
    }

    /// @notice Gets all WebAuthn credentials for an account
    function getWebAuthnCredentials(address account)
        public
        view
        returns (WebAuthnCredential[] memory)
    {
        bytes32[] memory credentialIds = webAuthnCredentialIds.values(account);
        WebAuthnCredential[] memory _credentials = new WebAuthnCredential[](credentialIds.length);
        for (uint256 i = 0; i < credentialIds.length; i++) {
            _credentials[i] = webAuthnCredentialDetails[credentialIds[i]][account];
        }
        return _credentials;
    }

    /// @notice Gets the total count of all credentials (ECDSA + WebAuthn) for an account
    function getCredentialsCount(address account) public view returns (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) {
        return (ecdsaOwners.length(account), webAuthnCredentialIds.length(account));
    }

    /// @notice Generates a credential ID for a WebAuthn credential
    function generateCredentialId(
        address account,
        WebAuthnCredential memory credential
    )
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(credential.pubKeyX, credential.pubKeyY, account));
    }

    /*//////////////////////////////////////////////////////////////
                                VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a user operation
    /// @dev Validates signatures from both ECDSA owners and WebAuthn credentials
    /// @param userOp PackedUserOperation struct containing the UserOperation
    /// @param userOpHash bytes32 hash of the UserOperation
    /// @return ValidationData the UserOperation validation result
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
        bool isValid = _validateSignatureWithConfig(userOp.sender, userOpHash, userOp.signature);

        if (isValid) return VALIDATION_SUCCESS;
        return VALIDATION_FAILED;
    }

    /// @notice Validates an ERC-1271 signature with the sender
    /// @dev Implements EIP-1271 isValidSignature for smart contract signatures
    /// @param hash Hash of the data to validate
    /// @param data Signature data containing both ECDSA and WebAuthn signatures
    /// @return bytes4 EIP1271_SUCCESS if valid, EIP1271_FAILED otherwise
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
        if (_validateSignatureWithConfig(msg.sender, hash, data)) return EIP1271_SUCCESS;
        return EIP1271_FAILED;
    }

    /// @notice Validates a signature with external credential data
    /// @dev Used for stateless validation without pre-registered credentials
    /// @dev IMPORTANT: The order of the ecdsaOwners and webAuthnSignatureData matters. The ecdsaOwners must be sorted and uniquified. The webAuthnSignatureData must be sorted and uniquified.
    /// @param hash Hash of the data to validate
    /// @param signature Signature data containing both ECDSA and WebAuthn signatures
    /// @param data Encoded credential details and threshold
    /// @return bool True if the signature is valid, false otherwise
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata signature,
        bytes calldata data
    )
        external
        view
        override
        returns (bool)
    {
        // Decode the unified signature data
        // Format: abi.encode(UnifiedSignatureData memory signatureData)
        UnifiedSignatureData memory signatureData = abi.decode(signature, (UnifiedSignatureData));

        // Decode the verification context
        // Format: abi.encode(uint256 threshold, address[] ecdsaOwners, WebAuthVerificationContext
        // memory webAuthnContext)
        (
            uint256 requiredThreshold,
            address[] memory ecdsaOwnerList,
            WebAuthVerificationContext memory webAuthnContext
        ) = abi.decode(data, (uint256, address[], WebAuthVerificationContext));

        // Verify ECDSA signatures if present
        uint256 validSignatures = 0;

        if (signatureData.ecdsaSignatureData.length > 0) {
            address[] memory ecdsaSigners = CheckSignatures.recoverNSignatures(
                hash, signatureData.ecdsaSignatureData, requiredThreshold
            );

            // ensure the same signature cannot be used multiple times
            ecdsaSigners.sort();
            ecdsaSigners.uniquifySorted();

            // Count valid ECDSA signers
            for (uint256 i = 0; i < ecdsaSigners.length; i++) {
                (bool found,) = ecdsaOwnerList.searchSorted(ecdsaSigners[i]);
                if (found) validSignatures++;
            }
        }

        // Verify WebAuthn signatures if present
        if (signatureData.webAuthnSignatureData.length > 0) {
            validSignatures += _verifyWebAuthnSignatures(
                hash, signatureData.webAuthnSignatureData, webAuthnContext
            );
        }

        return validSignatures >= requiredThreshold;
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a signature against the account's credentials
    /// @dev Internal function to verify both ECDSA and WebAuthn signatures against registered
    /// credentials
    /// @param account Address of the account
    /// @param hash Hash of the data to verify
    /// @param data Signature data containing both ECDSA and WebAuthn signatures
    /// @return bool True if signature is valid and meets threshold, false otherwise
    function _validateSignatureWithConfig(
        address account,
        bytes32 hash,
        bytes calldata data
    )
        internal
        view
        returns (bool)
    {
        if (!isInitialized(account)) return false;

        uint256 threshold = thresholds[account];

        // Decode the unified signature data
        // Format: abi.encode(UnifiedSignatureData memory signatureData)
        UnifiedSignatureData memory signatureData = abi.decode(data, (UnifiedSignatureData));

        uint256 validSignatures = 0;

        // Verify ECDSA signatures if present (use eth signed message hash)
        if (signatureData.ecdsaSignatureData.length > 0) {
            bytes32 ecdsaHash = ECDSA.toEthSignedMessageHash(hash);
            address[] memory ecdsaSigners = CheckSignatures.recoverNSignatures(
                ecdsaHash, signatureData.ecdsaSignatureData, threshold
            );

            // Count valid ECDSA signers
            for (uint256 i = 0; i < ecdsaSigners.length; i++) {
                if (ecdsaOwners.contains(account, ecdsaSigners[i])) {
                    validSignatures++;
                }
            }
        }

        // Verify WebAuthn signatures if present
        if (signatureData.webAuthnSignatureData.length > 0) {
            // Prepare WebAuthnCredential array from registered credentials
            WebAuthnCredential[] memory credentialData =
                new WebAuthnCredential[](signatureData.webAuthnCredentialIds.length);

            for (uint256 i = 0; i < signatureData.webAuthnCredentialIds.length; i++) {
                credentialData[i] =
                    webAuthnCredentialDetails[signatureData.webAuthnCredentialIds[i]][account];
            }

            validSignatures += _verifyWebAuthnSignatures(
                hash,
                signatureData.webAuthnSignatureData,
                WebAuthVerificationContext({
                    threshold: threshold,
                    credentialData: credentialData
                })
            );
        }

        return validSignatures >= threshold;
    }

    /// @dev Core WebAuthn signature verification logic
    /// @param hash Hash of the data to verify
    /// @param auth WebAuthn data containing signatures
    /// @param context Verification context containing credential details
    /// @return validCount Number of valid WebAuthn signatures
    function _verifyWebAuthnSignatures(
        bytes32 hash,
        WebAuthn.WebAuthnAuth[] memory auth,
        WebAuthVerificationContext memory context
    )
        internal
        view
        returns (uint256 validCount)
    {
        if (context.credentialData.length < auth.length) return 0;

        // Challenge is the hash to be signed
        bytes memory challenge = abi.encode(hash);

        for (uint256 i = 0; i < auth.length; i++) {
            // Verify the signature against the credential at the same index
            bool isValid = WebAuthn.verify(
                challenge,
                context.credentialData[i].requireUV,
                auth[i],
                context.credentialData[i].pubKeyX,
                context.credentialData[i].pubKeyY
            );
            if (isValid) validCount++;
        }

        return validCount;
    }

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the type of the module
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_STATELESS_VALIDATOR;
    }

    /// @notice Returns the name of the module
    function name() external pure virtual returns (string memory) {
        return "ContangoValidator";
    }

    /// @notice Returns the version of the module
    function version() external pure virtual returns (string memory) {
        return "1.0.0";
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

// Contracts
import { ERC7579HybridValidatorBase } from "modulekit/Modules.sol";

// Types
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";

// Libraries
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { EnumerableSet } from "@erc7579/enumerablemap4337/EnumerableSet4337.sol";
import { CheckSignatures } from "checknsignatures/CheckNSignatures.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { WebAuthn } from "@webauthn/WebAuthn.sol";
import { LibSort } from "solady/utils/LibSort.sol";
import { MODULE_TYPE_STATELESS_VALIDATOR as TYPE_STATELESS_VALIDATOR } from
    "modulekit/module-bases/utils/ERC7579Constants.sol";

/// @title WebAuthnValidator
/// @author Based on Rhinestone's OwnableValidator
/// @notice A validator module that enables WebAuthn (passkey) authentication with threshold support
/// @dev Module allows smart accounts to authenticate using one or more WebAuthn credentials
///     (passkeys) with support for M-of-N threshold signatures.
contract ContangoWebAuthnValidator is ERC7579HybridValidatorBase {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using EnumerableSet for EnumerableSet.Bytes32Set;
    using WebAuthn for bytes;
    using LibSort for bytes32[];

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Structure holding WebAuthn credential information
    /// @dev Maps a credential ID to its public key and verification requirements
    /// @param pubKeyX The X coordinate of the credential's public key on the P-256 curve
    /// @param pubKeyY The Y coordinate of the credential's public key on the P-256 curve
    /// @param requireUV Whether user verification (biometrics/PIN) is required for this credential
    struct WebAuthnCredential {
        uint256 pubKeyX;
        uint256 pubKeyY;
        bool requireUV;
    }

    /// @notice WebAuthVerificationContext
    /// @dev Context for WebAuthn verification, including credential details and threshold
    /// @param usePrecompile Whether to use the RIP7212 precompile for signature verification,
    ///                      or fallback to FreshCryptoLib. According to ERC-7562, calling the
    ///                      precompile is only allowed on networks that support it.
    /// @param threshold The number of signatures required for validation
    /// @param credentialIds The IDs of the credentials used for signing
    /// @param credential data WebAuthn credential data
    struct WebAuthVerificationContext {
        bool usePrecompile;
        uint256 threshold;
        WebAuthnCredential[] credentialData;
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the module is installed for an account
    event ModuleInitialized(address indexed account);

    /// @notice Emitted when the module is uninstalled for an account
    event ModuleUninitialized(address indexed account);

    /// @notice Emitted when a threshold is set for an account
    /// @param account The address of the smart account
    /// @param threshold The new threshold value
    event ThresholdSet(address indexed account, uint256 threshold);

    /// @notice Emitted when a credential is added to an account
    /// @param account The address of the smart account
    /// @param credentialId The ID of the added credential
    /// @param credential The WebAuthn credential
    event CredentialAdded(
        address indexed account, bytes32 indexed credentialId, WebAuthnCredential credential
    );

    /// @notice Emitted when a credential is removed from an account
    /// @param account The address of the smart account
    /// @param credentialId The ID of the removed credential
    event CredentialRemoved(address indexed account, bytes32 indexed credentialId);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when credential IDs are not sorted
    error NotSorted();

    error InvalidPublicKey(); // todo: maybe remove
    error InvalidThreshold(uint256 threshold, uint256 minThreshold, uint256 maxThreshold);
    error InvalidCredentialsCount(
        uint256 credentialCount, uint256 minCredentialCount, uint256 maxCredentialCount
    );
    error AddCredentialError_CredentialAlreadyExists(address account, WebAuthnCredential credential);
    error RemoveCredentialError_CredentialDoesNotExist(address account, bytes32 credentialId);

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum number of credentials allowed per account
    uint256 constant MAX_OWNERS = 32;
    uint256 constant MIN_OWNERS = 1;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Enumerable set of enabled credentials per account
    EnumerableSet.Bytes32Set owners;

    /// @notice Mapping of credential IDs to their respective WebAuthn credentials
    mapping(bytes32 credentialId => mapping(address account => WebAuthnCredential credential))
        public credentialDetails;

    /// @notice Threshold for each account
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

    // Default to the min and max value constants for the invariants
    modifier checkInvariants() {
        _;
        _checkInvariants(msg.sender, MIN_OWNERS, MAX_OWNERS);
    }

    function _checkInvariants(
        address account,
        uint256 minCredentialsCount,
        uint256 maxCredentialsCount
    )
        internal
        view
    {
        uint256 credentialsCount = owners.length(account);
        uint256 threshold = thresholds[account];
        require(
            minCredentialsCount <= credentialsCount && credentialsCount <= maxCredentialsCount,
            InvalidCredentialsCount(credentialsCount, minCredentialsCount, maxCredentialsCount)
        );
        require(
            minCredentialsCount <= threshold && threshold <= credentialsCount,
            InvalidThreshold(threshold, minCredentialsCount, credentialsCount)
        );
    }

    function _setThreshold(address account, uint256 _threshold) internal {
        thresholds[account] = _threshold;
        emit ThresholdSet(account, _threshold);
    }

    function _addCredentials(address account, WebAuthnCredential[] memory _credentials) internal {
        for (uint256 i = 0; i < _credentials.length; i++) {
            WebAuthnCredential memory credential = _credentials[i];
            bytes32 credentialId = _generateCredentialId(account, credential);

            if (credential.pubKeyX == 0 || credential.pubKeyY == 0) revert InvalidPublicKey();

            if (owners.add(account, credentialId)) {
                credentialDetails[credentialId][account] = credential;
                emit CredentialAdded(account, credentialId, credential);
            } else {
                revert AddCredentialError_CredentialAlreadyExists(account, credential);
            }
        }
    }

    function _removeCredentials(address account, bytes32[] memory _credentialIds) internal {
        for (uint256 i = 0; i < _credentialIds.length; i++) {
            bytes32 credentialId = _credentialIds[i];

            if (owners.remove(account, credentialId)) {
                delete credentialDetails[credentialId][account];
                emit CredentialRemoved(account, credentialId);
            } else {
                revert RemoveCredentialError_CredentialDoesNotExist(account, credentialId);
            }
        }
    }

    function _updateConfig(
        uint256 newThreshold,
        WebAuthnCredential[] memory credentialsToAdd,
        bytes32[] memory credentialsToRemove
    )
        internal
        moduleIsInitialized
        checkInvariants
    {
        address account = msg.sender;
        _setThreshold(account, newThreshold);
        _addCredentials(account, credentialsToAdd);
        _removeCredentials(account, credentialsToRemove);
    }

    /// @notice Updates the config for the account
    /// @dev Updates the threshold and credentials for the account
    /// @param newThreshold uint256 new threshold to set
    /// @param credentialsToAdd WebAuthnCredential[] array of credentials to add
    /// @param credentialsToRemove bytes32[] array of credential IDs to remove
    function updateConfig(
        uint256 newThreshold,
        WebAuthnCredential[] calldata credentialsToAdd,
        bytes32[] calldata credentialsToRemove
    )
        external
        virtual
    {
        _updateConfig(newThreshold, credentialsToAdd, credentialsToRemove);
    }

    /// @notice Initializes the module with WebAuthn credentials
    /// @dev Installs the validator with threshold and initial set of credentials
    /// @param data Encoded as: abi.encode(threshold, pubKeysX, pubKeysY, requireUVs)
    function onInstall(bytes calldata data)
        external
        override
        moduleIsNotInitialized
        checkInvariants
    {
        // Decode the credential data
        (uint256 _threshold, WebAuthnCredential[] memory _credentials) =
            abi.decode(data, (uint256, WebAuthnCredential[]));

        _setThreshold(msg.sender, _threshold);
        _addCredentials(msg.sender, _credentials);
    }

    /// @notice Handles the uninstallation of the module and clears all credentials
    /// @dev Removes all credentials and settings for the account
    function onUninstall(bytes calldata) external override moduleIsInitialized {
        address account = msg.sender;
        _removeCredentials(account, getCredentialIds(account));
        _setThreshold(account, 0);
        _checkInvariants(account, 0, 0);

        emit ModuleUninitialized(msg.sender);
    }

    function isInitialized(address smartAccount) public view returns (bool) {
        return thresholds[smartAccount] != 0;
    }

    function getCredentialIds(address account)
        public
        view
        returns (bytes32[] memory credentialsIds)
    {
        return owners.values(account);
    }

    function getCredential(
        address account,
        bytes32 credentialId
    )
        public
        view
        returns (WebAuthnCredential memory)
    {
        return credentialDetails[credentialId][account];
    }

    function getCredentials(address account) public view returns (WebAuthnCredential[] memory) {
        bytes32[] memory credentialIds = owners.values(account);
        WebAuthnCredential[] memory _credentials = new WebAuthnCredential[](credentialIds.length);
        for (uint256 i = 0; i < credentialIds.length; i++) {
            _credentials[i] = credentialDetails[credentialIds[i]][account];
        }
        return _credentials;
    }

    function getCredentialCount(address account) external view returns (uint256 count) {
        return owners.length(account);
    }

    function hasCredential(
        address account,
        WebAuthnCredential memory credential
    )
        external
        view
        returns (bool exists)
    {
        bytes32 credentialId = _generateCredentialId(account, credential);
        return owners.contains(account, credentialId);
    }

    function hasCredentialById(
        address account,
        bytes32 credentialId
    )
        external
        view
        returns (bool exists)
    {
        return owners.contains(account, credentialId);
    }

    // internal
    function _getCredentialById(
        address account,
        bytes32 credentialId
    )
        internal
        view
        returns (WebAuthnCredential memory)
    {
        return credentialDetails[credentialId][account];
    }

    // external
    function getCredentialById(
        address account,
        bytes32 credentialId
    )
        external
        view
        returns (WebAuthnCredential memory)
    {
        return _getCredentialById(account, credentialId);
    }

    // internal
    function _generateCredentialId(
        address account,
        WebAuthnCredential memory credential
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(credential.pubKeyX, credential.pubKeyY, account));
    }

    // external
    function generateCredentialId(
        address account,
        WebAuthnCredential memory credential
    )
        external
        pure
        returns (bytes32)
    {
        return _generateCredentialId(account, credential);
    }

    /*//////////////////////////////////////////////////////////////
                                VALIDATE
    //////////////////////////////////////////////////////////////*/

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        view
        override
        returns (ValidationData)
    {
        if (_validateSignatureWithConfig(userOp.sender, userOpHash, userOp.signature)) {
            return VALIDATION_SUCCESS;
        }
        return VALIDATION_FAILED;
    }

    /// @notice Validates an ERC-1271 signature with the sender
    /// @dev Implements EIP-1271 isValidSignature for smart contract signatures
    /// @param hash Hash of the data to validate
    /// @param data Signature data
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
    /// @param hash Hash of the data to validate
    /// @param signature WebAuthn signature data
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
        // Decode the threshold, credentials and account address from data
        // Format: abi.encode(WebAuthVerificationContext memory context, address account)
        (WebAuthVerificationContext memory context,) =
            abi.decode(data, (WebAuthVerificationContext, address));

        // Decode signature
        // Format: abi.encode(WebAuthn.WebAuthnAuth[])
        WebAuthn.WebAuthnAuth[] memory auth = abi.decode(signature, (WebAuthn.WebAuthnAuth[]));

        // Verify WebAuthn signatures
        return _verifyWebAuthnSignatures(hash, auth, context);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a signature against the account's credentials
    /// @dev Internal function to verify WebAuthn signatures against registered keys
    /// @param account Address of the account
    /// @param hash Hash of the data to verify
    /// @param data Signature data
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
        // Get the threshold
        uint256 threshold = thresholds[account];

        if (!isInitialized(account)) return false;

        // Get credential IDs from data
        // Format: abi.encode(bytes32[], bool, bytes)
        (bytes32[] memory credIds, bool usePrecompile, WebAuthn.WebAuthnAuth[] memory auth) =
            abi.decode(data, (bytes32[], bool, WebAuthn.WebAuthnAuth[]));

        // Prepare WebAuthnCredential array
        WebAuthnCredential[] memory credentialData = new WebAuthnCredential[](credIds.length);

        // Populate credential data
        for (uint256 i; i < credIds.length; ++i) {
            credentialData[i] = credentialDetails[credIds[i]][account];
        }

        // Set up the verification context
        WebAuthVerificationContext memory context = WebAuthVerificationContext({
            usePrecompile: usePrecompile,
            threshold: threshold,
            credentialData: credentialData
        });

        // Verify WebAuthn signatures
        return _verifyWebAuthnSignatures(hash, auth, context);
    }

    /// @dev Core signature verification logic
    /// @param hash Hash of the data to verify
    /// @param auth WebAuthn data containing signatures
    /// @param context Verification context containing credential details
    /// @return success Whether verification process completed successfully
    function _verifyWebAuthnSignatures(
        bytes32 hash,
        WebAuthn.WebAuthnAuth[] memory auth,
        WebAuthVerificationContext memory context
    )
        internal
        view
        returns (bool success)
    {
        if (context.credentialData.length < auth.length) return false;

        // Challenge is the hash to be signed
        bytes memory challenge = abi.encode(hash);

        uint256 validCount;
        for (uint256 i; i < auth.length; ++i) {
            // Verify the signature against the credential at the same index
            bool valid = _verifyWebAuthSignature(
                challenge, auth[i], context.credentialData[i], context.usePrecompile
            );
            if (valid) ++validCount;
        }

        return validCount >= context.threshold;
    }

    function _verifyWebAuthSignature(
        bytes memory challenge,
        WebAuthn.WebAuthnAuth memory auth,
        WebAuthnCredential memory credential,
        bool usePrecompile
    )
        internal
        view
        returns (bool)
    {
        return WebAuthn.verify(
            challenge,
            credential.requireUV,
            auth,
            credential.pubKeyX,
            credential.pubKeyY,
            usePrecompile
        );
    }

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the type of the module
    /// @dev Implements interface to indicate validator capabilities
    /// @param typeID Type identifier to check
    /// @return bool True if this module supports the specified type
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_STATELESS_VALIDATOR;
    }

    /// @notice Returns the name of the module
    /// @dev Provides a human-readable identifier for the module
    /// @return string Module name
    function name() external pure virtual returns (string memory) {
        return "ContangoWebAuthnValidator";
    }

    /// @notice Returns the version of the module
    /// @dev Provides version information for compatibility checks
    /// @return string Semantic version of the module
    function version() external pure virtual returns (string memory) {
        return "1.0.0";
    }
}

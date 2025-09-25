// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { ContangoWebAuthnTestValidator } from
    "test/ContangoWebAuthnValidator/ContangoWebAuthnValidatorTest.sol";
import { ERC7579HybridValidatorBase, ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { WebAuthn } from "webauthn-sol/src/WebAuthn.sol";
import { IModule as IERC7579Module } from "modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { EIP1271_MAGIC_VALUE } from "test/utils/Constants.sol";
import { ContangoWebAuthnValidator } from
    "src/ContangoWebAuthnValidator/ContangoWebAuthnValidator.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";
import { LibSort } from "solady/utils/LibSort.sol";
import { console } from "forge-std/console.sol";

contract ContangoWebAuthnValidatorTest is BaseTest {
    /*//////////////////////////////////////////////////////////////////////////
                                    LIBRARIES
    //////////////////////////////////////////////////////////////////////////*/

    using LibSort for bytes32[];

    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    ContangoWebAuthnTestValidator internal validator;

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    uint256 _threshold = 2;

    // Mock WebAuthn signature data
    WebAuthn.WebAuthnAuth mockAuth;

    // Mock signature data for testing
    bytes mockSignatureData;

    // Deterministically generated credential IDs (computed in setUp)
    bytes32[] _credentialIds;
    ContangoWebAuthnValidator.WebAuthnCredential[] _credentials;
    mapping(bytes32 => ContangoWebAuthnValidator.WebAuthnCredential) public credentialIdToCredential;

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        BaseTest.setUp();
        validator = new ContangoWebAuthnTestValidator();

        // Initialize storage array by pushing elements instead of direct assignment
        _credentials.push(
            ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: 66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805,
                pubKeyY: 46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186,
                requireUV: false
            })
        );

        _credentials.push(
            ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: 77_427_310_596_034_628_445_756_159_459_159_056_108_500_819_865_614_675_054_701_790_516_611_205_123_311,
                pubKeyY: 20_591_151_874_462_689_689_754_215_152_304_668_244_192_265_896_034_279_288_204_806_249_532_173_935_644,
                requireUV: true
            })
        );

        // Pre-compute credential IDs for testing
        uint256 credentialsCount = _credentials.length;
        for (uint256 i = 0; i < credentialsCount; i++) {
            bytes32 credentialId = validator.generateCredentialId(address(this), _credentials[i]);
            _credentialIds.push(credentialId);
            credentialIdToCredential[credentialId] = _credentials[i];
        }

        // Use a fixed challenge for testing
        bytes memory challenge =
            abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Set up real WebAuthn authentication data
        mockAuth = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001",
            clientDataJSON: string.concat(
                '{"type":"webauthn.get","challenge":"',
                Base64Url.encode(challenge),
                '","origin":"http://localhost:8080","crossOrigin":false}'
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 23_510_924_181_331_275_540_501_876_269_042_668_160_690_304_423_490_805_737_085_519_687_669_896_593_880,
            s: 36_590_747_517_247_563_381_084_733_394_442_750_806_324_326_036_343_798_276_847_517_765_557_371_045_088
        });

        // Create WebAuthn signature data
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);

        sigs[0] = mockAuth;

        // Use a slightly different signature for the second credential
        WebAuthn.WebAuthnAuth memory mockAuth2 = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001",
            clientDataJSON: string.concat(
                '{"type":"webauthn.get","challenge":"',
                Base64Url.encode(challenge),
                '","origin":"http://localhost:8080","crossOrigin":false}'
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 70_190_788_404_940_879_339_470_429_048_068_864_326_256_942_039_718_306_809_827_270_917_601_845_266_065,
            s: 372_310_544_955_428_259_193_186_543_685_199_264_627_091_796_694_315_697_785_543_526_117_532_572_367
        });

        sigs[1] = mockAuth2;

        // Create the new signature format that includes the credential IDs:
        // abi.encode(credentialIds, abi.encode(signatures))
        mockSignatureData = abi.encode(_credentialIds, false, sigs);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                 CONFIG
    //////////////////////////////////////////////////////////////*/

    function test_GenerateCredentialId() public view {
        // Test that credential ID generation is deterministic based on the following properties:
        // address, pubKeyX, pubKeyY (Note: requireUV is not included in the generation)
        bytes32 credId1 = validator.generateCredentialId(address(this), _credentials[0]);

        bytes32 credId2 = validator.generateCredentialId(
            address(this),
            ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: _credentials[0].pubKeyX,
                pubKeyY: _credentials[0].pubKeyY,
                requireUV: !_credentials[0].requireUV // negate the requireUV
             })
        );

        assertEq(credId1, credId2, "RequireUV should not affect the credential ID generation");

        // Test that different parameters produce different credential IDs
        bytes32 credId3 = validator.generateCredentialId(
            address(1), // Different address
            _credentials[0]
        );

        assertTrue(
            credId2 != credId3, "Different addresses should produce different credential IDs"
        );
    }

    function test_OnInstallRevertWhen_ModuleIsInitialized() public {
        // Install the module first

        bytes memory data = abi.encode(_threshold, _credentials);
        validator.onInstall(data);

        ContangoWebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new ContangoWebAuthnValidator.WebAuthnCredential[](1);
        webAuthnCredentials[0] = ContangoWebAuthnValidator.WebAuthnCredential({
            pubKeyX: 1000,
            pubKeyY: 2000,
            requireUV: false
        });
        bytes memory data2 = abi.encode(1, webAuthnCredentials);

        // Try to install again with different data than initially
        vm.expectRevert();
        validator.onInstall(data2);

        // try installing again with same data as initially
        vm.expectRevert();
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_ThresholdIs0() public whenModuleIsNotInitialized {
        // Create data with threshold = 0
        bytes memory data = abi.encode(0, _credentials);

        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoWebAuthnValidator.InvalidThreshold.selector, 0, 1, _credentials.length
            )
        );
        validator.onInstall(data);
    }

    function test_OnInstallWhenThresholdIsValid() public whenModuleIsNotInitialized {
        bytes memory data = abi.encode(_threshold, _credentials);
        validator.onInstall(data);

        uint256 threshold = validator.thresholds(address(this));
        assertEq(threshold, _threshold, "Threshold should be set correctly");
    }

    function test_OnInstallRevertWhen_CredentialsLengthIsLessThanThreshold()
        public
        whenModuleIsNotInitialized
    {
        // Create data with threshold > credentials length
        bytes memory data = abi.encode(3, _credentials);

        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoWebAuthnValidator.InvalidThreshold.selector, 3, 1, _credentials.length
            )
        );
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_CredentialsLengthIsMoreThanMax()
        public
        whenModuleIsNotInitialized
    {
        // Create array with 33 credentials (exceeding MAX_CREDENTIALS)
        ContangoWebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new ContangoWebAuthnValidator.WebAuthnCredential[](33);

        for (uint256 i = 0; i < 33; i++) {
            webAuthnCredentials[i] = ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: i + 1000,
                pubKeyY: i + 2000,
                requireUV: (i % 2 == 0) // Alternate true/false
             });
        }

        bytes memory data = abi.encode(_threshold, webAuthnCredentials);

        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoWebAuthnValidator.InvalidCredentialsCount.selector, 33, 1, 32
            )
        );
        validator.onInstall(data);
    }

    // why validate calldata? Why is a public key of 0 not valid, yet we don't revert if its 1?
    // they're both highly improbable/impossible to be valid public keys in practice, so why treat
    // them differently?

    function test_OnInstallRevertWhen_PubKeyXIsZero() public whenModuleIsNotInitialized {
        // Create credentials with zero X pubkey
        ContangoWebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new ContangoWebAuthnValidator.WebAuthnCredential[](2);

        webAuthnCredentials[0] = ContangoWebAuthnValidator.WebAuthnCredential({
            pubKeyX: 0, // Zero pubkey
            pubKeyY: _credentials[0].pubKeyY,
            requireUV: _credentials[0].requireUV
        });

        webAuthnCredentials[1] = _credentials[1];

        bytes memory data = abi.encode(_threshold, webAuthnCredentials);

        vm.expectRevert(ContangoWebAuthnValidator.InvalidPublicKey.selector);
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_PubKeyYIsZero() public whenModuleIsNotInitialized {
        // Create credentials with zero X pubkey
        ContangoWebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new ContangoWebAuthnValidator.WebAuthnCredential[](2);

        webAuthnCredentials[0] = ContangoWebAuthnValidator.WebAuthnCredential({
            pubKeyX: _credentials[0].pubKeyX,
            pubKeyY: 0, // Zero pubkey
            requireUV: _credentials[0].requireUV
        });

        webAuthnCredentials[1] = _credentials[1];

        bytes memory data = abi.encode(_threshold, webAuthnCredentials);

        vm.expectRevert(ContangoWebAuthnValidator.InvalidPublicKey.selector);
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_CredentialsNotUnique() public whenModuleIsNotInitialized {
        // Create credentials with duplicate values (same pubKeyX, pubKeyY, requireUV)
        ContangoWebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new ContangoWebAuthnValidator.WebAuthnCredential[](2);

        webAuthnCredentials[0] = _credentials[0];
        webAuthnCredentials[1] = _credentials[0];

        bytes memory data = abi.encode(_threshold, webAuthnCredentials);

        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoWebAuthnValidator.AddCredentialError_CredentialAlreadyExists.selector,
                address(this),
                webAuthnCredentials[0]
            )
        );
        validator.onInstall(data);
    }

    function test_OnInstallWhenCredentialsAreValid() public whenModuleIsNotInitialized {
        bytes memory data = abi.encode(_threshold, _credentials);
        validator.onInstall(data);

        ContangoWebAuthnValidator.WebAuthnCredential[] memory credentialsOnContract =
            validator.getCredentials(address(this));
        assertEq(credentialsOnContract.length, _credentials.length, "Credential count should match");

        // test getCredentialIds and make sure it matches the credentials
        bytes32[] memory credIds = validator.getCredentialIds(address(this));
        assertEq(credIds.length, _credentials.length, "Credential count should match");

        // knowing that the lengths math, we now take the credentials that we got from the contract
        // and compare them
        // to the expected, which is the credentials we've defined in the test setup
        for (uint256 i = 0; i < credentialsOnContract.length; i++) {
            bytes32 credentialId =
                validator.generateCredentialId(address(this), credentialsOnContract[i]);
            ContangoWebAuthnValidator.WebAuthnCredential memory credentialInTestSetup =
                credentialIdToCredential[credentialId];

            assertEq(
                credentialsOnContract[i].pubKeyX,
                credentialInTestSetup.pubKeyX,
                "Public key X should match"
            );
            assertEq(
                credentialsOnContract[i].pubKeyY,
                credentialInTestSetup.pubKeyY,
                "Public key Y should match"
            );
            assertEq(
                credentialsOnContract[i].requireUV,
                credentialInTestSetup.requireUV,
                "RequireUV should match"
            );
        }
    }

    function test_OnUninstallShouldRemoveAllCredentials() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Then uninstall
        validator.onUninstall("");

        // Check credentials were removed
        bytes32[] memory credIds = validator.getCredentialIds(address(this));
        ContangoWebAuthnValidator.WebAuthnCredential[] memory credentialsOnContract =
            validator.getCredentials(address(this));
        assertEq(credentialsOnContract.length, 0, "All credentials should be removed");
        assertEq(credIds.length, 0, "All credentials should be removed");
    }

    function test_OnUninstallShouldSetThresholdTo0() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Then uninstall
        validator.onUninstall("");

        // Check threshold is 0
        uint256 threshold = validator.thresholds(address(this));
        assertEq(threshold, 0, "Threshold should be reset to 0");
    }

    function test_IsInitializedWhenModuleIsNotInitialized() public view {
        // Should return false when not initialized
        bool isInitialized = validator.isInitialized(address(this));
        assertFalse(isInitialized, "Module should not be initialized");
    }

    function test_IsInitializedWhenModuleIsInitialized() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Should return true when initialized
        bool isInitialized = validator.isInitialized(address(this));
        assertTrue(isInitialized, "Module should be initialized");
    }

    function test_SetThresholdRevertWhen_ModuleIsNotInitialized() public {
        // Should revert
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.setThreshold(1);
    }

    function test_SetThresholdRevertWhen_ThresholdIs0() public whenModuleIsInitialized {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoWebAuthnValidator.InvalidThreshold.selector, 0, 1, _credentials.length
            )
        );
        validator.setThreshold(0);
    }

    function test_SetThresholdRevertWhen_ThresholdIsHigherThanCredentialsCount()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoWebAuthnValidator.InvalidThreshold.selector, 10, 1, _credentials.length
            )
        );
        validator.setThreshold(10);
    }

    function test_SetThresholdWhenThresholdIsValid() public whenModuleIsInitialized {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Get current threshold
        uint256 oldThreshold = validator.thresholds(address(this));
        uint256 newThreshold = 1;
        assertNotEq(oldThreshold, newThreshold, "New threshold should be different");

        // Set threshold
        validator.setThreshold(newThreshold);

        // Check threshold
        assertEq(validator.thresholds(address(this)), newThreshold, "Threshold should be updated");
    }

    function test_AddCredentialRevertWhen_ModuleIsNotInitialized() public {
        // Should revert
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );

        validator.addCredential(
            ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: 99_999,
                pubKeyY: 88_888,
                requireUV: true
            })
        );
    }

    function test_AddCredentialRevertWhen_PubKeyIsZero() public whenModuleIsInitialized {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Should revert when X is 0
        vm.expectRevert(ContangoWebAuthnValidator.InvalidPublicKey.selector);
        validator.addCredential(
            ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: 0,
                pubKeyY: 88_888,
                requireUV: true
            })
        );

        // Should revert when Y is 0
        vm.expectRevert(ContangoWebAuthnValidator.InvalidPublicKey.selector);
        validator.addCredential(
            ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: 99_999,
                pubKeyY: 0,
                requireUV: true
            })
        );
    }

    function test_AddCredentialRevertWhen_CredentialCountIsMoreThanMax()
        public
        whenModuleIsInitialized
    {
        // Create and install module with 32 credentials
        ContangoWebAuthnValidator.WebAuthnCredential[] memory webAuthnCredentials =
            new ContangoWebAuthnValidator.WebAuthnCredential[](32);

        for (uint256 i = 0; i < 32; i++) {
            webAuthnCredentials[i] = ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: i + 1000,
                pubKeyY: i + 2000,
                requireUV: (i % 2 == 0) // Alternate true/false
             });
        }

        bytes memory data = abi.encode(1, webAuthnCredentials);
        validator.onInstall(data);

        // Try to add one more credential
        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoWebAuthnValidator.InvalidCredentialsCount.selector, 33, 1, 32
            )
        );
        validator.addCredential(
            ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: 99_999,
                pubKeyY: 88_888,
                requireUV: true
            })
        );
    }

    function test_AddCredentialRevertWhen_CredentialAlreadyExists()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Try to add a credential that already exists
        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoWebAuthnValidator.AddCredentialError_CredentialAlreadyExists.selector,
                address(this),
                _credentials[0]
            )
        );
        validator.addCredential(_credentials[0]);
    }

    function test_AddCredentialWhenCredentialIsValid() public whenModuleIsInitialized {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        ContangoWebAuthnValidator.WebAuthnCredential memory newCredential =
        ContangoWebAuthnValidator.WebAuthnCredential({
            pubKeyX: 99_999,
            pubKeyY: 88_888,
            requireUV: true
        });

        validator.addCredential(newCredential);

        // Compute the credential ID
        bytes32 newCredentialId = validator.generateCredentialId(address(this), newCredential);

        // Check credential was added
        assertTrue(
            validator.hasCredential(address(this), newCredential),
            "Should have credential by parameters"
        );

        assertTrue(
            validator.hasCredentialById(address(this), newCredentialId),
            "Should have credential by ID"
        );

        // Check credential info
        ContangoWebAuthnValidator.WebAuthnCredential memory credential =
            validator.getCredential(address(this), newCredentialId);
        assertEq(credential.pubKeyX, newCredential.pubKeyX, "Public key X should match");
        assertEq(credential.pubKeyY, newCredential.pubKeyY, "Public key Y should match");
        assertEq(credential.requireUV, newCredential.requireUV, "RequireUV should match");

        // Check credential count
        assertEq(validator.getCredentialCount(address(this)), 3, "Credential count should be 3");
    }

    function test_RemoveCredentialRevertWhen_ModuleIsNotInitialized() public {
        // Should revert
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.removeCredential(
            ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: 99_999,
                pubKeyY: 88_888,
                requireUV: true
            })
        );
    }

    function test_RemoveCredentialRevertWhen_CredentialDoesNotExist()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        ContangoWebAuthnValidator.WebAuthnCredential memory credentialToRemove =
        ContangoWebAuthnValidator.WebAuthnCredential({
            pubKeyX: 99_999,
            pubKeyY: 88_888,
            requireUV: true
        });

        // Try to remove a credential that doesn't exist
        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoWebAuthnValidator.RemoveCredentialError_CredentialDoesNotExist.selector,
                address(this),
                validator.generateCredentialId(address(this), credentialToRemove)
            )
        );
        validator.removeCredential(credentialToRemove);
    }

    function test_RemoveCredentialRevertWhen_RemovalWouldBreakThreshold()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // We have 2 credentials with threshold 2, so removing any would break threshold
        vm.expectRevert(
            abi.encodeWithSelector(ContangoWebAuthnValidator.InvalidThreshold.selector, 2, 1, 1)
        );
        validator.removeCredential(_credentials[0]);
    }

    function test_RemoveCredentialWhenRemovalWouldNotBreakThreshold()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // removing one and lowering threshold should work however
        bytes32[] memory credentialIdsToRemove = new bytes32[](1);
        credentialIdsToRemove[0] = validator.generateCredentialId(address(this), _credentials[0]);
        validator.updateConfig(
            1, new ContangoWebAuthnValidator.WebAuthnCredential[](0), credentialIdsToRemove
        );

        // Check credential was removed
        assertFalse(
            validator.hasCredential(address(this), _credentials[0]), "Credential should be removed"
        );

        assertFalse(
            validator.hasCredentialById(address(this), credentialIdsToRemove[0]),
            "Credential should be removed by ID check"
        );

        // Check credential count
        assertEq(validator.getCredentialCount(address(this)), 1, "Credential count should be 1");
    }

    function test_GetCredentialIds() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Get credential IDs
        bytes32[] memory credIds = validator.getCredentialIds(address(this));

        // Check length
        assertEq(credIds.length, _credentialIds.length, "Should have correct number of credentials");
        assertEq(credIds.length, _credentials.length, "Should have correct number of credentials");

        // Check IDs match (may be in different order due to set storage)
        bool found0 = false;
        bool found1 = false;

        for (uint256 i = 0; i < credIds.length; i++) {
            if (credIds[i] == _credentialIds[0]) found0 = true;
            if (credIds[i] == _credentialIds[1]) found1 = true;
        }

        assertTrue(found0, "First credential should be found");
        assertTrue(found1, "Second credential should be found");
    }

    function test_HasCredential() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Check existing credential by parameters
        assertTrue(
            validator.hasCredential(address(this), _credentials[0]), "Should have first credential"
        );

        // Check existing credential by ID
        assertTrue(
            validator.hasCredentialById(address(this), _credentialIds[0]),
            "Should have first credential by ID"
        );

        // Check non-existent credential
        assertFalse(
            validator.hasCredential(
                address(this),
                ContangoWebAuthnValidator.WebAuthnCredential({
                    pubKeyX: 99_999,
                    pubKeyY: 88_888,
                    requireUV: true
                })
            ),
            "Should not have non-existent credential"
        );
    }

    function test_GetCredentialCount() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Check credential count
        assertEq(validator.getCredentialCount(address(this)), 2, "Should have 2 credentials");

        // Add a credential
        validator.addCredential(
            ContangoWebAuthnValidator.WebAuthnCredential({
                pubKeyX: 99_999,
                pubKeyY: 88_888,
                requireUV: true
            })
        );

        // Check updated credential count
        assertEq(validator.getCredentialCount(address(this)), 3, "Should have 3 credentials");
    }

    function test_GetCredentialInfo() public {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Get credential for credential ID [0]
        ContangoWebAuthnValidator.WebAuthnCredential memory credential =
            validator.getCredential(address(this), _credentialIds[1]);

        // Check info matches
        assertEq(credential.pubKeyX, _credentials[1].pubKeyX, "Public key X should match");
        assertEq(credential.pubKeyY, _credentials[1].pubKeyY, "Public key Y should match");
        assertEq(credential.requireUV, _credentials[1].requireUV, "RequireUV should match");
    }

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    function test_IsModuleType() public view {
        // Test validation type
        assertTrue(
            validator.isModuleType(uint256(1)), // TYPE_VALIDATOR
            "Should return true for TYPE_VALIDATOR"
        );

        // Test stateless validation type
        assertTrue(
            validator.isModuleType(uint256(7)), "Should return true for TYPE_STATELESS_VALIDATOR"
        );

        // Test invalid type
        assertFalse(validator.isModuleType(99), "Should return false for invalid type");
    }

    function test_Name() public view {
        string memory name = validator.name();
        assertEq(name, "ContangoWebAuthnValidator", "Name should be ContangoWebAuthnValidator");
    }

    function test_Version() public view {
        string memory version = validator.version();
        assertEq(version, "1.0.0", "Version should be 1.0.0");
    }

    /*//////////////////////////////////////////////////////////////
                               VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_ValidateUserOpWhenThresholdIsNotSet() public view {
        // should return VALIDATION_FAILED
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(
            validationData, uint256(1), "Should return VALIDATION_FAILED when threshold is not set"
        );
    }

    function test_ValidateUserOpWhenSignaturesAreNotInOrderWithCredentials()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a user operation with invalid signatures
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        // Create signature data with credentials in wrong order
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);

        // Swap the credential IDs in the WebAuthnSignatureData
        sigs[0] = mockAuth;
        sigs[1] = mockAuth;

        // But still use the correct order in the outer array
        userOp.signature = abi.encode(_credentialIds, false, sigs);

        // Validation should fail because the signature data doesn't match
        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(
            validationData,
            uint256(1),
            "Should return VALIDATION_FAILED when signatures are not in order"
        );
    }

    function test_ValidateUserOpWhenNotEnoughValidSignatures() public whenModuleIsInitialized {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a user operation with invalid signatures
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        // Create signature data with only 1 valid signature (threshold is 2)
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);

        // Swap the credential IDs in the WebAuthnSignatureData
        sigs[0] = mockAuth;
        sigs[1] = mockAuth;

        // Encode the signatures
        (bytes32[] memory credIds,,) = abi.decode(mockSignatureData, (bytes32[], bool, bytes));
        userOp.signature = abi.encode(credIds, false, sigs);

        // Validation should fail because we need 2 valid signatures
        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(
            validationData,
            uint256(1),
            "Should return VALIDATION_FAILED when not enough valid signatures"
        );
    }

    function test_IsValidSignatureWithSenderWhenThresholdIsNotSet() public view {
        // Should return EIP1271_FAILED
        bytes32 hash = bytes32(keccak256("test message"));
        bytes memory data = "";

        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, data);
        assertNotEq(
            result, EIP1271_MAGIC_VALUE, "Should return EIP1271_FAILED when threshold is not set"
        );
    }

    function test_IsValidSignatureWithSenderWhenSignaturesAreNotInOrderWithCredentials()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a message hash
        bytes32 hash = bytes32(keccak256("test message"));

        // Create signature data with credentials in wrong order
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);

        // Swap the credential IDs in the WebAuthnSignatureData
        sigs[0] = mockAuth;
        sigs[1] = mockAuth;

        // But still use the correct order in the outer array
        bytes memory signature = abi.encode(_credentialIds, false, sigs);

        // Validation should fail
        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, signature);
        assertNotEq(
            result,
            EIP1271_MAGIC_VALUE,
            "Should return EIP1271_FAILED when signatures are not in order"
        );
    }

    function test_IsValidSignatureWithSenderWhenNotEnoughValidSignatures()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a message hash
        bytes32 hash = bytes32(keccak256("test message"));

        // Create signature data with only 1 valid signature (threshold is 2)
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);

        // Swap the credential IDs in the WebAuthnSignatureData
        sigs[0] = mockAuth;
        sigs[1] = mockAuth;

        // Encode the signatures
        (bytes32[] memory credIds,,) = abi.decode(mockSignatureData, (bytes32[], bool, bytes));
        bytes memory signature = abi.encode(credIds, false, sigs);

        // Validation should fail because we need 2 valid signatures
        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, signature);
        assertNotEq(
            result,
            EIP1271_MAGIC_VALUE,
            "Should return EIP1271_FAILED when not enough valid signatures"
        );
    }

    function test_ValidateSignatureWithDataWhenArrayLengthsDontMatch() public view {
        // Should return false when credential IDs and credential data arrays have different lengths
        bytes32 hash = bytes32(keccak256("test message"));
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);
        sigs[0] = mockAuth;
        sigs[1] = mockAuth;
        bytes memory signature = abi.encode(sigs);

        // Create verification context with mismatched arrays
        ContangoWebAuthnValidator.WebAuthVerificationContext memory context =
        ContangoWebAuthnValidator.WebAuthVerificationContext({
            usePrecompile: false,
            threshold: 2,
            credentialData: new ContangoWebAuthnValidator.WebAuthnCredential[](1) // Different
                // length!
         });

        bytes memory data = abi.encode(context, address(this));

        bool result = validator.validateSignatureWithData(hash, signature, data);
        assertFalse(result, "Should return false when array lengths don't match");
    }

    function test_ValidateSignatureWithDataWhenThresholdIsZero() public view {
        // Should return false when threshold is 0 or greater than credentials length
        bytes32 hash = bytes32(keccak256("test message"));
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);
        sigs[0] = mockAuth;
        sigs[1] = mockAuth;
        bytes memory signature = abi.encode(sigs);

        ContangoWebAuthnValidator.WebAuthVerificationContext memory context1 =
        ContangoWebAuthnValidator.WebAuthVerificationContext({
            usePrecompile: false,
            threshold: 0, // Invalid threshold
            credentialData: _credentials
        });

        bytes memory data1 = abi.encode(context1);
        bool result1 = validator.validateSignatureWithData(hash, signature, data1);

        // I see no reason to not allow a threshold of 0 when calling this pure function
        assertTrue(result1, "Should return true when threshold is 0");
        // assertFalse(result1, "Should return false when threshold is 0");
    }

    function test_ValidateSignatureWithDataWhenThresholdIsGreaterThanCredentialsLength()
        public
        view
    {
        // Should return false when threshold is 0 or greater than credentials length
        bytes32 hash = bytes32(keccak256("test message"));
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);
        sigs[0] = mockAuth;
        sigs[1] = mockAuth;
        bytes memory signature = abi.encode(sigs);

        ContangoWebAuthnValidator.WebAuthVerificationContext memory context =
        ContangoWebAuthnValidator.WebAuthVerificationContext({
            usePrecompile: false,
            threshold: 3, // Invalid threshold (> credentials length)
            credentialData: _credentials
        });

        bytes memory data = abi.encode(context);
        bool result = validator.validateSignatureWithData(hash, signature, data);
        assertFalse(result, "Should return false when threshold is greater than credentials length");
    }

    function test_ValidateSignatureWithDataWhenSignaturesAreNotInOrderWithCredentials()
        public
        view
    {
        // Should return false when signatures don't match credential order
        bytes32 hash = bytes32(keccak256("test message"));

        // Create signature data with credentials in wrong order
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);

        // Swap the credential IDs in the WebAuthnSignatureData
        sigs[0] = mockAuth;
        sigs[1] = mockAuth;

        // Encode the signatures
        bytes memory signature = abi.encode(sigs);

        // Context with valid threshold
        ContangoWebAuthnValidator.WebAuthVerificationContext memory context =
        ContangoWebAuthnValidator.WebAuthVerificationContext({
            usePrecompile: false,
            threshold: 2,
            credentialData: _credentials
        });

        bytes memory data = abi.encode(context);

        bool result = validator.validateSignatureWithData(hash, signature, data);
        assertFalse(result, "Should return false when signatures are not in order with credentials");
    }

    function test_ValidateSignatureWithDataWhenNotEnoughValidSignatures() public view {
        // Should return false when not enough valid signatures are provided
        bytes32 hash = bytes32(keccak256("test message"));

        // Create signature data
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);

        // Swap the credential IDs in the WebAuthnSignatureData
        sigs[0] = mockAuth;
        sigs[1] = mockAuth;

        // Encode the signatures
        bytes memory signature = abi.encode(sigs);

        // Context with valid threshold
        ContangoWebAuthnValidator.WebAuthVerificationContext memory context =
        ContangoWebAuthnValidator.WebAuthVerificationContext({
            usePrecompile: false,
            threshold: 2,
            credentialData: _credentials
        });

        bytes memory data = abi.encode(context);

        bool result = validator.validateSignatureWithData(hash, signature, data);
        assertFalse(result, "Should return false when not enough valid signatures are provided");
    }

    function test_ValidateUserOpWhenEnoughValidSignaturesAreProvided()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a user operation with valid signatures
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);

        // Use a fixed challenge that matches our WebAuthn signatures
        bytes32 userOpHash = createTestUserOpHash();

        // Use our pre-encoded valid signatures
        userOp.signature = mockSignatureData;

        // Validation should succeed with our real WebAuthn signatures
        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(
            validationData,
            uint256(0),
            "Should return VALIDATION_SUCCESS when enough valid signatures"
        );
    }

    function test_IsValidSignatureWithSenderWhenEnoughValidSignaturesAreProvided()
        public
        whenModuleIsInitialized
    {
        // First install the module
        test_OnInstallWhenCredentialsAreValid();

        // Create a message hash that matches our WebAuthn challenge
        bytes32 hash = createTestUserOpHash();

        // Use our pre-encoded valid signatures
        bytes memory signature = mockSignatureData;

        // Validation should succeed with our real WebAuthn signatures
        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, signature);
        assertEq(
            result,
            EIP1271_MAGIC_VALUE,
            "Should return EIP1271_SUCCESS when enough valid signatures"
        );
    }

    function test_ValidateSignatureWithDataWhenEnoughValidSignaturesAreProvidedInOrder()
        public
        view
    {
        // Create a message hash that matches our WebAuthn challenge
        bytes32 hash = createTestUserOpHash();

        // Use our pre-encoded valid signatures
        (,, WebAuthn.WebAuthnAuth[] memory signature) =
            abi.decode(mockSignatureData, (bytes32, bool, WebAuthn.WebAuthnAuth[]));

        // Context with valid threshold
        ContangoWebAuthnValidator.WebAuthVerificationContext memory context =
        ContangoWebAuthnValidator.WebAuthVerificationContext({
            usePrecompile: false,
            threshold: 2,
            credentialData: _credentials
        });

        bytes memory data = abi.encode(context, address(this));

        // Validation should succeed with our real WebAuthn signatures
        bool result = validator.validateSignatureWithData(hash, abi.encode(signature), data);
        assertTrue(result, "Should return true when enough valid signatures are provided in order");
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    MODIFIERS
    //////////////////////////////////////////////////////////////////////////*/

    modifier whenModuleIsNotInitialized() {
        _;
    }

    modifier whenModuleIsInitialized() {
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function createTestUserOpHash() internal pure returns (bytes32) {
        return bytes32(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);
    }
}

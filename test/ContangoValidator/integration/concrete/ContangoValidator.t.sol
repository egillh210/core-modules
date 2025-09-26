// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { ContangoTestValidator } from "test/ContangoValidator/ContangoValidatorTest.sol";
import { ContangoValidator } from "src/ContangoValidator/ContangoValidator.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { EIP1271_MAGIC_VALUE } from "test/utils/Constants.sol";
import { LibSort } from "solady/utils/LibSort.sol";
import { EnumerableMap } from "@erc7579/enumerablemap4337/EnumerableMap4337.sol";
import { WebAuthn } from "@webauthn-sol/WebAuthn.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";

contract ContangoValidatorIntegrationTest is BaseTest {
    using LibSort for *;
    using EnumerableMap for EnumerableMap.AddressToUintMap;

    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    ContangoTestValidator internal validator;

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    uint256 _threshold = 2;
    EnumerableMap.AddressToUintMap ecdsaOwnersMap;

    // WebAuthn test data
    ContangoValidator.WebAuthnCredential[] _webAuthnCredentials;
    bytes32[] _webAuthnCredentialIds;
    mapping(bytes32 => ContangoValidator.WebAuthnCredential) public webAuthnCredentialIdToCredential;

    // Mock WebAuthn signature data
    WebAuthn.WebAuthnAuth mockAuth;
    bytes mockSignatureData;

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        BaseTest.setUp();

        validator = new ContangoTestValidator();

        // Setup ECDSA owners
        (address _owner1, uint256 _owner1Pk) = makeAddrAndKey("owner1");
        (address _owner2, uint256 _owner2Pk) = makeAddrAndKey("owner2");
        ecdsaOwnersMap.set(address(this), _owner1, _owner1Pk);
        ecdsaOwnersMap.set(address(this), _owner2, _owner2Pk);

        // Setup WebAuthn credentials
        _webAuthnCredentials.push(
            ContangoValidator.WebAuthnCredential({
                pubKeyX: 66_296_829_923_831_658_891_499_717_579_803_548_012_279_830_557_731_564_719_736_971_029_660_387_468_805,
                pubKeyY: 46_098_569_798_045_992_993_621_049_610_647_226_011_837_333_919_273_603_402_527_314_962_291_506_652_186,
                requireUV: false
            })
        );

        _webAuthnCredentials.push(
            ContangoValidator.WebAuthnCredential({
                pubKeyX: 77_427_310_596_034_628_445_756_159_459_159_056_108_500_819_865_614_675_054_701_790_516_611_205_123_311,
                pubKeyY: 20_591_151_874_462_689_689_754_215_152_304_668_244_192_265_896_034_279_288_204_806_249_532_173_935_644,
                requireUV: true
            })
        );

        // Pre-compute WebAuthn credential IDs
        for (uint256 i = 0; i < _webAuthnCredentials.length; i++) {
            bytes32 credentialId =
                validator.generateCredentialId(address(this), _webAuthnCredentials[i]);
            _webAuthnCredentialIds.push(credentialId);
            webAuthnCredentialIdToCredential[credentialId] = _webAuthnCredentials[i];
        }

        // Setup WebAuthn signature data
        setupWebAuthnSignatureData();
    }

    function setupWebAuthnSignatureData() internal {
        // Use a fixed challenge for testing
        bytes memory challenge =
            abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Set up real WebAuthn authentication data
        mockAuth = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001",
            clientDataJSON: string.concat(
                "{'type':'webauthn.get','challenge':'",
                Base64Url.encode(challenge),
                "','origin':'http://localhost:8080','crossOrigin':false}"
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
                "{'type':'webauthn.get','challenge':'",
                Base64Url.encode(challenge),
                "','origin':'http://localhost:8080','crossOrigin':false}"
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 70_190_788_404_940_879_339_470_429_048_068_864_326_256_942_039_718_306_809_827_270_917_601_845_266_065,
            s: 372_310_544_955_428_259_193_186_543_685_199_264_627_091_796_694_315_697_785_543_526_117_532_572_367
        });

        sigs[1] = mockAuth2;

        // Create the signature format that includes the credential IDs
        mockSignatureData = abi.encode(_webAuthnCredentialIds, false, sigs);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                               INSTALLATION
    //////////////////////////////////////////////////////////////*/

    function test_OnInstallSetsOwnersAndCredentials() public {
        bytes memory data =
            abi.encode(_threshold, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);
        validator.onInstall(data);

        // Check ECDSA owners
        address[] memory ecdsaOwners = validator.getECDSAOwners(address(this));
        assertEq(ecdsaOwners.length, 2);

        // Check WebAuthn credentials
        ContangoValidator.WebAuthnCredential[] memory webAuthnCredentials =
            validator.getWebAuthnCredentials(address(this));
        assertEq(webAuthnCredentials.length, 2);

        // Check total credentials
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 4);

        // Check threshold
        assertEq(validator.thresholds(address(this)), _threshold);
    }

    function test_OnInstallWithMixedCredentialTypes() public {
        // Install with 1 ECDSA owner and 1 WebAuthn credential
        address[] memory singleECDSAOwner = new address[](1);
        singleECDSAOwner[0] = ecdsaOwnersMap.keys(address(this))[0];

        ContangoValidator.WebAuthnCredential[] memory singleWebAuthnCredential =
            new ContangoValidator.WebAuthnCredential[](1);
        singleWebAuthnCredential[0] = _webAuthnCredentials[0];

        bytes memory data = abi.encode(1, singleECDSAOwner, singleWebAuthnCredential);
        validator.onInstall(data);

        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount, 1);
        assertEq(webAuthnCredentialsCount, 1);
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 2);
        assertEq(validator.thresholds(address(this)), 1);
    }

    function test_OnInstallWithOnlyECDSAOwners() public {
        bytes memory data = abi.encode(
            2, ecdsaOwnersMap.keys(address(this)), new ContangoValidator.WebAuthnCredential[](0)
        );
        validator.onInstall(data);

        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount, 2);
        assertEq(webAuthnCredentialsCount, 0);
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 2);
        assertEq(validator.thresholds(address(this)), 2);
    }

    function test_OnInstallWithOnlyWebAuthnCredentials() public {
        bytes memory data = abi.encode(2, new address[](0), _webAuthnCredentials);
        validator.onInstall(data);

        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount, 0);
        assertEq(webAuthnCredentialsCount, 2);
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 2);
        assertEq(validator.thresholds(address(this)), 2);
    }

    /*//////////////////////////////////////////////////////////////
                            CONFIGURATION UPDATES
    //////////////////////////////////////////////////////////////*/

    function test_UpdateConfigAddsBothCredentialTypes() public {
        // Start with at least one credential to avoid empty configuration error
        address[] memory initialOwners = new address[](1);
        initialOwners[0] = ecdsaOwnersMap.keys(address(this))[0];

        bytes memory data =
            abi.encode(1, initialOwners, new ContangoValidator.WebAuthnCredential[](0));
        validator.onInstall(data);

        // Add both credential types
        address newECDSAOwner = address(3);
        ContangoValidator.WebAuthnCredential memory newWebAuthnCredential = ContangoValidator
            .WebAuthnCredential({ pubKeyX: 99_999, pubKeyY: 88_888, requireUV: true });

        ContangoValidator.CredentialUpdateConfig memory config = ContangoValidator
            .CredentialUpdateConfig({
            ecdsaOwnersToAdd: new address[](1),
            ecdsaOwnersToRemove: new address[](0),
            webAuthnCredentialsToAdd: new ContangoValidator.WebAuthnCredential[](1),
            webAuthnCredentialsToRemove: new bytes32[](0)
        });
        config.ecdsaOwnersToAdd[0] = newECDSAOwner;
        config.webAuthnCredentialsToAdd[0] = newWebAuthnCredential;

        validator.updateConfig(3, config);

        assertTrue(validator.isECDSAOwner(address(this), newECDSAOwner));
        assertTrue(validator.hasWebAuthnCredential(address(this), newWebAuthnCredential));
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 3);
        assertEq(validator.thresholds(address(this)), 3);
    }

    function test_UpdateConfigRemovesBothCredentialTypes() public {
        // Start with full setup
        bytes memory data =
            abi.encode(_threshold, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);
        validator.onInstall(data);

        // Remove both credential types
        address[] memory owners = ecdsaOwnersMap.keys(address(this));
        bytes32[] memory credentialIdsToRemove = new bytes32[](1);
        credentialIdsToRemove[0] =
            validator.generateCredentialId(address(this), _webAuthnCredentials[0]);

        ContangoValidator.CredentialUpdateConfig memory config = ContangoValidator
            .CredentialUpdateConfig({
            ecdsaOwnersToAdd: new address[](0),
            ecdsaOwnersToRemove: new address[](1),
            webAuthnCredentialsToAdd: new ContangoValidator.WebAuthnCredential[](0),
            webAuthnCredentialsToRemove: credentialIdsToRemove
        });
        config.ecdsaOwnersToRemove[0] = owners[0];

        validator.updateConfig(1, config);

        assertFalse(validator.isECDSAOwner(address(this), owners[0]));
        assertFalse(validator.hasWebAuthnCredential(address(this), _webAuthnCredentials[0]));
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 2);
        assertEq(validator.thresholds(address(this)), 1);
    }

    function test_UpdateConfigComplexScenario() public {
        // Start with mixed credentials
        address[] memory initialECDSAOwners = new address[](2);
        initialECDSAOwners[0] = ecdsaOwnersMap.keys(address(this))[0];
        initialECDSAOwners[1] = ecdsaOwnersMap.keys(address(this))[1];

        ContangoValidator.WebAuthnCredential[] memory initialWebAuthnCredentials =
            new ContangoValidator.WebAuthnCredential[](1);
        initialWebAuthnCredentials[0] = _webAuthnCredentials[0];

        bytes memory data = abi.encode(2, initialECDSAOwners, initialWebAuthnCredentials);
        validator.onInstall(data);

        // Complex update: add 1 ECDSA owner, remove 1 ECDSA owner, add 1 WebAuthn credential,
        // remove 1 WebAuthn credential
        address newECDSAOwner = address(3);
        address[] memory ecdsaOwnersToAdd = new address[](1);
        ecdsaOwnersToAdd[0] = newECDSAOwner;

        address[] memory ecdsaOwnersToRemove = new address[](1);
        ecdsaOwnersToRemove[0] = initialECDSAOwners[0];

        ContangoValidator.WebAuthnCredential memory newWebAuthnCredential = ContangoValidator
            .WebAuthnCredential({ pubKeyX: 99_999, pubKeyY: 88_888, requireUV: true });
        ContangoValidator.WebAuthnCredential[] memory webAuthnCredentialsToAdd =
            new ContangoValidator.WebAuthnCredential[](1);
        webAuthnCredentialsToAdd[0] = newWebAuthnCredential;

        bytes32[] memory webAuthnCredentialsToRemove = new bytes32[](1);
        webAuthnCredentialsToRemove[0] =
            validator.generateCredentialId(address(this), initialWebAuthnCredentials[0]);

        ContangoValidator.CredentialUpdateConfig memory config = ContangoValidator
            .CredentialUpdateConfig({
            ecdsaOwnersToAdd: ecdsaOwnersToAdd,
            ecdsaOwnersToRemove: ecdsaOwnersToRemove,
            webAuthnCredentialsToAdd: webAuthnCredentialsToAdd,
            webAuthnCredentialsToRemove: webAuthnCredentialsToRemove
        });

        validator.updateConfig(2, config);

        // Verify final state
        assertTrue(validator.isECDSAOwner(address(this), newECDSAOwner));
        assertFalse(validator.isECDSAOwner(address(this), initialECDSAOwners[0]));
        assertTrue(validator.hasWebAuthnCredential(address(this), newWebAuthnCredential));
        assertFalse(validator.hasWebAuthnCredential(address(this), initialWebAuthnCredentials[0]));
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 3);
    }

    /*//////////////////////////////////////////////////////////////
                            THRESHOLD MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_ThresholdAppliesToTotalCredentials() public {
        bytes memory data = abi.encode(3, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);
        validator.onInstall(data);

        // Threshold should be 3, total credentials should be 4
        assertEq(validator.thresholds(address(this)), 3);
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 4);

        // Should be able to set threshold to 4 (total credentials)
        validator.setThreshold(4);
        assertEq(validator.thresholds(address(this)), 4);

        // Should not be able to set threshold to 5 (more than total credentials)
        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidThreshold.selector, 5, 1, 4)
        );
        validator.setThreshold(5);
    }

    function test_ThresholdAdjustmentWhenCredentialsChange() public {
        bytes memory data = abi.encode(2, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);
        validator.onInstall(data);

        // Remove one credential, threshold should still be valid
        address[] memory owners = ecdsaOwnersMap.keys(address(this));
        ContangoValidator.CredentialUpdateConfig memory config = ContangoValidator
            .CredentialUpdateConfig({
            ecdsaOwnersToAdd: new address[](0),
            ecdsaOwnersToRemove: new address[](1),
            webAuthnCredentialsToAdd: new ContangoValidator.WebAuthnCredential[](0),
            webAuthnCredentialsToRemove: new bytes32[](0)
        });
        config.ecdsaOwnersToRemove[0] = owners[0];

        validator.updateConfig(2, config);

        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 3);
        assertEq(validator.thresholds(address(this)), 2);

        // Try to remove another credential without adjusting threshold - should succeed since
        // threshold (2) <= total (2)
        config.ecdsaOwnersToRemove[0] = owners[1];
        validator.updateConfig(2, config);

        (ecdsaOwnersCount, webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 2);
        assertEq(validator.thresholds(address(this)), 2);
    }

    /*//////////////////////////////////////////////////////////////
                            CREDENTIAL MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_CredentialManagementAcrossTypes() public {
        // Start with at least one credential to avoid empty configuration error
        address[] memory initialOwners = new address[](1);
        initialOwners[0] = ecdsaOwnersMap.keys(address(this))[0];

        bytes memory data =
            abi.encode(1, initialOwners, new ContangoValidator.WebAuthnCredential[](0));
        validator.onInstall(data);

        // Add WebAuthn credential
        ContangoValidator.WebAuthnCredential memory webAuthnCredential = ContangoValidator
            .WebAuthnCredential({ pubKeyX: 99_999, pubKeyY: 88_888, requireUV: true });
        validator.addWebAuthnCredential(webAuthnCredential);
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 2);

        // Remove ECDSA owner
        validator.removeECDSAOwner(initialOwners[0]);
        (ecdsaOwnersCount, webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 1);

        // Remove WebAuthn credential - should revert because it would result in 0 total credentials
        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidCredentialsCount.selector, 0, 1, 32)
        );
        validator.removeWebAuthnCredential(webAuthnCredential);
    }

    function test_CredentialExistenceChecks() public {
        bytes memory data =
            abi.encode(_threshold, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);
        validator.onInstall(data);

        address[] memory owners = ecdsaOwnersMap.keys(address(this));

        // Check ECDSA owner existence
        assertTrue(validator.isECDSAOwner(address(this), owners[0]));
        assertFalse(validator.isECDSAOwner(address(this), address(999)));

        // Check WebAuthn credential existence
        assertTrue(validator.hasWebAuthnCredential(address(this), _webAuthnCredentials[0]));
        assertTrue(validator.hasWebAuthnCredentialById(address(this), _webAuthnCredentialIds[0]));

        ContangoValidator.WebAuthnCredential memory nonExistentCredential = ContangoValidator
            .WebAuthnCredential({ pubKeyX: 99_999, pubKeyY: 88_888, requireUV: true });
        assertFalse(validator.hasWebAuthnCredential(address(this), nonExistentCredential));
    }

    /*//////////////////////////////////////////////////////////////
                            EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_MaximumCredentialsLimit() public {
        // Test with maximum allowed credentials (32)
        address[] memory maxECDSAOwners = new address[](32);
        for (uint256 i = 0; i < 32; i++) {
            maxECDSAOwners[i] = makeAddr(vm.toString(i));
        }

        bytes memory data =
            abi.encode(1, maxECDSAOwners, new ContangoValidator.WebAuthnCredential[](0));
        validator.onInstall(data);

        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 32);

        // Try to add one more - should fail
        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidCredentialsCount.selector, 33, 1, 32)
        );
        validator.addECDSAOwner(makeAddr("overflow"));
    }

    function test_EmptyConfiguration() public {
        // Empty configuration should revert because total credentials (0) < minimum (1)
        bytes memory data =
            abi.encode(1, new address[](0), new ContangoValidator.WebAuthnCredential[](0));

        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidCredentialsCount.selector, 0, 1, 32)
        );
        validator.onInstall(data);
    }

    function test_UninstallClearsAllState() public {
        bytes memory data =
            abi.encode(_threshold, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);
        validator.onInstall(data);

        // Verify initial state
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 4);
        assertEq(validator.thresholds(address(this)), _threshold);

        // Uninstall
        validator.onUninstall("");

        // Verify cleared state
        (ecdsaOwnersCount, webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 0);
        assertEq(validator.thresholds(address(this)), 0);
        assertFalse(validator.isInitialized(address(this)));
    }

    /*//////////////////////////////////////////////////////////////
                            VALIDATION (STUBS)
    //////////////////////////////////////////////////////////////*/

    function test_ValidationMethodsReturnExpectedValues() external view {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        // validateUserOp should return VALIDATION_FAILED (stub implementation)
        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1);

        // isValidSignatureWithSender should return EIP1271_FAILED (stub implementation)
        bytes32 hash = bytes32(keccak256("hash"));
        bytes memory data = "";
        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, data);
        assertNotEq(result, EIP1271_MAGIC_VALUE);

        // validateSignatureWithData should return false (stub implementation)
        // Create empty unified signature data
        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: "",
            webAuthnCredentialIds: new bytes32[](0),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](0)
        });
        bytes memory signature = abi.encode(signatureData);

        // Create empty verification context
        ContangoValidator.WebAuthVerificationContext memory webAuthnContext = ContangoValidator
            .WebAuthVerificationContext({
            threshold: 1,
            credentialData: new ContangoValidator.WebAuthnCredential[](0)
        });
        bytes memory validationContext = abi.encode(1, new address[](0), webAuthnContext);

        bool isValid = validator.validateSignatureWithData(hash, signature, validationContext);
        assertFalse(isValid);
    }
}

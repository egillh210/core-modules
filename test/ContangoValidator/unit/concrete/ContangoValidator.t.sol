// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { ContangoTestValidator } from "test/ContangoValidator/ContangoValidatorTest.sol";
import { ContangoValidator } from "src/ContangoValidator/ContangoValidator.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { IModule as IERC7579Module } from "modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { signHash, signUserOpHash } from "test/utils/Signature.sol";
import { EIP1271_MAGIC_VALUE } from "test/utils/Constants.sol";
import { LibSort } from "solady/utils/LibSort.sol";
import { EnumerableSet } from "@erc7579/enumerablemap4337/EnumerableSet4337.sol";
import { EnumerableMap } from "@erc7579/enumerablemap4337/EnumerableMap4337.sol";
import { WebAuthn } from "@webauthn-sol/WebAuthn.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";

contract ContangoValidatorTest is BaseTest {
    using LibSort for *;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;

    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    ContangoTestValidator internal validator;

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    uint256 _threshold = 2;
    EnumerableMap.AddressToUintMap ecdsaOwnersMap; // key is address, value is private key (uint256)

    // WebAuthn test data
    ContangoValidator.WebAuthnCredential[] _webAuthnCredentials;
    bytes32[] _webAuthnCredentialIds;
    mapping(bytes32 => ContangoValidator.WebAuthnCredential) public webAuthnCredentialIdToCredential;

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

        // Setup WebAuthn mock signature data
        setupWebAuthnMockSignatures();
    }

    /*//////////////////////////////////////////////////////////////////////////
                                WEBAUTHN SETUP
    //////////////////////////////////////////////////////////////////////////*/

    // Mock WebAuthn signature data for testing
    WebAuthn.WebAuthnAuth mockWebAuthnAuth1;
    WebAuthn.WebAuthnAuth mockWebAuthnAuth2;
    bytes mockWebAuthnSignatureData;

    function setupWebAuthnMockSignatures() internal {
        // Use a fixed challenge for testing
        bytes memory challenge =
            abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

        // Set up real WebAuthn authentication data for first credential
        mockWebAuthnAuth1 = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001",
            // solhint-disable quotes
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

        // Set up real WebAuthn authentication data for second credential
        mockWebAuthnAuth2 = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001",
            // solhint-disable quotes
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

        // Create WebAuthn signature data
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](2);
        sigs[0] = mockWebAuthnAuth1;
        sigs[1] = mockWebAuthnAuth2;

        // Create the signature format: abi.encode(credentialIds, signatures)
        mockWebAuthnSignatureData = abi.encode(_webAuthnCredentialIds, sigs);
    }

    function createTestUserOpHash() internal pure returns (bytes32) {
        return bytes32(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                                 INSTALL
    //////////////////////////////////////////////////////////////*/

    function test_OnInstallRevertWhen_ModuleIsInitialized() public {
        bytes memory data =
            abi.encode(_threshold, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);
        validator.onInstall(data);

        vm.expectRevert();
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_ThresholdIs0() public whenModuleIsNotInitialized {
        bytes memory data = abi.encode(0, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);

        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidThreshold.selector, 0, 1, 4)
        );
        validator.onInstall(data);
    }

    function test_OnInstallWhenThresholdIsValid() public whenModuleIsNotInitialized {
        bytes memory data =
            abi.encode(_threshold, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);
        validator.onInstall(data);

        uint256 threshold = validator.thresholds(address(this));
        assertEq(threshold, _threshold);
    }

    function test_OnInstallRevertWhen_TotalCredentialsLengthIsLessThanThreshold()
        public
        whenModuleIsNotInitialized
    {
        bytes memory data = abi.encode(5, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);

        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidThreshold.selector, 5, 1, 4)
        );
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_TotalCredentialsLengthIsMoreThanMax()
        external
        whenModuleIsNotInitialized
    {
        // Create 33 total credentials (exceeding MAX_TOTAL_CREDENTIALS)
        address[] memory _ecdsaOwners = new address[](33);
        for (uint256 i = 0; i < 33; i++) {
            _ecdsaOwners[i] = makeAddr(vm.toString(i));
        }
        bytes memory data =
            abi.encode(_threshold, _ecdsaOwners, new ContangoValidator.WebAuthnCredential[](0));

        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidCredentialsCount.selector, 33, 1, 32)
        );
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_WebAuthnCredentialsNotUnique()
        public
        whenModuleIsNotInitialized
    {
        ContangoValidator.WebAuthnCredential[] memory duplicateCredentials =
            new ContangoValidator.WebAuthnCredential[](2);
        duplicateCredentials[0] = _webAuthnCredentials[0];
        duplicateCredentials[1] = _webAuthnCredentials[0];

        bytes memory data =
            abi.encode(_threshold, ecdsaOwnersMap.keys(address(this)), duplicateCredentials);

        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoValidator.AddWebAuthnCredentialError_CredentialAlreadyExists.selector,
                address(this),
                duplicateCredentials[0]
            )
        );
        validator.onInstall(data);
    }

    function test_OnInstallWhenCredentialsAreValid() public whenModuleIsNotInitialized {
        bytes memory data =
            abi.encode(_threshold, ecdsaOwnersMap.keys(address(this)), _webAuthnCredentials);
        validator.onInstall(data);

        // Check ECDSA owners
        address[] memory ecdsaOwners = validator.getECDSAOwners(address(this));
        assertEq(ecdsaOwners.length, ecdsaOwnersMap.keys(address(this)).length);

        // Check WebAuthn credentials
        ContangoValidator.WebAuthnCredential[] memory webAuthnCredentials =
            validator.getWebAuthnCredentials(address(this));
        assertEq(webAuthnCredentials.length, _webAuthnCredentials.length);

        // Check total credentials count
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 4);
    }

    /*//////////////////////////////////////////////////////////////
                                UNINSTALL
    //////////////////////////////////////////////////////////////*/

    function test_OnUninstallShouldRemoveAllCredentials() public {
        test_OnInstallWhenCredentialsAreValid();

        validator.onUninstall("");

        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 0);
    }

    function test_OnUninstallShouldSetThresholdTo0() public {
        test_OnInstallWhenCredentialsAreValid();

        validator.onUninstall("");

        uint256 threshold = validator.thresholds(address(this));
        assertEq(threshold, 0);
    }

    /*//////////////////////////////////////////////////////////////
                               INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_IsInitializedWhenModuleIsNotInitialized() external view {
        bool isInitialized = validator.isInitialized(address(this));
        assertFalse(isInitialized);
    }

    function test_IsInitializedWhenModuleIsInitialized() public {
        test_OnInstallWhenCredentialsAreValid();

        bool isInitialized = validator.isInitialized(address(this));
        assertTrue(isInitialized);
    }

    /*//////////////////////////////////////////////////////////////
                              THRESHOLD MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_SetThresholdRevertWhen_ModuleIsNotInitialized() external {
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.setThreshold(1);
    }

    function test_SetThresholdRevertWhen_ThresholdIs0() external whenModuleIsInitialized {
        test_OnInstallWhenCredentialsAreValid();

        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidThreshold.selector, 0, 1, 4)
        );
        validator.setThreshold(0);
    }

    function test_SetThresholdRevertWhen_ThresholdIsHigherThanTotalCredentialsCount()
        external
        whenModuleIsInitialized
    {
        test_OnInstallWhenCredentialsAreValid();

        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidThreshold.selector, 10, 1, 4)
        );
        validator.setThreshold(10);
    }

    function test_SetThresholdWhenThresholdIsValid() external whenModuleIsInitialized {
        test_OnInstallWhenCredentialsAreValid();

        uint256 oldThreshold = validator.thresholds(address(this));
        uint256 newThreshold = 1;
        assertNotEq(oldThreshold, newThreshold);

        validator.setThreshold(newThreshold);

        assertEq(validator.thresholds(address(this)), newThreshold);
    }

    /*//////////////////////////////////////////////////////////////
                            ECDSA CREDENTIAL MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_AddECDSAOwnerRevertWhen_ModuleIsNotInitialized() external {
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.addECDSAOwner(address(1));
    }

    function test_AddECDSAOwnerRevertWhen_TotalCredentialsCountIsMoreThanMax()
        external
        whenModuleIsInitialized
    {
        // Install with 32 ECDSA owners
        address[] memory _ecdsaOwners = new address[](32);
        for (uint256 i = 0; i < 32; i++) {
            _ecdsaOwners[i] = makeAddr(vm.toString(i));
        }
        bytes memory data =
            abi.encode(1, _ecdsaOwners, new ContangoValidator.WebAuthnCredential[](0));
        validator.onInstall(data);

        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidCredentialsCount.selector, 33, 1, 32)
        );
        validator.addECDSAOwner(makeAddr("finalOwner"));
    }

    function test_AddECDSAOwnerRevertWhen_OwnerAlreadyExists() external whenModuleIsInitialized {
        test_OnInstallWhenCredentialsAreValid();

        address[] memory owners = ecdsaOwnersMap.keys(address(this));
        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoValidator.AddECDSAOwnerError_OwnerAlreadyExists.selector,
                address(this),
                owners[0]
            )
        );
        validator.addECDSAOwner(owners[0]);
    }

    function test_AddECDSAOwnerWhenOwnerIsValid() external whenModuleIsInitialized {
        test_OnInstallWhenCredentialsAreValid();

        address newOwner = address(3);
        validator.addECDSAOwner(newOwner);

        assertTrue(validator.isECDSAOwner(address(this), newOwner));
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount, 3);
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 5);
    }

    function test_RemoveECDSAOwnerRevertWhen_ModuleIsNotInitialized() external {
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.removeECDSAOwner(address(1));
    }

    function test_RemoveECDSAOwnerRevertWhen_OwnerDoesNotExist() external whenModuleIsInitialized {
        test_OnInstallWhenCredentialsAreValid();

        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoValidator.RemoveECDSAOwnerError_OwnerDoesNotExist.selector,
                address(this),
                address(999)
            )
        );
        validator.removeECDSAOwner(address(999));
    }

    function test_RemoveECDSAOwnerWhenOwnerExists() external whenModuleIsInitialized {
        test_OnInstallWhenCredentialsAreValid();

        address[] memory owners = ecdsaOwnersMap.keys(address(this));
        validator.removeECDSAOwner(owners[0]);

        assertFalse(validator.isECDSAOwner(address(this), owners[0]));
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount, 1);
        assertEq(webAuthnCredentialsCount, 2);
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 3);
    }

    /*//////////////////////////////////////////////////////////////
                          WEBAUTHN CREDENTIAL MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_AddWebAuthnCredentialRevertWhen_ModuleIsNotInitialized() external {
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.addWebAuthnCredential(_webAuthnCredentials[0]);
    }

    function test_AddWebAuthnCredentialRevertWhen_TotalCredentialsCountIsMoreThanMax()
        external
        whenModuleIsInitialized
    {
        // Install with 32 WebAuthn credentials
        ContangoValidator.WebAuthnCredential[] memory _credentials =
            new ContangoValidator.WebAuthnCredential[](32);
        for (uint256 i = 0; i < 32; i++) {
            _credentials[i] = ContangoValidator.WebAuthnCredential({
                pubKeyX: i + 1000,
                pubKeyY: i + 2000,
                requireUV: (i % 2 == 0)
            });
        }
        bytes memory data = abi.encode(1, new address[](0), _credentials);
        validator.onInstall(data);

        ContangoValidator.WebAuthnCredential memory newCredential = ContangoValidator
            .WebAuthnCredential({ pubKeyX: 99_999, pubKeyY: 88_888, requireUV: true });

        vm.expectRevert(
            abi.encodeWithSelector(ContangoValidator.InvalidCredentialsCount.selector, 33, 1, 32)
        );
        validator.addWebAuthnCredential(newCredential);
    }

    function test_AddWebAuthnCredentialRevertWhen_CredentialAlreadyExists()
        external
        whenModuleIsInitialized
    {
        test_OnInstallWhenCredentialsAreValid();

        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoValidator.AddWebAuthnCredentialError_CredentialAlreadyExists.selector,
                address(this),
                _webAuthnCredentials[0]
            )
        );
        validator.addWebAuthnCredential(_webAuthnCredentials[0]);
    }

    function test_AddWebAuthnCredentialWhenCredentialIsValid() external whenModuleIsInitialized {
        test_OnInstallWhenCredentialsAreValid();

        ContangoValidator.WebAuthnCredential memory newCredential = ContangoValidator
            .WebAuthnCredential({ pubKeyX: 99_999, pubKeyY: 88_888, requireUV: true });

        validator.addWebAuthnCredential(newCredential);

        bytes32 newCredentialId = validator.generateCredentialId(address(this), newCredential);

        assertTrue(validator.hasWebAuthnCredential(address(this), newCredential));
        assertTrue(validator.hasWebAuthnCredentialById(address(this), newCredentialId));
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount, 2);
        assertEq(webAuthnCredentialsCount, 3);
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 5);
    }

    function test_RemoveWebAuthnCredentialRevertWhen_ModuleIsNotInitialized() external {
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.removeWebAuthnCredential(_webAuthnCredentials[0]);
    }

    function test_RemoveWebAuthnCredentialRevertWhen_CredentialDoesNotExist()
        external
        whenModuleIsInitialized
    {
        test_OnInstallWhenCredentialsAreValid();

        ContangoValidator.WebAuthnCredential memory nonExistentCredential = ContangoValidator
            .WebAuthnCredential({ pubKeyX: 99_999, pubKeyY: 88_888, requireUV: true });

        bytes32 credentialId = validator.generateCredentialId(address(this), nonExistentCredential);

        vm.expectRevert(
            abi.encodeWithSelector(
                ContangoValidator.RemoveWebAuthnCredentialError_CredentialDoesNotExist.selector,
                address(this),
                credentialId
            )
        );
        validator.removeWebAuthnCredential(nonExistentCredential);
    }

    function test_RemoveWebAuthnCredentialWhenCredentialExists() external whenModuleIsInitialized {
        test_OnInstallWhenCredentialsAreValid();

        validator.removeWebAuthnCredential(_webAuthnCredentials[0]);

        assertFalse(validator.hasWebAuthnCredential(address(this), _webAuthnCredentials[0]));
        (uint256 ecdsaOwnersCount, uint256 webAuthnCredentialsCount) = validator.getCredentialsCount(address(this));
        assertEq(ecdsaOwnersCount, 2);
        assertEq(webAuthnCredentialsCount, 1);
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 3);
    }

    /*//////////////////////////////////////////////////////////////
                            CONFIGURATION UPDATES
    //////////////////////////////////////////////////////////////*/

    function test_UpdateConfigRevertWhen_ModuleIsNotInitialized() external {
        ContangoValidator.CredentialUpdateConfig memory config = ContangoValidator
            .CredentialUpdateConfig({
            ecdsaOwnersToAdd: new address[](0),
            ecdsaOwnersToRemove: new address[](0),
            webAuthnCredentialsToAdd: new ContangoValidator.WebAuthnCredential[](0),
            webAuthnCredentialsToRemove: new bytes32[](0)
        });

        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.updateConfig(1, config);
    }

    function test_UpdateConfigWhenAddingBothCredentialTypes() external whenModuleIsInitialized {
        test_OnInstallWhenCredentialsAreValid();

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
        assertEq(ecdsaOwnersCount, 3);
        assertEq(webAuthnCredentialsCount, 3);
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 6);
        assertEq(validator.thresholds(address(this)), 3);
    }

    function test_UpdateConfigWhenRemovingBothCredentialTypes() external whenModuleIsInitialized {
        test_OnInstallWhenCredentialsAreValid();

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
        assertEq(ecdsaOwnersCount, 1);
        assertEq(webAuthnCredentialsCount, 1);
        assertEq(ecdsaOwnersCount + webAuthnCredentialsCount, 2);
        assertEq(validator.thresholds(address(this)), 1);
    }

    /*//////////////////////////////////////////////////////////////
                                VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetECDSAOwners() external {
        test_OnInstallWhenCredentialsAreValid();

        address[] memory owners = validator.getECDSAOwners(address(this));
        address[] memory expectedOwners = ecdsaOwnersMap.keys(address(this));

        assertEq(owners.length, expectedOwners.length);

        for (uint256 i = 0; i < owners.length; i++) {
            assertTrue(ecdsaOwnersMap.contains(address(this), owners[i]));
        }
    }

    function test_GetWebAuthnCredentials() external {
        test_OnInstallWhenCredentialsAreValid();

        ContangoValidator.WebAuthnCredential[] memory credentials =
            validator.getWebAuthnCredentials(address(this));
        assertEq(credentials.length, _webAuthnCredentials.length);

        for (uint256 i = 0; i < credentials.length; i++) {
            bytes32 credentialId = validator.generateCredentialId(address(this), credentials[i]);
            ContangoValidator.WebAuthnCredential memory expectedCredential =
                webAuthnCredentialIdToCredential[credentialId];

            assertEq(credentials[i].pubKeyX, expectedCredential.pubKeyX);
            assertEq(credentials[i].pubKeyY, expectedCredential.pubKeyY);
            assertEq(credentials[i].requireUV, expectedCredential.requireUV);
        }
    }

    function test_GenerateCredentialId() external view {
        bytes32 credId1 = validator.generateCredentialId(address(this), _webAuthnCredentials[0]);
        bytes32 credId2 = validator.generateCredentialId(address(this), _webAuthnCredentials[0]);
        assertEq(credId1, credId2, "Credential ID generation should be deterministic");

        bytes32 credId3 = validator.generateCredentialId(address(1), _webAuthnCredentials[0]);
        assertTrue(
            credId1 != credId3, "Different addresses should produce different credential IDs"
        );
    }

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    function test_Name() external view {
        string memory name = validator.name();
        assertEq(name, "ContangoValidator");
    }

    function test_Version() external view {
        string memory version = validator.version();
        assertEq(version, "1.0.0");
    }

    function test_IsModuleTypeWhenTypeIDIs1() external view {
        bool isModuleType = validator.isModuleType(1);
        assertTrue(isModuleType);
    }

    function test_IsModuleTypeWhenTypeIDIs7() external view {
        bool isModuleType = validator.isModuleType(7);
        assertTrue(isModuleType);
    }

    function test_IsModuleTypeWhenTypeIDIsNot1Or7() external view {
        bool isModuleType = validator.isModuleType(2);
        assertFalse(isModuleType);
    }

    /*//////////////////////////////////////////////////////////////
                               VALIDATION (STUBS)
    //////////////////////////////////////////////////////////////*/

    function test_ValidateUserOpReturnsValidationFailed() external view {
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1); // VALIDATION_FAILED
    }

    function test_ValidateUserOpWithValidECDSASignatures() external whenModuleIsInitialized {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        // Create valid ECDSA signatures from registered owners
        address[] memory owners = ecdsaOwnersMap.keys(address(this));

        // Create unified signature data with ECDSA signatures
        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(ecdsaOwnersMap.get(address(this), owners[0]), userOpHash),
                signUserOpHash(ecdsaOwnersMap.get(address(this), owners[1]), userOpHash)
            ),
            webAuthnCredentialIds: new bytes32[](0),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](0)
        });

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 0); // VALIDATION_SUCCESS
    }

    function test_ValidateUserOpWithInvalidECDSASignatures() external whenModuleIsInitialized {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        // Create invalid ECDSA signatures from non-registered private keys
        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(uint256(999), userOpHash), // Invalid private key
                signUserOpHash(uint256(888), userOpHash) // Invalid private key
            ),
            webAuthnCredentialIds: new bytes32[](0),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](0)
        });

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1); // VALIDATION_FAILED
    }

    function test_ValidateUserOpWithValidSignaturesBelowThreshold()
        external
        whenModuleIsInitialized
    {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        // Create 2 signatures: 1 valid, 1 invalid (threshold is 2, but only 1 valid)
        address[] memory owners = ecdsaOwnersMap.keys(address(this));

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(ecdsaOwnersMap.get(address(this), owners[0]), userOpHash), // Valid
                    // signature
                signUserOpHash(uint256(999), userOpHash) // Invalid signature
            ),
            webAuthnCredentialIds: new bytes32[](0),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](0)
        });

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1); // VALIDATION_FAILED
    }

    function test_ValidateUserOpWithSignaturesFromNonRegisteredOwners()
        external
        whenModuleIsInitialized
    {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        // Create signatures from non-registered private keys (but valid signatures)
        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(uint256(123), userOpHash), // Non-registered private key
                signUserOpHash(uint256(456), userOpHash) // Non-registered private key
            ),
            webAuthnCredentialIds: new bytes32[](0),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](0)
        });

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1); // VALIDATION_FAILED
    }

    function test_IsValidSignatureWithSenderWithValidECDSASignatures()
        external
        whenModuleIsInitialized
    {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        bytes32 hash = bytes32(keccak256("hash"));
        address[] memory owners = ecdsaOwnersMap.keys(address(this));

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(ecdsaOwnersMap.get(address(this), owners[0]), hash),
                signUserOpHash(ecdsaOwnersMap.get(address(this), owners[1]), hash)
            ),
            webAuthnCredentialIds: new bytes32[](0),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](0)
        });

        bytes memory data = abi.encode(signatureData);

        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, data);
        assertEq(result, EIP1271_MAGIC_VALUE);
    }

    function test_IsValidSignatureWithSenderWithInvalidSignatures()
        external
        whenModuleIsInitialized
    {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        bytes32 hash = bytes32(keccak256("hash"));

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(uint256(999), hash), // Invalid private key
                signUserOpHash(uint256(888), hash) // Invalid private key
            ),
            webAuthnCredentialIds: new bytes32[](0),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](0)
        });

        bytes memory data = abi.encode(signatureData);

        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, data);
        assertNotEq(result, EIP1271_MAGIC_VALUE);
    }

    function test_IsValidSignatureWithSenderReturnsFailed() external view {
        bytes32 hash = bytes32(keccak256("hash"));
        bytes memory data = "";

        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, data);
        assertNotEq(result, EIP1271_MAGIC_VALUE);
    }

    /*//////////////////////////////////////////////////////////////
                            WEBAUTHN SIGNATURE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_ValidateUserOpWithValidWebAuthnSignatures() external whenModuleIsInitialized {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = createTestUserOpHash();

        // Create WebAuthn signature data
        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: "",
            webAuthnCredentialIds: _webAuthnCredentialIds,
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](0)
        });

        // Decode the mock WebAuthn signature data and use it
        (bytes32[] memory credIds, WebAuthn.WebAuthnAuth[] memory sigs) =
            abi.decode(mockWebAuthnSignatureData, (bytes32[], WebAuthn.WebAuthnAuth[]));

        signatureData.webAuthnCredentialIds = credIds;
        signatureData.webAuthnSignatureData = sigs;

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 0); // VALIDATION_SUCCESS
    }

    function test_ValidateUserOpWithInvalidWebAuthnSignatures() external whenModuleIsInitialized {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = createTestUserOpHash();

        // Create invalid WebAuthn signature data with wrong challenge
        WebAuthn.WebAuthnAuth[] memory invalidSigs = new WebAuthn.WebAuthnAuth[](2);

        // Use wrong challenge in clientDataJSON
        bytes memory wrongChallenge =
            abi.encode(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

        invalidSigs[0] = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001",
            clientDataJSON: string.concat(
                "{'type':'webauthn.get','challenge':'",
                Base64Url.encode(wrongChallenge),
                "','origin':'http://localhost:8080','crossOrigin':false}"
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 23_510_924_181_331_275_540_501_876_269_042_668_160_690_304_423_490_805_737_085_519_687_669_896_593_880,
            s: 36_590_747_517_247_563_381_084_733_394_442_750_806_324_326_036_343_798_276_847_517_765_557_371_045_088
        });

        invalidSigs[1] = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001",
            clientDataJSON: string.concat(
                "{'type':'webauthn.get','challenge':'",
                Base64Url.encode(wrongChallenge),
                "','origin':'http://localhost:8080','crossOrigin':false}"
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 70_190_788_404_940_879_339_470_429_048_068_864_326_256_942_039_718_306_809_827_270_917_601_845_266_065,
            s: 372_310_544_955_428_259_193_186_543_685_199_264_627_091_796_694_315_697_785_543_526_117_532_572_367
        });

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: "",
            webAuthnCredentialIds: _webAuthnCredentialIds,
            webAuthnSignatureData: invalidSigs
        });

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1); // VALIDATION_FAILED
    }

    function test_ValidateUserOpWithWebAuthnSignaturesBelowThreshold()
        external
        whenModuleIsInitialized
    {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = createTestUserOpHash();

        // Create only 1 valid WebAuthn signature (threshold is 2)
        WebAuthn.WebAuthnAuth[] memory sigs = new WebAuthn.WebAuthnAuth[](1);
        sigs[0] = mockWebAuthnAuth1;

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: "",
            webAuthnCredentialIds: new bytes32[](1),
            webAuthnSignatureData: sigs
        });

        // Use only the first credential ID
        signatureData.webAuthnCredentialIds[0] = _webAuthnCredentialIds[0];

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1); // VALIDATION_FAILED
    }

    function test_IsValidSignatureWithSenderWithValidWebAuthnSignatures()
        external
        whenModuleIsInitialized
    {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        bytes32 hash = createTestUserOpHash();

        // Decode the mock WebAuthn signature data and use it
        (bytes32[] memory credIds, WebAuthn.WebAuthnAuth[] memory sigs) =
            abi.decode(mockWebAuthnSignatureData, (bytes32[], WebAuthn.WebAuthnAuth[]));

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: "",
            webAuthnCredentialIds: credIds,
            webAuthnSignatureData: sigs
        });

        bytes memory data = abi.encode(signatureData);

        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, data);
        assertEq(result, EIP1271_MAGIC_VALUE);
    }

    function test_IsValidSignatureWithSenderWithInvalidWebAuthnSignatures()
        external
        whenModuleIsInitialized
    {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        bytes32 hash = createTestUserOpHash();

        // Create invalid WebAuthn signature data
        WebAuthn.WebAuthnAuth[] memory invalidSigs = new WebAuthn.WebAuthnAuth[](2);

        // Use wrong challenge
        bytes memory wrongChallenge =
            abi.encode(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

        invalidSigs[0] = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001",
            clientDataJSON: string.concat(
                "{'type':'webauthn.get','challenge':'",
                Base64Url.encode(wrongChallenge),
                "','origin':'http://localhost:8080','crossOrigin':false}"
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 23_510_924_181_331_275_540_501_876_269_042_668_160_690_304_423_490_805_737_085_519_687_669_896_593_880,
            s: 36_590_747_517_247_563_381_084_733_394_442_750_806_324_326_036_343_798_276_847_517_765_557_371_045_088
        });

        invalidSigs[1] = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001",
            clientDataJSON: string.concat(
                "{'type':'webauthn.get','challenge':'",
                Base64Url.encode(wrongChallenge),
                "','origin':'http://localhost:8080','crossOrigin':false}"
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 70_190_788_404_940_879_339_470_429_048_068_864_326_256_942_039_718_306_809_827_270_917_601_845_266_065,
            s: 372_310_544_955_428_259_193_186_543_685_199_264_627_091_796_694_315_697_785_543_526_117_532_572_367
        });

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: "",
            webAuthnCredentialIds: _webAuthnCredentialIds,
            webAuthnSignatureData: invalidSigs
        });

        bytes memory data = abi.encode(signatureData);

        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, data);
        assertNotEq(result, EIP1271_MAGIC_VALUE);
    }

    /*//////////////////////////////////////////////////////////////
                        MIXED ECDSA + WEBAUTHN SIGNATURE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_ValidateUserOpWithMixedValidSignatures() external whenModuleIsInitialized {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = createTestUserOpHash();

        // Create 1 ECDSA signature + 1 WebAuthn signature (threshold is 2)
        // But we need to provide 2 ECDSA signatures to satisfy CheckSignatures.recoverNSignatures
        // The second ECDSA signature will be invalid (from non-registered owner)
        address[] memory owners = ecdsaOwnersMap.keys(address(this));

        // Decode the mock WebAuthn signature data and use it
        (bytes32[] memory credIds, WebAuthn.WebAuthnAuth[] memory sigs) =
            abi.decode(mockWebAuthnSignatureData, (bytes32[], WebAuthn.WebAuthnAuth[]));

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(ecdsaOwnersMap.get(address(this), owners[0]), userOpHash), // Valid ECDSA
                signUserOpHash(uint256(999), userOpHash) // Invalid ECDSA (to satisfy
                    // recoverNSignatures)
            ),
            webAuthnCredentialIds: new bytes32[](1),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](1)
        });

        // Use only the first WebAuthn credential and signature
        signatureData.webAuthnCredentialIds[0] = credIds[0];
        signatureData.webAuthnSignatureData[0] = sigs[0];

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 0); // VALIDATION_SUCCESS
    }

    function test_ValidateUserOpWithMixedSignaturesBelowThreshold()
        external
        whenModuleIsInitialized
    {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = createTestUserOpHash();

        // Create 1 valid ECDSA signature + 1 invalid ECDSA signature (threshold is 2, but only 1
        // valid)
        address[] memory owners = ecdsaOwnersMap.keys(address(this));

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(ecdsaOwnersMap.get(address(this), owners[0]), userOpHash), // Valid ECDSA
                signUserOpHash(uint256(999), userOpHash) // Invalid ECDSA (to satisfy
                    // recoverNSignatures)
            ),
            webAuthnCredentialIds: new bytes32[](0),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](0)
        });

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1); // VALIDATION_FAILED
    }

    function test_ValidateUserOpWithMixedSignaturesOneInvalid() external whenModuleIsInitialized {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = createTestUserOpHash();

        // Create 1 valid ECDSA signature + 1 invalid ECDSA signature + 1 invalid WebAuthn signature
        address[] memory owners = ecdsaOwnersMap.keys(address(this));

        // Create invalid WebAuthn signature with wrong challenge
        bytes memory wrongChallenge =
            abi.encode(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

        WebAuthn.WebAuthnAuth memory invalidWebAuthnSig = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001",
            clientDataJSON: string.concat(
                "{'type':'webauthn.get','challenge':'",
                Base64Url.encode(wrongChallenge),
                "','origin':'http://localhost:8080','crossOrigin':false}"
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 23_510_924_181_331_275_540_501_876_269_042_668_160_690_304_423_490_805_737_085_519_687_669_896_593_880,
            s: 36_590_747_517_247_563_381_084_733_394_442_750_806_324_326_036_343_798_276_847_517_765_557_371_045_088
        });

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(ecdsaOwnersMap.get(address(this), owners[0]), userOpHash), // Valid ECDSA
                signUserOpHash(uint256(999), userOpHash) // Invalid ECDSA (to satisfy
                    // recoverNSignatures)
            ),
            webAuthnCredentialIds: new bytes32[](1),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](1)
        });

        // Use the first WebAuthn credential but with invalid signature
        signatureData.webAuthnCredentialIds[0] = _webAuthnCredentialIds[0];
        signatureData.webAuthnSignatureData[0] = invalidWebAuthnSig;

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1); // VALIDATION_FAILED
    }

    function test_ValidateUserOpWithMixedSignaturesBothInvalid() external whenModuleIsInitialized {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = createTestUserOpHash();

        // Create 2 invalid ECDSA signatures + 1 invalid WebAuthn signature
        bytes memory wrongChallenge =
            abi.encode(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

        WebAuthn.WebAuthnAuth memory invalidWebAuthnSig = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001",
            clientDataJSON: string.concat(
                "{'type':'webauthn.get','challenge':'",
                Base64Url.encode(wrongChallenge),
                "','origin':'http://localhost:8080','crossOrigin':false}"
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 23_510_924_181_331_275_540_501_876_269_042_668_160_690_304_423_490_805_737_085_519_687_669_896_593_880,
            s: 36_590_747_517_247_563_381_084_733_394_442_750_806_324_326_036_343_798_276_847_517_765_557_371_045_088
        });

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(uint256(999), userOpHash), // Invalid private key
                signUserOpHash(uint256(888), userOpHash) // Invalid private key
            ),
            webAuthnCredentialIds: new bytes32[](1),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](1)
        });

        // Use the first WebAuthn credential but with invalid signature
        signatureData.webAuthnCredentialIds[0] = _webAuthnCredentialIds[0];
        signatureData.webAuthnSignatureData[0] = invalidWebAuthnSig;

        userOp.signature = abi.encode(signatureData);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1); // VALIDATION_FAILED
    }

    function test_IsValidSignatureWithSenderWithMixedValidSignatures()
        external
        whenModuleIsInitialized
    {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        bytes32 hash = createTestUserOpHash();
        address[] memory owners = ecdsaOwnersMap.keys(address(this));

        // Decode the mock WebAuthn signature data and use it
        (bytes32[] memory credIds, WebAuthn.WebAuthnAuth[] memory sigs) =
            abi.decode(mockWebAuthnSignatureData, (bytes32[], WebAuthn.WebAuthnAuth[]));

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signUserOpHash(ecdsaOwnersMap.get(address(this), owners[0]), hash), // Valid ECDSA
                signUserOpHash(uint256(999), hash) // Invalid ECDSA (to satisfy recoverNSignatures)
            ),
            webAuthnCredentialIds: new bytes32[](1),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](1)
        });

        // Use only the first WebAuthn credential and signature
        signatureData.webAuthnCredentialIds[0] = credIds[0];
        signatureData.webAuthnSignatureData[0] = sigs[0];

        bytes memory data = abi.encode(signatureData);

        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, data);
        assertEq(result, EIP1271_MAGIC_VALUE);
    }

    function test_IsValidSignatureWithSenderWithMixedSignaturesBelowThreshold()
        external
        whenModuleIsInitialized
    {
        // Install the module first
        test_OnInstallWhenCredentialsAreValid();

        bytes32 hash = createTestUserOpHash();
        address[] memory owners = ecdsaOwnersMap.keys(address(this));

        ContangoValidator.UnifiedSignatureData memory signatureData = ContangoValidator
            .UnifiedSignatureData({
            ecdsaSignatureData: abi.encodePacked(
                signHash(ecdsaOwnersMap.get(address(this), owners[0]), hash), // Valid ECDSA
                signHash(uint256(999), hash) // Invalid ECDSA (to satisfy recoverNSignatures)
            ),
            webAuthnCredentialIds: new bytes32[](0),
            webAuthnSignatureData: new WebAuthn.WebAuthnAuth[](0)
        });

        bytes memory data = abi.encode(signatureData);

        bytes4 result = validator.isValidSignatureWithSender(address(this), hash, data);
        assertNotEq(result, EIP1271_MAGIC_VALUE);
    }

    function test_ValidateSignatureWithDataReturnsFalse() external view {
        bytes32 hash = bytes32(keccak256("hash"));

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
        bytes memory data = abi.encode(1, new address[](0), webAuthnContext);

        bool isValid = validator.validateSignatureWithData(hash, signature, data);
        assertFalse(isValid);
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
}

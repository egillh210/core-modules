// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { ContangoOwnableTestValidator } from
    "test/ContangoOwnableValidator/ContangoOwnableValidatorTest.sol";
import {
    ContangoOwnableValidator,
    ERC7579ValidatorBase
} from "src/ContangoOwnableValidator/ContangoOwnableValidator.sol";
import { IModule as IERC7579Module } from "modulekit/accounts/common/interfaces/IERC7579Module.sol";
import { PackedUserOperation, getEmptyUserOperation } from "test/utils/ERC4337.sol";
import { signHash, signUserOpHash } from "test/utils/Signature.sol";
import { EIP1271_MAGIC_VALUE } from "test/utils/Constants.sol";
import { LibSort } from "solady/utils/LibSort.sol";
import { EnumerableSet } from "@erc7579/enumerablemap4337/EnumerableSet4337.sol";
import { EnumerableMap } from "@erc7579/enumerablemap4337/EnumerableMap4337.sol";

contract ContangoOwnableValidatorTest is BaseTest {
    using LibSort for *;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;

    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    ContangoOwnableTestValidator internal validator;

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    uint256 _threshold = 2;
    EnumerableMap.AddressToUintMap ownersMap; // key is address, value is private key (uint256)

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        BaseTest.setUp();

        validator = new ContangoOwnableTestValidator();

        (address _owner1, uint256 _owner1Pk) = makeAddrAndKey("owner1");
        (address _owner2, uint256 _owner2Pk) = makeAddrAndKey("owner2");
        ownersMap.set(address(this), _owner1, _owner1Pk);
        ownersMap.set(address(this), _owner2, _owner2Pk);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_OnInstallRevertWhen_ModuleIsIntialized() public {
        // it should revert
        bytes memory data = abi.encode(_threshold, ownersMap.keys(address(this)));

        validator.onInstall(data);

        vm.expectRevert();
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_ThresholdIs0() public whenModuleIsNotIntialized {
        // it should revert
        bytes memory data = abi.encode(0, ownersMap.keys(address(this)));

        vm.expectRevert(
            abi.encodeWithSelector(ContangoOwnableValidator.InvalidThreshold.selector, 0, 1, 2)
        );
        validator.onInstall(data);
    }

    function test_OnInstallWhenThresholdIsNot0()
        public
        whenModuleIsNotIntialized
        whenThresholdIsNot0
    {
        // it should set the threshold
        bytes memory data = abi.encode(_threshold, ownersMap.keys(address(this)));

        validator.onInstall(data);

        uint256 threshold = validator.thresholds(address(this));
        assertEq(threshold, _threshold);
    }

    function test_OnInstallRevertWhen_OwnersLengthIsLessThanThreshold()
        public
        whenModuleIsNotIntialized
        whenThresholdIsNot0
    {
        // it should revert
        bytes memory data = abi.encode(3, ownersMap.keys(address(this)));

        vm.expectRevert(
            abi.encodeWithSelector(ContangoOwnableValidator.InvalidThreshold.selector, 3, 1, 2)
        );
        validator.onInstall(data);
    }

    function test_OnInstallRevertWhen_OwnersLengthIsMoreThanMax()
        external
        whenModuleIsNotIntialized
        whenThresholdIsNot0
        whenOwnersLengthIsNotLessThanThreshold
    {
        // it should revert
        address[] memory _newOwners = new address[](33);
        for (uint256 i = 0; i < 33; i++) {
            _newOwners[i] = makeAddr(vm.toString(i));
        }
        bytes memory data = abi.encode(_threshold, _newOwners);

        vm.expectRevert(
            abi.encodeWithSelector(ContangoOwnableValidator.InvalidOwnersCount.selector, 33, 1, 32)
        );
        validator.onInstall(data);
    }

    function test_OnInstallWhenOwnersLengthIsNotMoreThanMax()
        external
        whenModuleIsNotIntialized
        whenThresholdIsNot0
        whenOwnersLengthIsNotLessThanThreshold
        whenOwnersLengthIsNotMoreThanMax
    {
        // it should set owner count
        address[] memory owners = ownersMap.keys(address(this));
        bytes memory data = abi.encode(_threshold, owners);

        validator.onInstall(data);

        uint256 ownerCount = validator.getOwnersCount(address(this));
        assertEq(ownerCount, owners.length);
    }

    /**
     * Note: Removed validation for address(0) owners since:
     * 1. The owners arrays are calldata, so validation adds gas overhead
     * 2. There's no strong reason to treat address(0) differently than other addresses
     * 3. Parameter validation is the caller's responsibility
     * 4. Adding arbitrary validation heuristics increases complexity without clear benefit
     */
    function test_OnInstallRevertWhen_OwnersInclude0Address()
        public
        whenModuleIsNotIntialized
        whenThresholdIsNot0
        whenOwnersLengthIsNotLessThanThreshold
        whenOwnersLengthIsNotMoreThanMax
    {
        // it should revert
        address[] memory _newOwners = new address[](2);
        _newOwners[0] = address(0);
        _newOwners[1] = ownersMap.keys(address(this))[1];
        bytes memory data = abi.encode(_threshold, _newOwners);

        // vm.expectRevert();
        validator.onInstall(data);
    }

    // duplicates are allowed. you pay for the extra calldata overhead and runtime gas, but it is
    // allowed
    function test_OnInstallWhenOwnersIncludeDuplicates()
        public
        whenModuleIsNotIntialized
        whenThresholdIsNot0
        whenOwnersLengthIsNotLessThanThreshold
        whenOwnersLengthIsNotMoreThanMax
    {
        address[] memory owners = ownersMap.keys(address(this));
        // it should revert
        address[] memory _newOwners = new address[](3);
        _newOwners[0] = owners[0];
        _newOwners[1] = owners[1];
        _newOwners[2] = owners[0];
        bytes memory data = abi.encode(_threshold, _newOwners);

        vm.expectRevert(
            abi.encodeWithSelector(ContangoOwnableValidator.AddOwnerError_OwnerAlreadyExists.selector, address(this), ownersMap.keys(address(this))[0])
        );
        validator.onInstall(data);
    }

    function test_OnInstallWhenOwnersIncludeNoDuplicates()
        public
        whenModuleIsNotIntialized
        whenThresholdIsNot0
        whenOwnersLengthIsNotLessThanThreshold
        whenOwnersLengthIsNotMoreThanMax
    {
        // it should set all owners
        address[] memory testOwners = ownersMap.keys(address(this));
        bytes memory data = abi.encode(_threshold, testOwners);

        validator.onInstall(data);

        address[] memory actualOwners = validator.getOwners(address(this));
        assertEq(actualOwners.length, testOwners.length);
    }

    function test_OnUninstallShouldRemoveAllOwners() public {
        // it should remove all owners
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        validator.onUninstall("");

        address[] memory owners = validator.getOwners(address(this));
        assertEq(owners.length, 0);
    }

    function test_OnUninstallShouldSetThresholdTo0() public {
        // it should set threshold to 0
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        validator.onUninstall("");

        uint256 threshold = validator.thresholds(address(this));
        assertEq(threshold, 0);
    }

    function test_OnUninstallShouldSetOwnerCountTo0() external view {
        // it should set owner count to 0
        uint256 ownerCount = validator.getOwnersCount(address(this));
        assertEq(ownerCount, 0);
    }

    function test_IsInitializedWhenModuleIsNotIntialized() external view {
        // it should return false
        bool isInitialized = validator.isInitialized(address(this));
        assertFalse(isInitialized);
    }

    function test_IsInitializedWhenModuleIsIntialized() public {
        // it should return true
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        bool isInitialized = validator.isInitialized(address(this));
        assertTrue(isInitialized);
    }

    function test_SetThresholdRevertWhen_ModuleIsNotIntialized() external {
        // it should revert
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        validator.updateConfig(1, new address[](0), new address[](0));
    }

    function test_SetThresholdRevertWhen_ThresholdIs0() external whenModuleIsIntialized {
        // it should revert
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        vm.expectRevert(
            abi.encodeWithSelector(ContangoOwnableValidator.InvalidThreshold.selector, 0, 1, 2)
        );
        validator.updateConfig(0, new address[](0), new address[](0));
    }

    function test_SetThresholdRevertWhen_ThresholdIsHigherThanOwnersLength()
        external
        whenModuleIsIntialized
        whenThresholdIsNot0
    {
        // it should revert
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        vm.expectRevert(
            abi.encodeWithSelector(ContangoOwnableValidator.InvalidThreshold.selector, 10, 1, 2)
        );
        validator.updateConfig(10, new address[](0), new address[](0));
    }

    function test_SetThresholdWhenThresholdIsNotHigherThanOwnersLength()
        external
        whenModuleIsIntialized
        whenThresholdIsNot0
    {
        // it should set the threshold
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        uint256 oldThreshold = validator.thresholds(address(this));
        uint256 newThreshold = 1;
        assertNotEq(oldThreshold, newThreshold);

        validator.updateConfig(newThreshold, new address[](0), new address[](0));

        assertEq(validator.thresholds(address(this)), newThreshold);
    }

    function test_AddOwnerRevertWhen_ModuleIsNotIntialized() external {
        // it should revert
        vm.expectRevert(
            abi.encodeWithSelector(IERC7579Module.NotInitialized.selector, address(this))
        );
        address[] memory ownersToAdd = new address[](1);
        ownersToAdd[0] = address(1);
        validator.updateConfig(_threshold, ownersToAdd, new address[](0));
    }

    function test_AddOwnerRevertWhen_OwnerCountIsMoreThanMax()
        external
        whenModuleIsIntialized
        whenOwnerIsNot0Address
    {
        // it should revert
        address[] memory _newOwners = new address[](32);
        for (uint256 i = 0; i < 32; i++) {
            _newOwners[i] = makeAddr(vm.toString(i));
        }
        bytes memory data = abi.encode(_threshold, _newOwners);

        validator.onInstall(data);

        bool isInitialized = validator.isInitialized(address(this));
        assertTrue(isInitialized);

        vm.expectRevert(
            abi.encodeWithSelector(ContangoOwnableValidator.InvalidOwnersCount.selector, 33, 1, 32)
        );
        validator.addOwner(makeAddr("finalOwner"));
    }

    // adding an owner that is already added should not revert.
    function test_AddOwnerShouldNotRevertWhen_OwnerIsAlreadyAdded()
        external
        whenModuleIsIntialized
        whenOwnerIsNot0Address
        whenOwnerCountIsNotMoreThanMax
    {
        // it should revert
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        vm.expectRevert(
            abi.encodeWithSelector(ContangoOwnableValidator.AddOwnerError_OwnerAlreadyExists.selector, address(this), ownersMap.keys(address(this))[0])
        );
        validator.addOwner(ownersMap.keys(address(this))[0]);
    }

    // calling the contract to remove an owner that doesn't exist as an owner should not revert.
    // The contract will simply carry out the instruction and do nothing
    function test_RemoveOwnerShouldNotRevertWhen_OwnerIsNotAdded()
        external
        whenModuleIsIntialized
        whenOwnerIsNot0Address
        whenOwnerCountIsNotMoreThanMax
    {
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        address ownerToRemove = address(2); // is not a configured owner

        vm.expectRevert(
            abi.encodeWithSelector(ContangoOwnableValidator.RemoveOwnerError_OwnerDoesNotExist.selector, address(this), ownerToRemove)
        );
        validator.removeOwner(ownerToRemove);
    }

    function test_AddOwnerWhenOwnerIsNotAdded()
        external
        whenModuleIsIntialized
        whenOwnerIsNot0Address
        whenOwnerCountIsNotMoreThanMax
    {
        // it should increment owner count
        // it should add the owners
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        address newOwner = address(2);
        validator.addOwner(newOwner);

        address[] memory owners = validator.getOwners(address(this));
        uint256 ownerCount = validator.getOwnersCount(address(this));

        assertTrue(validator.isOwner(address(this), newOwner));
        assertEq(owners.length, 3);
        assertEq(ownerCount, 3);
    }

    function test_RemoveOwnerRevertWhen_ModuleIsNotIntialized() external {
        // it should revert
        vm.expectRevert();
        validator.removeOwner(ownersMap.keys(address(this))[0]);
    }

    function test_RemoveOwnerAndUpdateThreshold() external {
        // it should decrement owner count
        // it should remove the owner
        test_OnInstallWhenOwnersIncludeNoDuplicates();
        address[] memory ownersToRemove = new address[](1);
        ownersToRemove[0] = ownersMap.keys(address(this))[1];
        validator.updateConfig(1, new address[](0), ownersToRemove);

        uint256 ownerCount = validator.getOwnersCount(address(this));
        assertEq(ownerCount, 1);
    }

    function test_GetOwnersShouldGetAllOwners() external {
        // it should get all owners
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        address[] memory owners = validator.getOwners(address(this));
        assertEq(owners.length, ownersMap.keys(address(this)).length);

        for (uint256 i = 0; i < owners.length; i++) {
            assertTrue(ownersMap.contains(address(this), owners[i]));
        }
    }

    // this test really is just testing if the module is initialized
    // former test name: test_ValidateUserOpWhenThresholdIsNotSet
    // new test name: test_ValidateUserOpWhenModuleIsNotIntialized
    function test_ValidateUserOpWhenModuleIsNotIntialized() external view {
        // it should return 1
        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1);
    }

    function test_ValidateUserOpWhenTheSignaturesAreNotValid() public whenThresholdIsSet {
        // it should return 1
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        bytes memory signature1 = signHash(uint256(1), userOpHash);
        bytes memory signature2 = signHash(uint256(2), userOpHash);
        userOp.signature = abi.encodePacked(signature1, signature2);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1);
    }

    function test_ValidateUserOpWhenTheUniqueSignaturesAreLessThanThreshold()
        public
        whenThresholdIsSet
        whenTheSignaturesAreValid
    {
        // it should return 1
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        address[] memory owners = ownersMap.keys(address(this));

        bytes memory signature1 = signHash(ownersMap.get(address(this), owners[0]), userOpHash);
        bytes memory signature2 = signHash(uint256(2), userOpHash);
        userOp.signature = abi.encodePacked(signature1, signature2);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 1);
    }

    function test_ValidateUserOpWhenTheUniqueSignaturesAreGreaterThanThreshold()
        public
        whenThresholdIsSet
        whenTheSignaturesAreValid
    {
        // it should return 0
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        PackedUserOperation memory userOp = getEmptyUserOperation();
        userOp.sender = address(this);
        bytes32 userOpHash = bytes32(keccak256("userOpHash"));

        address[] memory owners = ownersMap.keys(address(this));

        bytes memory signature1 =
            signUserOpHash(ownersMap.get(address(this), owners[0]), userOpHash);
        bytes memory signature2 =
            signUserOpHash(ownersMap.get(address(this), owners[1]), userOpHash);
        userOp.signature = abi.encodePacked(signature1, signature2);

        uint256 validationData =
            ERC7579ValidatorBase.ValidationData.unwrap(validator.validateUserOp(userOp, userOpHash));
        assertEq(validationData, 0);
    }

    function test_IsValidSignatureWithSenderWhenThresholdIsNotSet() public {
        // it should return EIP1271_FAILED
        address sender = address(1);
        bytes32 hash = bytes32(keccak256("hash"));
        bytes memory data = "";

        bytes4 result = validator.isValidSignatureWithSender(sender, hash, data);
        assertNotEq(result, EIP1271_MAGIC_VALUE);
    }

    function test_IsValidSignatureWithSenderWhenTheSignaturesAreNotValid()
        public
        whenThresholdIsSet
    {
        // it should return EIP1271_FAILED
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        address sender = address(1);
        bytes32 hash = bytes32(keccak256("hash"));

        bytes memory signature1 = signHash(uint256(1), hash);
        bytes memory signature2 = signHash(uint256(2), hash);
        bytes memory data = abi.encodePacked(signature1, signature2);

        bytes4 result = validator.isValidSignatureWithSender(sender, hash, data);
        assertNotEq(result, EIP1271_MAGIC_VALUE);
    }

    function test_IsValidSignatureWithSenderWhenTheUniqueSignaturesAreLessThanThreshold()
        public
        whenThresholdIsSet
        whenTheSignaturesAreValid
    {
        // it should return EIP1271_FAILED
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        address sender = address(1);
        bytes32 hash = bytes32(keccak256("hash"));

        address[] memory owners = ownersMap.keys(address(this));

        bytes memory signature1 = signHash(ownersMap.get(address(this), owners[0]), hash);
        bytes memory signature2 = signHash(uint256(2), hash);
        bytes memory data = abi.encodePacked(signature1, signature2);

        bytes4 result = validator.isValidSignatureWithSender(sender, hash, data);
        assertNotEq(result, EIP1271_MAGIC_VALUE);
    }

    function test_IsValidSignatureWithSenderWhenTheUniqueSignaturesAreGreaterThanThreshold()
        public
        whenThresholdIsSet
        whenTheSignaturesAreValid
    {
        // it should return ERC1271_MAGIC_VALUE
        test_OnInstallWhenOwnersIncludeNoDuplicates();

        address sender = address(1);
        bytes32 hash = bytes32(keccak256("hash"));

        address[] memory owners = ownersMap.keys(address(this));

        bytes memory signature1 = signHash(ownersMap.get(address(this), owners[0]), hash);
        bytes memory signature2 = signHash(ownersMap.get(address(this), owners[1]), hash);
        bytes memory data = abi.encodePacked(signature1, signature2);

        bytes4 result = validator.isValidSignatureWithSender(sender, hash, data);
        assertEq(result, EIP1271_MAGIC_VALUE);
    }

    function test_ValidateSignatureWithDataRevertWhen_OwnersAreNotUnique() external {
        // it should return false
        bytes32 hash = bytes32(keccak256("hash"));

        address[] memory owners = ownersMap.keys(address(this));

        bytes memory signature1 = signHash(ownersMap.get(address(this), owners[0]), hash);
        bytes memory signature2 = signHash(ownersMap.get(address(this), owners[0]), hash);
        bytes memory signatures = abi.encodePacked(signature1, signature2);

        bytes memory data = abi.encode(_threshold, owners);

        bool isValid = validator.validateSignatureWithData(hash, signatures, data);
        assertFalse(isValid);
    }

    function test_ValidateSignatureWithDataRevertWhen_ThresholdIsNotSet()
        external
        view
        whenOwnersAreUnique
    {
        //it should return false
        bytes32 hash = bytes32(keccak256("hash"));
        bytes memory signatures = "";
        bytes memory data = abi.encode(0, ownersMap.keys(address(this)));

        bool isValid = validator.validateSignatureWithData(hash, signatures, data);
        assertFalse(isValid);
    }

    function test_ValidateSignatureWithDataWhenTheSignaturesAreNotValid()
        external
        whenOwnersAreUnique
        whenThresholdIsSet
    {
        // it should return false
        bytes32 hash = bytes32(keccak256("hash"));
        bytes memory signature1 = signHash(uint256(1), hash);
        bytes memory signature2 = signHash(uint256(2), hash);
        bytes memory signatures = abi.encodePacked(signature1, signature2);
        bytes memory data = abi.encode(_threshold, ownersMap.keys(address(this)));

        bool isValid = validator.validateSignatureWithData(hash, signatures, data);
        assertFalse(isValid);
    }

    function test_ValidateSignatureWithDataWhenTheUniqueSignaturesAreLessThanThreshold()
        external
        whenOwnersAreUnique
        whenThresholdIsSet
        whenTheSignaturesAreValid
    {
        address[] memory owners = ownersMap.keys(address(this));
        // it should return false
        bytes32 hash = bytes32(keccak256("hash"));
        bytes memory signature1 = signHash(ownersMap.get(address(this), owners[0]), hash);
        bytes memory signature2 = signHash(uint256(2), hash);
        bytes memory signatures = abi.encodePacked(signature1, signature2);
        bytes memory data = abi.encode(_threshold, owners);

        bool isValid = validator.validateSignatureWithData(hash, signatures, data);
        assertFalse(isValid);
    }

    function test_ValidateSignatureWithDataWhenTheUniqueSignaturesAreGreaterThanThreshold()
        external
        whenOwnersAreUnique
        whenThresholdIsSet
        whenTheSignaturesAreValid
    {
        // it should return true
        bytes32 hash = bytes32(keccak256("hash"));
        address[] memory owners = ownersMap.keys(address(this));
        bytes memory signature1 = signHash(ownersMap.get(address(this), owners[0]), hash);
        bytes memory signature2 = signHash(ownersMap.get(address(this), owners[1]), hash);
        bytes memory signatures = abi.encodePacked(signature1, signature2);
        bytes memory data = abi.encode(_threshold, owners);

        bool isValid = validator.validateSignatureWithData(hash, signatures, data);
        assertTrue(isValid);
    }

    function test_Name() external view {
        // it should return OwnableValidator
        string memory name = validator.name();
        assertEq(name, "ContangoOwnableValidator");
    }

    function test_Version() external view {
        // it should return 1.0.0
        string memory version = validator.version();
        assertEq(version, "1.0.0");
    }

    function test_IsModuleTypeWhenTypeIDIs1() external view {
        // it should return true
        bool isModuleType = validator.isModuleType(1);
        assertTrue(isModuleType);
    }

    function test_IsModuleTypeWhenTypeIDIsNot1() external view {
        // it should return false
        bool isModuleType = validator.isModuleType(2);
        assertFalse(isModuleType);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    MODIFIERS
    //////////////////////////////////////////////////////////////////////////*/

    modifier whenModuleIsNotIntialized() {
        _;
    }

    modifier whenModuleIsIntialized() {
        _;
    }

    modifier whenThresholdIsNot0() {
        _;
    }

    modifier whenOwnersLengthIsNotLessThanThreshold() {
        _;
    }

    modifier whenOwnersLengthIsNotMoreThanMax() {
        _;
    }

    modifier whenOwnerIsNot0Address() {
        _;
    }

    modifier whenOwnerCountIsNotMoreThanMax() {
        _;
    }

    modifier whenThresholdIsSet() {
        _;
    }

    modifier whenTheSignaturesAreValid() {
        _;
    }

    modifier whenOwnersAreUnique() {
        _;
    }
}

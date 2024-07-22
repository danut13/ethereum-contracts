// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.20;
pragma abicoder v2;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {Safe} from "@safe/Safe.sol";
import {CompatibilityFallbackHandler} from "@safe/handler/CompatibilityFallbackHandler.sol";
import {SignMessageLib} from "@safe/libraries/SignMessageLib.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {MultiSend} from "@safe/libraries/MultiSend.sol";
import {Enum} from "@safe/libraries/Enum.sol";
import {TestNFT} from "./helpers/TestNFT.sol";

// Example of a Gnosis Safe which is an owner of another Gnosis Safe
// We will refer to the Gnosis Safe which is an owner as the main account
// and the Gnosis Safe which is owned as the smart account
// The smart account is the owner of a TestNFT contract
// The smart account is owned by the defined owners
contract DeploySafe is Script {
    address GNOSIS_SAFE_MASTER_COPY;
    address FALLBACK_HANDLER_MASTER_COPY;
    address PROXY_FACTORY;

    uint256 public smartAccountThreshold = 2;
    mapping(address => bytes) public signatures;

    address[] public smartAccountOwners = [
        // ANVIL's default accounts in ascending order
        0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC, // 0x3c44...
        0x70997970C51812dc3A010C7d01b50e0d17dc79C8, // 0x70...
        0x90F79bf6EB2c4f870365E785982E1f101E93b906 // 0x90...
    ];

    uint256[] private privateKeys = [
        // ANVIL's default accounts private keys
        0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a,
        0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d,
        0x7c8521182947a0b1ffdcf5e5babd128afdf80fbc5cdacbb0baed1bc56e75a6da
    ];

    function run() external {
        vm.startBroadcast();

        // Deploy the Gnosis Safe master copy contract
        Safe gnosisSafe = new Safe();
        console2.log(
            "Gnosis Safe Master Copy deployed at:",
            address(gnosisSafe)
        );
        GNOSIS_SAFE_MASTER_COPY = address(gnosisSafe);

        // Deploy the CompatibilityFallbackHandler master copy contract
        // We need this to be able to utilize EIP-1271 signatures
        CompatibilityFallbackHandler fallbackHandler = new CompatibilityFallbackHandler();
        console2.log(
            "CompatibilityFallbackHandler Master Copy deployed at:",
            address(fallbackHandler)
        );
        FALLBACK_HANDLER_MASTER_COPY = address(fallbackHandler);

        // Deploy the Proxy Factory contract
        SafeProxyFactory proxyFactory = new SafeProxyFactory();
        console2.log("Proxy Factory deployed at:", address(proxyFactory));
        PROXY_FACTORY = address(proxyFactory);

        // Smart account setup
        bytes memory setupSmartAccount = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            smartAccountOwners,
            smartAccountThreshold,
            address(0),
            "",
            FALLBACK_HANDLER_MASTER_COPY,
            address(0),
            0,
            address(0)
        );
        SafeProxy safeProxySmartAccount = proxyFactory
            .createChainSpecificProxyWithNonce(
                GNOSIS_SAFE_MASTER_COPY,
                setupSmartAccount,
                1
            );
        address payable safeSmartAccountAddress = payable(
            address(safeProxySmartAccount)
        );
        Safe safeSmartAccount = Safe(safeSmartAccountAddress);
        console2.log(
            "Safe Smart Account deployed at:",
            safeSmartAccountAddress
        );

        // Main account setup
        address[] memory mainAccountOwners = new address[](1);
        mainAccountOwners[0] = address(safeProxySmartAccount); // the smart account is the only owner of the main account
        bytes memory setupMainAccount = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            mainAccountOwners,
            1,
            address(0),
            "",
            address(0),
            address(0),
            0,
            address(0)
        );
        SafeProxy safeProxyMainAccount = proxyFactory
            .createChainSpecificProxyWithNonce(
                GNOSIS_SAFE_MASTER_COPY,
                setupMainAccount,
                1
            );
        address payable safeMainAccountAddress = payable(
            address(safeProxyMainAccount)
        );
        Safe safeMainAccount = Safe(safeMainAccountAddress);
        console2.log("Safe Main Account deployed at:", safeMainAccountAddress);

        // Deploy TestNFT contract
        TestNFT testNft = new TestNFT(safeMainAccountAddress);

        // This is the data of the transaction that we want to execute in the end
        bytes memory pauseData = abi.encodeWithSelector(
            testNft.pause.selector
        );

        // This is the transaction that will be executed by the main account
        bytes32 txHashMain = safeMainAccount.getTransactionHash(
            address(testNft),
            0,
            pauseData,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            safeMainAccount.nonce()
        );

        // We need to sign the message digested by the smart account
        bytes32 messageHashToBeSigned = CompatibilityFallbackHandler(
            safeSmartAccountAddress
        ).getMessageHash(abi.encodePacked(txHashMain));

        // Now we need to collect the signatures of the owners of the smart account
        bytes memory collectedSignatures;
        for (uint256 i = 0; i < smartAccountThreshold; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                privateKeys[i],
                messageHashToBeSigned
            );
            bytes memory signature = abi.encodePacked(r, s, v);
            collectedSignatures = abi.encodePacked(
                collectedSignatures,
                signature
            );
        }
        uint256 signatureLength = collectedSignatures.length;

        uint8 v2 = 0; // This means that the gnosis safe will interpret this as a contract signature according to EI-1271
        bytes32 r2 = bytes32(uint256(uint160(address(safeSmartAccount)))); // Address of the signer (in our case, the smart account)
        bytes32 s2 = bytes32(uint256(65)); // This is the position of the data in the signature.
        // I think if we have only one contract signature, then this is just 65 * number of signatures
        // If we have more than one, then we need to figure out where every data signature starts and ends

        bytes memory signature2 = abi.encodePacked(
            r2,
            s2,
            v2,
            signatureLength, // We have only one signature so we can already put this here
            collectedSignatures
        );

        // this is the transaction which will pause the nft contract
        bool success = safeMainAccount.execTransaction(
            address(testNft),
            0,
            pauseData,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            signature2
        );

        require(success, "Transaction failed");

        vm.stopBroadcast();
    }
}

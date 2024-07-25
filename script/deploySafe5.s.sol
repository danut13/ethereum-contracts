// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.20;
pragma abicoder v2;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {Safe} from "@safe/Safe.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {MultiSend} from "@safe/libraries/MultiSend.sol";
import {Enum} from "@safe/libraries/Enum.sol";
import {TestNFT} from "./helpers/TestNFT.sol";

contract DeploySafe is Script {
    address GNOSIS_SAFE_MASTER_COPY;
    address PROXY_FACTORY;
    address MULTISEND;

    uint256 public threshold = 2;
    mapping(address => bytes) public signatures;

    address[] public owners = [
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

        // Deploy the Proxy Factory contract
        SafeProxyFactory proxyFactory = new SafeProxyFactory();
        console2.log("Proxy Factory deployed at:", address(proxyFactory));
        PROXY_FACTORY = address(proxyFactory);

        // Deploy the MultiSend contract
        MultiSend multiSend = new MultiSend();
        console2.log("MultiSend deployed at:", address(multiSend));
        MULTISEND = address(multiSend);

        // Prepare data for Gnosis Safe setup
        bytes memory setupData = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            owners,
            threshold,
            address(0),
            "",
            address(0),
            address(0),
            0,
            address(0)
        );

        // Use createChainSpecificProxyWithNonce to deploy the proxy
        uint256 saltNonce = 1;
        SafeProxy safeProxy = proxyFactory.createChainSpecificProxyWithNonce(
            GNOSIS_SAFE_MASTER_COPY,
            setupData,
            saltNonce
        );

        address payable safeAddress = payable(address(safeProxy));
        Safe safe = Safe(safeAddress); // wrap proxy

        require(
            safe.getOwners().length == owners.length,
            "Owners not set up correctly"
        );
        require(
            safe.getThreshold() == threshold,
            "Threshold not set correctly"
        );

        // Deploy TestNFT and make safe wallet its owner
        TestNFT testNft = new TestNFT(safeAddress);

        // Get transaction hash for pausing TestNFT
        uint256 value = 0;
        bytes memory pauseData = abi.encodeWithSelector(
            testNft.pause.selector
        );

        bytes memory unpausedData = abi.encodeWithSelector(
            testNft.unpause.selector
        );

        bytes memory transactionPause = abi.encodePacked(
            Enum.Operation.Call,
            address(testNft),
            value,
            pauseData.length,
            pauseData
        );

        bytes memory transactionUnpause = abi.encodePacked(
            Enum.Operation.Call,
            address(testNft),
            value,
            unpausedData.length,
            unpausedData
        );

        bytes memory multiSendData = abi.encodeWithSelector(
            multiSend.multiSend.selector,
            abi.encodePacked(transactionPause, transactionUnpause)
        );

        uint256 nonce_ = safe.nonce(); // stack too deep

        bytes32 txHash = safe.getTransactionHash(
            address(MULTISEND),
            0,
            multiSendData,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            nonce_
        );

        console2.logBytes32(txHash);

        // Sign the transaction
        bytes memory collectedSignatures;
        for (uint256 i = 0; i < threshold; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeys[i], txHash);
            bytes memory signature = abi.encodePacked(r, s, v);
            collectedSignatures = abi.encodePacked(
                collectedSignatures,
                signature
            );
        }

        console2.logBytes(collectedSignatures);

        // Execute the transaction
        bool success = safe.execTransaction(
            address(MULTISEND),
            0,
            multiSendData,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            collectedSignatures
        );

        require(success, "Transaction failed");

        vm.stopBroadcast();
    }
}

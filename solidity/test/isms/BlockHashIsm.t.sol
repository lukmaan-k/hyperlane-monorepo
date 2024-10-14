// SPDX-License-Identifier: MIT or Apache-2.0
pragma solidity >=0.8.0;

import {Test} from "forge-std/Test.sol";
import "forge-std/Script.sol";

import {BlockHashISM} from "../../contracts/isms/blockHash/BlockHashISM.sol";
import {MockBlockHashOracle} from "../../contracts/mock/MockBlockHashOracle.sol";

contract BlockHashIsmTest is Test {
    using stdJson for string;

    BlockHashISM ism;
    MockBlockHashOracle blockHashOracle;

    uint256 blockHeight;
    uint256 logIndex;
    bytes txIndex;
    bytes blockHeaderRlp;
    bytes proof;
    bytes message;

    function setUp() public {
        blockHashOracle = new MockBlockHashOracle();
        ism = new BlockHashISM(address(blockHashOracle));

        string memory root = vm.projectRoot();
        string memory path = string.concat(
            root,
            "/../vectors/receiptProof.json"
        );
        string memory json = vm.readFile(path);
        blockHeight = json.readUint(string(abi.encodePacked(".blockHeight")));
        logIndex = json.readUint(string(abi.encodePacked(".logIndex")));
        txIndex = json.readBytes(string(abi.encodePacked(".txIndex")));
        blockHeaderRlp = json.readBytes(
            string(abi.encodePacked(".blockHeaderRlp"))
        );
        proof = json.readBytes(string(abi.encodePacked(".proof")));
        message = json.readBytes(string(abi.encodePacked(".message")));
    }

    function test_mainnetBlock() public {
        // Live test case for txHash 0xcc14210b96542918834c0c1834b7b2a694cf01b739ec25cb7e083f4073041fa4 on mainnet
        // Trusted Oracle
        bytes32 blockHash = hex"1e7767697d666d86dd7e259d205967715d0ee9b833f98f69954aaa398cc174f3";
        blockHashOracle.setBlockHash(blockHeight, blockHash);

        // Relay message with proof
        bytes memory metadata = (
            abi.encode(txIndex, proof, blockHeaderRlp, logIndex)
        );
        assertTrue(ism.verify(metadata, message));
    }
}

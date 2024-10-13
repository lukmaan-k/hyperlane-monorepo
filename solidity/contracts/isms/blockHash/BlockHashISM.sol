// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ Internal Imports ============
import {IBlockHashOracle} from "../../interfaces/IBlockHashOracle.sol";
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MerklePatriciaTrie, RLPReader} from "../../libs/MerklePatriciaTrie.sol";
import {BlockHashIsmMetadata} from "../libs/BlockHashIsmMetadata.sol";

import {console} from "forge-std/console.sol";

contract BlockHashISM is IInterchainSecurityModule, Ownable {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    IBlockHashOracle internal blockHashOracle;

    error InvalidBlockHash();

    constructor(address _blockHashOracle) {
        blockHashOracle = IBlockHashOracle(_blockHashOracle);
    }

    // ============ View Functions ============
    function verify(
        bytes calldata _metadata,
        bytes calldata _message
    ) external view returns (bool) {
        (
            bytes memory mptKey,
            bytes memory proof,
            bytes memory blockHeaderRlp,
            uint256 logIndex
        ) = abi.decode(_metadata, (bytes, bytes, bytes, uint256));

        RLPReader.RLPItem[] memory blockHeader = blockHeaderRlp
            .toRLPItem()
            .readList();
        bytes32 receiptRoot = bytes32(blockHeader[5].readBytes());
        uint256 blockHeight = blockHeader[8].readUint256();

        if (keccak256(blockHeaderRlp) != _getOracleBlockHash(blockHeight))
            revert InvalidBlockHash();

        (bool exists, bytes memory recoveredTxReceipt) = MerklePatriciaTrie.get(
            mptKey,
            proof,
            receiptRoot
        );

        bytes memory recoveredMessage = BlockHashIsmMetadata.getDispatchMessage(
            recoveredTxReceipt,
            logIndex
        );
        return exists && _isEqual(recoveredMessage, _message);
    }

    function moduleType() external pure returns (uint8) {
        return uint8(Types.BLOCK_HASH);
    }

    // ============ Admin Functions ===============
    function setBlockHashOracle(address _blockHashOracle) external onlyOwner {
        blockHashOracle = IBlockHashOracle(_blockHashOracle);
    }

    // ============ Internal Functions ============
    /**
     * @notice Get the block hash for a given block height from trusted oracle.
     * @param _height The block height.
     * @return The block hash.
     */
    function _getOracleBlockHash(
        uint256 _height
    ) internal view returns (bytes32) {
        return bytes32(blockHashOracle.blockHash(_height));
    }

    function _getMessageFromLog(
        bytes memory _log
    ) internal pure returns (bytes memory) {
        return abi.decode(_log, (bytes));
    }

    function _isEqual(
        bytes memory a,
        bytes memory b
    ) internal pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }
}

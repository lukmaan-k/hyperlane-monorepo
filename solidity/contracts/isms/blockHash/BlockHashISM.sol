// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ Internal Imports ============
import {IBlockHashOracle} from "../../interfaces/IBlockHashOracle.sol";
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MPTProof, RLPReader} from "../../libs/MPTProof.sol";

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
            bytes memory blockHeaderRlp
        ) = abi.decode(_metadata, (bytes, bytes, bytes));

        RLPReader.RLPItem[] memory blockHeader = blockHeaderRlp
            .toRlpItem()
            .toList();
        // bytes32 receiptRoot = bytes32(blockHeader[5].toBytes());
        bytes32 receiptRoot = hex"264f24611af850a076da1e34a2ac976c7e671ba226d36b6ddaefa94319bab2cb";
        uint256 blockHeight = blockHeader[8].toUint();

        if (keccak256(blockHeaderRlp) != _getOracleBlockHash(blockHeight))
            revert InvalidBlockHash();

        bytes memory recoveredMessage = MPTProof.verifyRLPProof(
            proof,
            receiptRoot,
            bytes32(mptKey)
        );

        return _isEqual(recoveredMessage, _message);
    }

    function rlpReader(bytes memory _rlp) external view {
        console.log(_rlp.length);
        RLPReader.RLPItem memory decoded = _rlp.toRlpItem();
        console.logBytes(decoded.toBytes());
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

    function _isEqual(
        bytes memory a,
        bytes memory b
    ) internal pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }
}

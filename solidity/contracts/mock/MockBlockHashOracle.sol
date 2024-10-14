// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

contract MockBlockHashOracle {
    mapping(uint256 => bytes32) public blockHashes;

    function setBlockHash(uint256 _height, bytes32 _hash) external {
        blockHashes[_height] = _hash;
    }

    function blockHash(uint256 _height) external view returns (bytes32) {
        return blockHashes[_height];
    }
}

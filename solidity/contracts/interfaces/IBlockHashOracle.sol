// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

interface IBlockHashOracle {
    function blockHash(uint256 height) external view returns (uint256 hash);
}

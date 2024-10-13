// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import {RLPReader} from "../../libs/RLPReader.sol";

import {console} from "forge-std/console.sol";

library BlockHashIsmMetadata {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    function getDispatchMessage(
        bytes memory receipt,
        uint256 logIndex
    ) internal pure returns (bytes memory) {
        return
            isLegacyReceipt(receipt)
                ? getLogByIndex(receipt, logIndex)
                : getLogByIndex(removeFirstByte(receipt), logIndex);
    }

    function getLogByIndex(
        bytes memory receipt,
        uint256 logIndex
    ) internal pure returns (bytes memory) {
        bytes memory logMessage = receipt
        .toRLPItem()
        .readList()[3]
        .readList()[logIndex]
        .readList()[2].readBytes();
        return abi.decode(logMessage, (bytes));
    }

    /*
     * @dev Hyperlane Message format is guaranteed to give receipt payload of
     * larger than 55 bytes, resulting in first byte of at least 0xf7
     * Non-legacy tx types (1, 2, 3) have their (rlp encoded) type concatenated
     * to start of receipt
     * Can safely assume if first byte is less than 0xf7, it is a legacy receipt
     * Will work until tx types are increased to 246 and adhere to EIP-2718 format
     * @param receipt The receipt to check
     * @return bool
     */
    function isLegacyReceipt(
        bytes memory receipt
    ) internal pure returns (bool) {
        return uint8(receipt[0]) >= 0xf7;
    }

    function removeFirstByte(
        bytes memory data
    ) internal pure returns (bytes memory) {
        bytes memory result = new bytes(data.length - 1);

        assembly {
            let len := sub(mload(data), 1)
            mstore(result, len)
            let dataPtr := add(data, 0x21)
            let resultPtr := add(result, 0x20)
            mstore(result, len)
            for {
                let i := 0
            } lt(i, len) {
                i := add(i, 0x20)
            } {
                mstore(add(resultPtr, i), mload(add(dataPtr, i))) // Can use mcopy starting from 0.8.25
            }
        }

        return result;
    }
}

import XCTest
@testable import ShieldedPoolCore

/// EventParser tests — binary event parsing for all on-chain event types
final class EventParserTests: XCTestCase {

    // MARK: - Helpers

    /// Build raw event data for DepositV2
    private func buildDepositV2(
        epoch: UInt64 = 1,
        poolId: Data = Data(repeating: 0x01, count: 32),
        commitment: Data = Data(repeating: 0xAA, count: 32),
        leafIndex: UInt64 = 0,
        newRoot: Data = Data(repeating: 0xBB, count: 32),
        encryptedNote: Data = Data(repeating: 0xCC, count: 64)
    ) -> Data {
        var data = EventDiscriminators.depositV2
        data.append(withUnsafeBytes(of: epoch) { Data($0) })
        data.append(poolId)
        data.append(commitment)
        data.append(withUnsafeBytes(of: leafIndex) { Data($0) })
        data.append(newRoot)
        data.append(withUnsafeBytes(of: UInt32(encryptedNote.count)) { Data($0) })
        data.append(encryptedNote)
        return data
    }

    /// Build raw event data for WithdrawV2
    private func buildWithdrawV2(
        epoch: UInt64 = 1,
        poolId: Data = Data(repeating: 0x01, count: 32),
        nullifier: Data = Data(repeating: 0xDD, count: 32),
        amount: UInt64 = 1_000_000,
        recipient: Data = Data(repeating: 0xEE, count: 32)
    ) -> Data {
        var data = EventDiscriminators.withdrawV2
        data.append(withUnsafeBytes(of: epoch) { Data($0) })
        data.append(poolId)
        data.append(nullifier)
        data.append(withUnsafeBytes(of: amount) { Data($0) })
        data.append(recipient)
        return data
    }

    /// Build raw event data for EpochRollover
    private func buildEpochRollover(
        previousEpoch: UInt64 = 0,
        newEpoch: UInt64 = 1,
        poolId: Data = Data(repeating: 0x01, count: 32)
    ) -> Data {
        var data = EventDiscriminators.epochRollover
        data.append(withUnsafeBytes(of: previousEpoch) { Data($0) })
        data.append(withUnsafeBytes(of: newEpoch) { Data($0) })
        data.append(poolId)
        return data
    }

    /// Build raw event data for EpochFinalized
    private func buildEpochFinalized(
        epoch: UInt64 = 1,
        poolId: Data = Data(repeating: 0x01, count: 32),
        merkleRoot: Data = Data(repeating: 0xFF, count: 32)
    ) -> Data {
        var data = EventDiscriminators.epochFinalized
        data.append(withUnsafeBytes(of: epoch) { Data($0) })
        data.append(poolId)
        data.append(merkleRoot)
        return data
    }

    /// Build raw event data for RenewV2
    private func buildRenewV2(
        sourceEpoch: UInt64 = 1,
        targetEpoch: UInt64 = 5,
        poolId: Data = Data(repeating: 0x01, count: 32),
        nullifier: Data = Data(repeating: 0xDD, count: 32),
        commitment: Data = Data(repeating: 0xAA, count: 32),
        leafIndex: UInt64 = 7,
        encryptedNote: Data = Data(repeating: 0xCC, count: 64)
    ) -> Data {
        var data = EventDiscriminators.renewV2
        data.append(withUnsafeBytes(of: sourceEpoch) { Data($0) })
        data.append(withUnsafeBytes(of: targetEpoch) { Data($0) })
        data.append(poolId)
        data.append(nullifier)
        data.append(commitment)
        data.append(withUnsafeBytes(of: leafIndex) { Data($0) })
        data.append(withUnsafeBytes(of: UInt32(encryptedNote.count)) { Data($0) })
        data.append(encryptedNote)
        return data
    }

    // MARK: - DepositV2

    func testParseDepositV2() {
        let data = buildDepositV2(epoch: 42, leafIndex: 7)
        let event = EventParser.parseDepositV2(data)

        XCTAssertNotNil(event)
        XCTAssertEqual(event?.epoch, 42)
        XCTAssertEqual(event?.commitment, Data(repeating: 0xAA, count: 32))
        XCTAssertEqual(event?.leafIndex, 7)
        XCTAssertEqual(event?.newRoot, Data(repeating: 0xBB, count: 32))
        XCTAssertEqual(event?.encryptedNote.count, 64)
    }

    func testParseDepositV2TooShort() {
        let data = Data(repeating: 0, count: 10) // way too short
        XCTAssertNil(EventParser.parseDepositV2(data))
    }

    // MARK: - WithdrawV2

    func testParseWithdrawV2() {
        let data = buildWithdrawV2(epoch: 3, amount: 5_000_000)
        let event = EventParser.parseWithdrawV2(data)

        XCTAssertNotNil(event)
        XCTAssertEqual(event?.epoch, 3)
        XCTAssertEqual(event?.nullifier, Data(repeating: 0xDD, count: 32))
        XCTAssertEqual(event?.amount, 5_000_000)
        XCTAssertEqual(event?.recipient, Data(repeating: 0xEE, count: 32))
    }

    func testParseWithdrawV2TooShort() {
        let data = Data(repeating: 0, count: 30)
        XCTAssertNil(EventParser.parseWithdrawV2(data))
    }

    // MARK: - EpochRollover

    func testParseEpochRollover() {
        let data = buildEpochRollover(previousEpoch: 9, newEpoch: 10)
        let event = EventParser.parseEpochRollover(data)

        XCTAssertNotNil(event)
        XCTAssertEqual(event?.previousEpoch, 9)
        XCTAssertEqual(event?.newEpoch, 10)
        XCTAssertEqual(event?.poolId, Data(repeating: 0x01, count: 32))
    }

    // MARK: - EpochFinalized

    func testParseEpochFinalized() {
        let root = Data(repeating: 0xAB, count: 32)
        let data = buildEpochFinalized(epoch: 5, merkleRoot: root)
        let event = EventParser.parseEpochFinalized(data)

        XCTAssertNotNil(event)
        XCTAssertEqual(event?.epoch, 5)
        XCTAssertEqual(event?.merkleRoot, root)
    }

    // MARK: - RenewV2

    func testParseRenewV2() {
        let data = buildRenewV2(sourceEpoch: 2, targetEpoch: 8, leafIndex: 42)
        let event = EventParser.parseRenewV2(data)

        XCTAssertNotNil(event)
        XCTAssertEqual(event?.sourceEpoch, 2)
        XCTAssertEqual(event?.targetEpoch, 8)
        XCTAssertEqual(event?.nullifier, Data(repeating: 0xDD, count: 32))
        XCTAssertEqual(event?.commitment, Data(repeating: 0xAA, count: 32))
        XCTAssertEqual(event?.leafIndex, 42)
        XCTAssertEqual(event?.encryptedNote.count, 64)
    }

    func testParseRenewV2TooShort() {
        let data = Data(repeating: 0, count: 20)
        XCTAssertNil(EventParser.parseRenewV2(data))
    }

    // MARK: - TransferV2 (complex vector layout)

    func testParseTransferV2() {
        var data = EventDiscriminators.transferV2
        let outputEpoch: UInt64 = 5
        data.append(withUnsafeBytes(of: outputEpoch) { Data($0) })
        data.append(Data(repeating: 0x01, count: 32)) // poolId

        // nullifiers: 2 items
        data.append(withUnsafeBytes(of: UInt32(2)) { Data($0) })
        data.append(Data(repeating: 0xD1, count: 32))
        data.append(Data(repeating: 0xD2, count: 32))

        // inputEpochs: 2 items
        data.append(withUnsafeBytes(of: UInt32(2)) { Data($0) })
        let epoch1: UInt64 = 3; let epoch2: UInt64 = 4
        data.append(withUnsafeBytes(of: epoch1) { Data($0) })
        data.append(withUnsafeBytes(of: epoch2) { Data($0) })

        // commitments: 2 items
        data.append(withUnsafeBytes(of: UInt32(2)) { Data($0) })
        data.append(Data(repeating: 0xC1, count: 32))
        data.append(Data(repeating: 0xC2, count: 32))

        // leafIndices: 2 items
        data.append(withUnsafeBytes(of: UInt32(2)) { Data($0) })
        let idx1: UInt64 = 10; let idx2: UInt64 = 11
        data.append(withUnsafeBytes(of: idx1) { Data($0) })
        data.append(withUnsafeBytes(of: idx2) { Data($0) })

        // encryptedNotes: 2 items
        data.append(withUnsafeBytes(of: UInt32(2)) { Data($0) })
        let enc1 = Data(repeating: 0xE1, count: 48)
        data.append(withUnsafeBytes(of: UInt32(enc1.count)) { Data($0) })
        data.append(enc1)
        let enc2 = Data(repeating: 0xE2, count: 48)
        data.append(withUnsafeBytes(of: UInt32(enc2.count)) { Data($0) })
        data.append(enc2)

        let event = EventParser.parseTransferV2(data)
        XCTAssertNotNil(event)
        XCTAssertEqual(event?.outputEpoch, 5)
        XCTAssertEqual(event?.nullifiers.count, 2)
        XCTAssertEqual(event?.inputEpochs, [3, 4])
        XCTAssertEqual(event?.commitments.count, 2)
        XCTAssertEqual(event?.leafIndices, [10, 11])
        XCTAssertEqual(event?.encryptedNotes.count, 2)
    }

    // MARK: - Discriminators

    func testEventDiscriminatorsAre8Bytes() {
        XCTAssertEqual(EventDiscriminators.depositV2.count, 8)
        XCTAssertEqual(EventDiscriminators.withdrawV2.count, 8)
        XCTAssertEqual(EventDiscriminators.transferV2.count, 8)
        XCTAssertEqual(EventDiscriminators.renewV2.count, 8)
        XCTAssertEqual(EventDiscriminators.epochRollover.count, 8)
        XCTAssertEqual(EventDiscriminators.epochFinalized.count, 8)
        XCTAssertEqual(EventDiscriminators.depositV1.count, 8)
        XCTAssertEqual(EventDiscriminators.withdrawV1.count, 8)
        XCTAssertEqual(EventDiscriminators.transferV1.count, 8)
    }

    func testAllDiscriminatorsUnique() {
        let discs = [
            EventDiscriminators.depositV2,
            EventDiscriminators.withdrawV2,
            EventDiscriminators.transferV2,
            EventDiscriminators.renewV2,
            EventDiscriminators.epochRollover,
            EventDiscriminators.epochFinalized,
            EventDiscriminators.depositV1,
            EventDiscriminators.withdrawV1,
            EventDiscriminators.transferV1,
        ]
        let unique = Set(discs)
        XCTAssertEqual(unique.count, discs.count, "All discriminators must be unique")
    }

    // MARK: - Edge Cases

    func testParseWithExactMinimumLength() {
        // WithdrawV2 minimum: 8 + 8 + 32 + 32 + 8 + 32 = 120 bytes
        let data = buildWithdrawV2()
        XCTAssertEqual(data.count, 120)
        XCTAssertNotNil(EventParser.parseWithdrawV2(data))
    }

    func testParseEmptyData() {
        XCTAssertNil(EventParser.parseDepositV2(Data()))
        XCTAssertNil(EventParser.parseWithdrawV2(Data()))
        XCTAssertNil(EventParser.parseTransferV2(Data()))
        XCTAssertNil(EventParser.parseRenewV2(Data()))
        XCTAssertNil(EventParser.parseEpochRollover(Data()))
        XCTAssertNil(EventParser.parseEpochFinalized(Data()))
    }
}

import XCTest
import SolanaSwift
@testable import ShieldedPoolSDK

/// Tests for ShieldedPoolInstructions — verifies instruction serialization and account layouts
final class InstructionTests: XCTestCase {

    // Test program ID (matches Anchor.toml)
    let programId: PublicKey = "C58iVei3DXTL9BSKe5ZpQuJehqLJL1fQjejdnCAdWzV7"

    // MARK: - Discriminator Verification

    func testDepositV2Discriminator() throws {
        let ix = ShieldedPoolInstructions.depositV2(
            commitment: Data(repeating: 0, count: 32),
            amount: 1_000_000,
            encryptedNote: Data(repeating: 0xCC, count: 20),
            accounts: makeDepositAccounts(),
            programId: programId
        )

        // First 8 bytes of instruction data = discriminator
        let disc = Array(ix.data.prefix(8))
        XCTAssertEqual(disc, [0x6d, 0x4b, 0x45, 0x99, 0xac, 0xda, 0x92, 0x13],
                       "deposit_v2 discriminator must match SHA256('global:deposit_v2')[0..8]")
    }

    func testWithdrawV2Discriminator() throws {
        let ix = ShieldedPoolInstructions.withdrawV2(
            proofBytes: ShieldedPoolInstructions.mockProofBytes(),
            publicInputs: makeWithdrawInputs(),
            accounts: makeWithdrawAccounts(),
            programId: programId
        )
        let disc = Array(ix.data.prefix(8))
        XCTAssertEqual(disc, [0xf2, 0x50, 0xa3, 0x00, 0xc4, 0xdd, 0xc2, 0xc2])
    }

    func testTransferV2Discriminator() throws {
        let ix = ShieldedPoolInstructions.transferV2(
            proofBytes: ShieldedPoolInstructions.mockProofBytes(),
            publicInputs: makeTransferInputs(),
            encryptedNotes: [Data(count: 20), Data(count: 20)],
            accounts: makeTransferAccounts(),
            programId: programId
        )
        let disc = Array(ix.data.prefix(8))
        XCTAssertEqual(disc, [0x77, 0x28, 0x06, 0xeb, 0xea, 0xdd, 0xf8, 0x31])
    }

    func testRenewNoteDiscriminator() throws {
        let ix = ShieldedPoolInstructions.renewNote(
            proofBytes: ShieldedPoolInstructions.mockProofBytes(),
            publicInputs: makeRenewInputs(),
            encryptedNote: Data(count: 20),
            accounts: makeRenewAccounts(),
            programId: programId
        )
        let disc = Array(ix.data.prefix(8))
        XCTAssertEqual(disc, [0xcf, 0xfe, 0x07, 0x63, 0xcc, 0x44, 0xa3, 0xab])
    }

    // MARK: - Deposit V2 Instruction Layout

    func testDepositV2Layout() throws {
        let commitment = Data(repeating: 0xAB, count: 32)
        let amount: UInt64 = 1_000_000_000
        let encNote = Data(repeating: 0xCC, count: 50)

        let ix = ShieldedPoolInstructions.depositV2(
            commitment: commitment,
            amount: amount,
            encryptedNote: encNote,
            accounts: makeDepositAccounts(),
            programId: programId
        )

        let data = Data(ix.data)
        // Layout: disc(8) + commitment(32) + amount(8) + enc_note(4+50) = 102
        XCTAssertEqual(data.count, 8 + 32 + 8 + 4 + 50)

        // Verify commitment at offset 8
        XCTAssertEqual(Data(data[8..<40]), commitment)

        // Verify amount at offset 40
        let amountLE = data[40..<48].withUnsafeBytes { $0.load(as: UInt64.self) }
        XCTAssertEqual(UInt64(littleEndian: amountLE), 1_000_000_000)

        // Verify encrypted note length at offset 48
        let encLen = data[48..<52].withUnsafeBytes { $0.load(as: UInt32.self) }
        XCTAssertEqual(UInt32(littleEndian: encLen), 50)
    }

    func testDepositV2AccountCount() throws {
        let ix = ShieldedPoolInstructions.depositV2(
            commitment: Data(count: 32),
            amount: 100,
            encryptedNote: Data(count: 10),
            accounts: makeDepositAccounts(),
            programId: programId
        )

        // deposit_v2 needs 8 accounts
        XCTAssertEqual(ix.keys.count, 8)

        // depositor (index 6) must be signer
        XCTAssertTrue(ix.keys[6].isSigner)

        // token_program (index 7) is read-only
        XCTAssertFalse(ix.keys[7].isWritable)
        XCTAssertFalse(ix.keys[7].isSigner)
    }

    // MARK: - Withdraw V2 Layout

    func testWithdrawV2AccountCount() throws {
        let ix = ShieldedPoolInstructions.withdrawV2(
            proofBytes: ShieldedPoolInstructions.mockProofBytes(),
            publicInputs: makeWithdrawInputs(),
            accounts: makeWithdrawAccounts(),
            programId: programId
        )

        // withdraw_v2 needs 11 accounts
        XCTAssertEqual(ix.keys.count, 11)

        // payer (index 8) must be signer
        XCTAssertTrue(ix.keys[8].isSigner)
    }

    func testWithdrawV2DataLayout() throws {
        let proof = ShieldedPoolInstructions.mockProofBytes()
        let inputs = makeWithdrawInputs()

        let ix = ShieldedPoolInstructions.withdrawV2(
            proofBytes: proof,
            publicInputs: inputs,
            accounts: makeWithdrawAccounts(),
            programId: programId
        )

        let data = Data(ix.data)
        // Layout: disc(8) + proof_bytes(4+256) + public_inputs(32+32+8+32+8+32+32) = 8+260+176 = 444
        XCTAssertEqual(data.count, 8 + 4 + 256 + 176)
    }

    // MARK: - Mock Proof

    func testMockProofBytes() {
        let proof = ShieldedPoolInstructions.mockProofBytes()
        XCTAssertEqual(proof.count, 256)
        XCTAssertTrue(proof.allSatisfy { $0 == 0 }, "Mock proof must be all zeros")
    }

    // MARK: - Initialize Instructions

    func testInitializePoolV2() throws {
        let accounts = ShieldedPoolInstructions.InitializePoolV2Accounts(
            poolConfig: try PublicKey(data: Data(repeating: 1, count: 32)),
            epochTree: try PublicKey(data: Data(repeating: 2, count: 32)),
            vaultAuthority: try PublicKey(data: Data(repeating: 3, count: 32)),
            vault: try PublicKey(data: Data(repeating: 4, count: 32)),
            mint: try PublicKey(data: Data(repeating: 5, count: 32)),
            authority: try PublicKey(data: Data(repeating: 6, count: 32)),
            payer: try PublicKey(data: Data(repeating: 7, count: 32))
        )

        let ix = ShieldedPoolInstructions.initializePoolV2(
            epochDurationSlots: 100,
            expirySlots: 300,
            finalizationDelaySlots: 10,
            accounts: accounts,
            programId: programId
        )

        let data = Data(ix.data)
        // disc(8) + 3 × u64(8) = 32 bytes
        XCTAssertEqual(data.count, 32)
        XCTAssertEqual(ix.keys.count, 9) // 7 accounts + system_program + token_program
    }

    func testInitializeEpochLeafChunk() throws {
        let ix = ShieldedPoolInstructions.initializeEpochLeafChunk(
            epoch: 0,
            chunkIndex: 0,
            poolConfig: try PublicKey(data: Data(repeating: 1, count: 32)),
            leafChunk: try PublicKey(data: Data(repeating: 2, count: 32)),
            payer: try PublicKey(data: Data(repeating: 3, count: 32)),
            programId: programId
        )

        let data = Data(ix.data)
        // disc(8) + epoch(8) + chunk_index(4) = 20 bytes
        XCTAssertEqual(data.count, 20)
        XCTAssertEqual(ix.keys.count, 4)
    }

    func testFinalizeEpoch() throws {
        let ix = ShieldedPoolInstructions.finalizeEpoch(
            epoch: 5,
            poolConfig: try PublicKey(data: Data(repeating: 1, count: 32)),
            epochTree: try PublicKey(data: Data(repeating: 2, count: 32)),
            programId: programId
        )

        let data = Data(ix.data)
        // disc(8) + epoch(8) = 16 bytes
        XCTAssertEqual(data.count, 16)
        XCTAssertEqual(ix.keys.count, 2)
    }

    // MARK: - PublicInputs Serialization

    func testWithdrawPublicInputsSerialization() throws {
        let inputs = makeWithdrawInputs()
        let data = inputs.serialize()
        // root(32) + nullifier(32) + amount(8) + recipient(32) + epoch(8) + txAnchor(32) + poolId(32) = 176
        XCTAssertEqual(data.count, 176)
    }

    func testTransferPublicInputsSerialization() {
        let inputs = makeTransferInputs()
        let data = inputs.serialize()
        // root(32) + nf1(32) + nf2(32) + oc1(32) + oc2(32) + epoch(8) + txAnchor(32) + poolId(32) = 232
        XCTAssertEqual(data.count, 232)
    }

    func testRenewPublicInputsSerialization() {
        let inputs = makeRenewInputs()
        let data = inputs.serialize()
        // oldRoot(32) + nullifier(32) + newCommitment(32) + oldEpoch(8) + newEpoch(8) + txAnchor(32) + poolId(32) = 176
        XCTAssertEqual(data.count, 176)
    }

    // MARK: - Helpers

    private func makeDepositAccounts() -> ShieldedPoolInstructions.DepositV2Accounts {
        ShieldedPoolInstructions.DepositV2Accounts(
            poolConfig: try! PublicKey(data: Data(repeating: 1, count: 32)),
            epochTree: try! PublicKey(data: Data(repeating: 2, count: 32)),
            leafChunk: try! PublicKey(data: Data(repeating: 3, count: 32)),
            vault: try! PublicKey(data: Data(repeating: 4, count: 32)),
            depositorTokenAccount: try! PublicKey(data: Data(repeating: 5, count: 32)),
            mint: try! PublicKey(data: Data(repeating: 6, count: 32)),
            depositor: try! PublicKey(data: Data(repeating: 7, count: 32))
        )
    }

    private func makeWithdrawAccounts() -> ShieldedPoolInstructions.WithdrawV2Accounts {
        ShieldedPoolInstructions.WithdrawV2Accounts(
            poolConfig: try! PublicKey(data: Data(repeating: 1, count: 32)),
            epochTree: try! PublicKey(data: Data(repeating: 2, count: 32)),
            nullifierMarker: try! PublicKey(data: Data(repeating: 3, count: 32)),
            verifierConfig: try! PublicKey(data: Data(repeating: 4, count: 32)),
            vaultAuthority: try! PublicKey(data: Data(repeating: 5, count: 32)),
            vault: try! PublicKey(data: Data(repeating: 6, count: 32)),
            recipientTokenAccount: try! PublicKey(data: Data(repeating: 7, count: 32)),
            mint: try! PublicKey(data: Data(repeating: 8, count: 32)),
            payer: try! PublicKey(data: Data(repeating: 9, count: 32))
        )
    }

    private func makeTransferAccounts() -> ShieldedPoolInstructions.TransferV2Accounts {
        ShieldedPoolInstructions.TransferV2Accounts(
            poolConfig: try! PublicKey(data: Data(repeating: 1, count: 32)),
            spendEpochTree: try! PublicKey(data: Data(repeating: 2, count: 32)),
            depositEpochTree: try! PublicKey(data: Data(repeating: 3, count: 32)),
            nullifierMarker1: try! PublicKey(data: Data(repeating: 4, count: 32)),
            nullifierMarker2: try! PublicKey(data: Data(repeating: 5, count: 32)),
            depositLeafChunk: try! PublicKey(data: Data(repeating: 6, count: 32)),
            verifierConfig: try! PublicKey(data: Data(repeating: 7, count: 32)),
            payer: try! PublicKey(data: Data(repeating: 8, count: 32))
        )
    }

    private func makeRenewAccounts() -> ShieldedPoolInstructions.RenewNoteAccounts {
        ShieldedPoolInstructions.RenewNoteAccounts(
            poolConfig: try! PublicKey(data: Data(repeating: 1, count: 32)),
            oldEpochTree: try! PublicKey(data: Data(repeating: 2, count: 32)),
            newEpochTree: try! PublicKey(data: Data(repeating: 3, count: 32)),
            nullifierMarker: try! PublicKey(data: Data(repeating: 4, count: 32)),
            newLeafChunk: try! PublicKey(data: Data(repeating: 5, count: 32)),
            verifierConfig: try! PublicKey(data: Data(repeating: 6, count: 32)),
            payer: try! PublicKey(data: Data(repeating: 7, count: 32))
        )
    }

    private func makeWithdrawInputs() -> ShieldedPoolInstructions.WithdrawPublicInputs {
        ShieldedPoolInstructions.WithdrawPublicInputs(
            root: Data(repeating: 0xAA, count: 32),
            nullifier: Data(repeating: 0xBB, count: 32),
            amount: 1_000_000,
            recipient: try! PublicKey(data: Data(repeating: 0xCC, count: 32)),
            epoch: 0,
            txAnchor: Data(count: 32),
            poolId: Data(repeating: 0x01, count: 32)
        )
    }

    private func makeTransferInputs() -> ShieldedPoolInstructions.TransferPublicInputs {
        ShieldedPoolInstructions.TransferPublicInputs(
            root: Data(repeating: 0xAA, count: 32),
            nullifier1: Data(repeating: 0xB1, count: 32),
            nullifier2: Data(repeating: 0xB2, count: 32),
            outputCommitment1: Data(repeating: 0xC1, count: 32),
            outputCommitment2: Data(repeating: 0xC2, count: 32),
            outputEpoch: 1,
            txAnchor: Data(count: 32),
            poolId: Data(repeating: 0x01, count: 32)
        )
    }

    private func makeRenewInputs() -> ShieldedPoolInstructions.RenewPublicInputs {
        ShieldedPoolInstructions.RenewPublicInputs(
            oldRoot: Data(repeating: 0xAA, count: 32),
            nullifier: Data(repeating: 0xBB, count: 32),
            newCommitment: Data(repeating: 0xCC, count: 32),
            oldEpoch: 1,
            newEpoch: 5,
            txAnchor: Data(count: 32),
            poolId: Data(repeating: 0x01, count: 32)
        )
    }
}

import XCTest
import BigInt
@testable import ShieldedPoolCore

/// Phase 4: Integration tests — full lifecycle flows, event processing, TxBuilder, PDA derivation.
/// These test the complete pipeline from deposit preparation through event scanning and state management.
/// On-chain submission requires Anchor instruction serialization (not yet implemented) or the TS SDK bridge.
final class IntegrationTests: XCTestCase {

    // MARK: - Shared Setup

    private let testSeed = Data(0..<32)
    private let tokenMint = Data(repeating: 0x42, count: 32)
    private let poolId = Data(repeating: 0x01, count: 32)

    private func makeKeyManager() -> KeyManager {
        KeyManager.fromSeed(testSeed)
    }

    private func makeNoteManager(keys: SpendingKeys? = nil) -> NoteManager {
        NoteManager(spendingKeys: keys)
    }

    private func makeTxBuilder() -> TxBuilder {
        let config = ProverConfig(zkeyPath: "/mock.zkey", circuitType: .withdraw)
        let prover = ZKProver(config: config)
        return TxBuilder(prover: prover, poolId: poolId, tokenMint: tokenMint)
    }

    // MARK: - Deposit Preparation

    func testPrepareDeposit() throws {
        let km = makeKeyManager()
        let txb = makeTxBuilder()
        txb.setCurrentEpoch(0)

        let deposit = try txb.prepareDeposit(
            amount: 1_000_000,
            recipientAddress: km.shieldedAddress,
            viewingKey: km.viewingKey
        )

        XCTAssertEqual(deposit.amount, 1_000_000)
        XCTAssertEqual(deposit.epoch, 0)
        XCTAssertEqual(deposit.commitment.count, 32)
        XCTAssertTrue(deposit.encryptedNote.count > 12, "Encrypted note = nonce(12) + ciphertext + tag")
        XCTAssertEqual(deposit.outputNote.value, 1_000_000)
        XCTAssertEqual(deposit.outputNote.owner, km.shieldedAddress)
    }

    func testPrepareDepositDecryptRoundtrip() throws {
        let km = makeKeyManager()
        let txb = makeTxBuilder()
        txb.setCurrentEpoch(3)

        let deposit = try txb.prepareDeposit(
            amount: 5_000_000,
            recipientAddress: km.shieldedAddress,
            viewingKey: km.viewingKey
        )

        // Decrypt the encrypted note (simulates what the scanner does on-chain)
        let decrypted = NoteManager.decryptNote(
            encryptedData: deposit.encryptedNote,
            viewingKey: km.viewingKey,
            token: tokenMint,
            leafIndex: 0,
            epoch: 3
        )

        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted?.value, 5_000_000)
        XCTAssertEqual(decrypted?.owner, km.shieldedAddress)
    }

    func testPrepareDepositCommitmentMatchesManual() throws {
        let km = makeKeyManager()
        let txb = makeTxBuilder()

        let deposit = try txb.prepareDeposit(
            amount: 1_000_000,
            recipientAddress: km.shieldedAddress,
            viewingKey: km.viewingKey
        )

        // Manually compute commitment from the output note
        let manualCommitment = try Crypto.computeCommitment(
            value: deposit.outputNote.value,
            owner: deposit.outputNote.owner,
            randomness: deposit.outputNote.randomness
        )

        XCTAssertEqual(deposit.commitment, manualCommitment,
                       "TxBuilder commitment must match manual Poseidon computation")
    }

    // MARK: - Full Deposit → Merkle → Nullifier Lifecycle

    func testDepositToMerkleToNullifierLifecycle() throws {
        let km = makeKeyManager()
        let keys = km.exportKeys()
        let txb = makeTxBuilder()
        let tree = EpochMerkleTree(epoch: 0)
        let mgr = makeNoteManager(keys: keys)
        mgr.setCurrentEpoch(0)

        // Step 1: Prepare deposit
        let deposit = try txb.prepareDeposit(
            amount: 1_000_000,
            recipientAddress: km.shieldedAddress,
            viewingKey: km.viewingKey
        )

        // Step 2: Insert commitment into Merkle tree (simulates on-chain deposit event)
        let (leafIndex, root) = try tree.insert(deposit.commitment)
        XCTAssertEqual(leafIndex, 0)
        XCTAssertEqual(root.count, 32)

        // Step 3: Update the note with confirmed position
        var confirmedNote = deposit.outputNote
        confirmedNote.leafIndex = UInt32(leafIndex)
        confirmedNote.epoch = 0

        // Step 4: Recompute nullifier with confirmed position
        confirmedNote.nullifier = try Crypto.computeNullifier(
            commitment: confirmedNote.commitment,
            nullifierKey: keys.nullifierKey,
            epoch: 0,
            leafIndex: UInt32(leafIndex)
        )

        // Step 5: Add to NoteManager
        mgr.addNote(confirmedNote)
        XCTAssertEqual(mgr.calculateBalance(), 1_000_000)
        XCTAssertEqual(mgr.getNotes().count, 1)

        // Step 6: Verify Merkle proof
        let proof = try tree.getProof(leafIndex: leafIndex)
        XCTAssertTrue(EpochMerkleTree.verifyProof(proof))

        // Step 7: Mark as spent via nullifier
        mgr.markSpentByNullifier(confirmedNote.nullifier, epoch: 0)
        XCTAssertEqual(mgr.calculateBalance(), 0)
        XCTAssertEqual(mgr.getNotes().count, 0)
    }

    // MARK: - Multi-Deposit + Selection

    func testMultiDepositAndSelection() throws {
        let km = makeKeyManager()
        let keys = km.exportKeys()
        let txb = makeTxBuilder()
        let tree = EpochMerkleTree(epoch: 0)
        let mgr = makeNoteManager(keys: keys)
        mgr.setCurrentEpoch(0)

        // Deposit 3 notes
        let amounts: [UInt64] = [1_000_000, 2_000_000, 500_000]
        for amount in amounts {
            let dep = try txb.prepareDeposit(
                amount: amount,
                recipientAddress: km.shieldedAddress,
                viewingKey: km.viewingKey
            )
            let (idx, _) = try tree.insert(dep.commitment)
            var note = dep.outputNote
            note.leafIndex = UInt32(idx)
            note.epoch = 0
            note.nullifier = try Crypto.computeNullifier(
                commitment: note.commitment,
                nullifierKey: keys.nullifierKey,
                epoch: 0,
                leafIndex: UInt32(idx)
            )
            mgr.addNote(note)
        }

        XCTAssertEqual(mgr.calculateBalance(), 3_500_000)
        XCTAssertEqual(mgr.getNotes().count, 3)

        // Select notes for a 2.5M withdraw
        let selected = try mgr.selectNotes(amount: 2_500_000)
        let selectedTotal = selected.reduce(0 as UInt64) { $0 + $1.value }
        XCTAssertTrue(selectedTotal >= 2_500_000)
    }

    // MARK: - Event Scanner Integration

    func testEventScannerDepositFlow() throws {
        let km = makeKeyManager()
        let keys = km.exportKeys()
        let mgr = makeNoteManager(keys: keys)
        let txb = makeTxBuilder()
        mgr.setCurrentEpoch(0)

        // Prepare a deposit
        let deposit = try txb.prepareDeposit(
            amount: 1_000_000,
            recipientAddress: km.shieldedAddress,
            viewingKey: km.viewingKey
        )

        // Create scanner
        let scanner = UTXOScanner(
            viewingKey: km.viewingKey,
            tokenMint: tokenMint,
            poolId: poolId,
            noteManager: mgr
        )

        // Build simulated deposit event data
        var eventData = EventDiscriminators.depositV2
        var epoch: UInt64 = 0
        eventData.append(withUnsafeBytes(of: &epoch) { Data($0) })
        eventData.append(poolId) // pool_id
        eventData.append(deposit.commitment) // commitment
        var leafIdx: UInt64 = 0
        eventData.append(withUnsafeBytes(of: &leafIdx) { Data($0) }) // leaf_index
        eventData.append(Data(repeating: 0xAA, count: 32)) // new_root (placeholder)
        var encLen = UInt32(deposit.encryptedNote.count)
        eventData.append(withUnsafeBytes(of: &encLen) { Data($0) })
        eventData.append(deposit.encryptedNote)

        // Process event
        scanner.processEventData(eventData)

        // Verify note was decrypted and added
        XCTAssertEqual(mgr.getNotes().count, 1)
        XCTAssertEqual(mgr.getNotes().first?.value, 1_000_000)
        XCTAssertEqual(mgr.getNotes().first?.epoch, 0)
        XCTAssertEqual(mgr.getNotes().first?.leafIndex, 0)
    }

    func testEventScannerWithdrawFlow() throws {
        let km = makeKeyManager()
        let keys = km.exportKeys()
        let mgr = makeNoteManager(keys: keys)

        // Pre-populate with a note
        let randomness = Crypto.sha256(Data("rand1".utf8))
        let commitment = try Crypto.computeCommitment(
            value: 1_000_000,
            owner: km.shieldedAddress,
            randomness: randomness
        )
        let nullifier = try Crypto.computeNullifier(
            commitment: commitment,
            nullifierKey: keys.nullifierKey,
            epoch: 0,
            leafIndex: 0
        )

        let note = Note(
            value: 1_000_000,
            token: tokenMint,
            owner: km.shieldedAddress,
            blinding: randomness,
            commitment: commitment,
            leafIndex: 0,
            epoch: 0,
            nullifier: nullifier,
            randomness: randomness
        )
        mgr.addNote(note)
        XCTAssertEqual(mgr.calculateBalance(), 1_000_000)

        // Create scanner
        let scanner = UTXOScanner(
            viewingKey: km.viewingKey,
            tokenMint: tokenMint,
            poolId: poolId,
            noteManager: mgr
        )

        // Build withdraw event — nullifier matches
        var eventData = EventDiscriminators.withdrawV2
        var epoch: UInt64 = 0
        eventData.append(withUnsafeBytes(of: &epoch) { Data($0) })
        eventData.append(poolId)
        eventData.append(nullifier)
        var amount: UInt64 = 1_000_000
        eventData.append(withUnsafeBytes(of: &amount) { Data($0) })
        eventData.append(Data(repeating: 0xFF, count: 32)) // recipient

        scanner.processEventData(eventData)

        // Note should be marked spent
        XCTAssertEqual(mgr.calculateBalance(), 0)
    }

    func testEventScannerEpochRollover() {
        let km = makeKeyManager()
        let mgr = makeNoteManager()

        let scanner = UTXOScanner(
            viewingKey: km.viewingKey,
            tokenMint: tokenMint,
            poolId: poolId,
            noteManager: mgr
        )

        scanner.setCurrentEpoch(0)

        // Build epoch rollover event
        var eventData = EventDiscriminators.epochRollover
        var prevEpoch: UInt64 = 0
        var newEpoch: UInt64 = 1
        eventData.append(withUnsafeBytes(of: &prevEpoch) { Data($0) })
        eventData.append(withUnsafeBytes(of: &newEpoch) { Data($0) })
        eventData.append(poolId)

        scanner.processEventData(eventData)

        // NoteManager epoch should be updated
        XCTAssertEqual(mgr.getCurrentEpoch(), 1)
    }

    // MARK: - Cross-Epoch Note Management

    func testCrossEpochDepositsAndRenewal() throws {
        let km = makeKeyManager()
        let keys = km.exportKeys()
        let mgr = makeNoteManager(keys: keys)

        // Add notes across multiple epochs
        for epoch in [UInt64(0), 1, 5] {
            let randomness = Crypto.sha256(Data("r\(epoch)".utf8))
            let commitment = try Crypto.computeCommitment(
                value: 1_000_000,
                owner: km.shieldedAddress,
                randomness: randomness
            )
            let nullifier = try Crypto.computeNullifier(
                commitment: commitment,
                nullifierKey: keys.nullifierKey,
                epoch: epoch,
                leafIndex: 0
            )

            mgr.addNote(Note(
                value: 1_000_000,
                token: tokenMint,
                owner: km.shieldedAddress,
                blinding: randomness,
                commitment: commitment,
                leafIndex: 0,
                epoch: epoch,
                nullifier: nullifier,
                randomness: randomness
            ))
        }

        XCTAssertEqual(mgr.calculateBalance(), 3_000_000)

        // Set current epoch to 7 — epochs 0 and 1 should be "expiring" (within threshold 2)
        mgr.setCurrentEpoch(7)
        let expiring = mgr.getExpiringNotes()
        // Epochs 5, 6 are within threshold (currentEpoch + 2 = 9) and < currentEpoch (7)
        // Epoch 5 is within threshold and < 7 → expiring
        // Epoch 0, 1 are also < 7 and <= 9 → expiring
        XCTAssertTrue(expiring.count >= 2, "Old epoch notes should be flagged as expiring")

        // Select for renewal
        let forRenewal = mgr.selectNotesForRenewal()
        XCTAssertTrue(forRenewal.count >= 2)
        // Should be sorted oldest first
        if forRenewal.count >= 2 {
            XCTAssertTrue((forRenewal[0].epoch ?? UInt64.max) <= (forRenewal[1].epoch ?? UInt64.max))
        }
    }

    // MARK: - Value Conservation

    func testValueConservationValidation() throws {
        let txb = makeTxBuilder()

        // Valid: inputs == outputs
        let note1 = Note(value: 1_000_000, token: tokenMint, owner: Data(count: 32),
                         blinding: Data(count: 32), randomness: Data(count: 32))
        let note2 = Note(value: 500_000, token: tokenMint, owner: Data(count: 32),
                         blinding: Data(count: 32), randomness: Data(count: 32))

        XCTAssertNoThrow(try txb.validateConservation(
            inputNotes: [note1, note2],
            outputValues: [800_000, 700_000],
            fee: 0
        ))

        // Invalid: inputs != outputs
        XCTAssertThrowsError(try txb.validateConservation(
            inputNotes: [note1],
            outputValues: [500_000],
            fee: 0
        ))
    }

    // MARK: - Merkle Root History Through Deposits

    func testMerkleRootHistoryAcrossDeposits() throws {
        let km = makeKeyManager()
        let txb = makeTxBuilder()
        let tree = EpochMerkleTree(epoch: 0)

        var roots: [Data] = []
        for i in 0..<5 {
            let dep = try txb.prepareDeposit(
                amount: UInt64(i + 1) * 100_000,
                recipientAddress: km.shieldedAddress,
                viewingKey: km.viewingKey
            )
            let (_, root) = try tree.insert(dep.commitment)
            roots.append(root)
        }

        // All historical roots should be known
        for root in roots {
            XCTAssertTrue(tree.isKnownRoot(root))
        }

        // Random root should not be known
        XCTAssertFalse(tree.isKnownRoot(Data(repeating: 0xFF, count: 32)))
    }

    // MARK: - Epoch Tree State Transitions

    func testEpochTreeFinalization() throws {
        let tree = EpochMerkleTree(epoch: 0)
        XCTAssertEqual(tree.getState(), .active)

        // Insert some leaves
        for i in 0..<3 {
            var leaf = Data(repeating: 0, count: 32)
            leaf[31] = UInt8(i + 1)
            let _ = try tree.insert(leaf)
        }

        // Finalize
        let finalRoot = tree.getRoot()
        tree.setFinalRoot(finalRoot)
        XCTAssertEqual(tree.getState(), .finalized)

        // Can't insert into finalized tree
        XCTAssertThrowsError(try tree.insert(Data(repeating: 0xFF, count: 32)))

        // Root should still be accessible
        XCTAssertEqual(tree.getRoot(), finalRoot)
    }

    // MARK: - Full Balance Info Lifecycle

    func testBalanceInfoThroughLifecycle() throws {
        let km = makeKeyManager()
        let keys = km.exportKeys()
        let mgr = makeNoteManager(keys: keys)
        mgr.setCurrentEpoch(5)

        // Add confirmed note in current epoch
        let r1 = Crypto.sha256(Data("r1".utf8))
        let c1 = try Crypto.computeCommitment(value: 2_000_000, owner: km.shieldedAddress, randomness: r1)
        let n1 = try Crypto.computeNullifier(commitment: c1, nullifierKey: keys.nullifierKey, epoch: 5, leafIndex: 0)
        mgr.addNote(Note(value: 2_000_000, token: tokenMint, owner: km.shieldedAddress,
                         blinding: r1, commitment: c1, leafIndex: 0, epoch: 5,
                         nullifier: n1, randomness: r1))

        // Add pending note
        let r2 = Crypto.sha256(Data("r2".utf8))
        let c2 = try Crypto.computeCommitment(value: 500_000, owner: km.shieldedAddress, randomness: r2)
        mgr.addPendingNote(Note(value: 500_000, token: tokenMint, owner: km.shieldedAddress,
                                blinding: r2, commitment: c2, randomness: r2))

        let info = mgr.calculateBalanceInfo()
        XCTAssertEqual(info.spendable, 2_000_000)
        XCTAssertEqual(info.pending, 500_000)
        XCTAssertEqual(info.total, 2_500_000)
        XCTAssertEqual(info.noteCount, 1)
        XCTAssertEqual(info.expired, 0)

        // Spend the confirmed note
        mgr.markSpentByNullifier(n1, epoch: 5)
        let info2 = mgr.calculateBalanceInfo()
        XCTAssertEqual(info2.spendable, 0)
        XCTAssertEqual(info2.pending, 500_000)
        XCTAssertEqual(info2.noteCount, 0)
    }

    // MARK: - PDA Seed Constants

    func testPDASeedConstants() {
        // Verify PDA seeds match on-chain program expectations
        XCTAssertEqual(PDASeed.poolConfig, "pool_config")
        XCTAssertEqual(PDASeed.epochTree, "epoch_tree")
        XCTAssertEqual(PDASeed.leafChunk, "leaves")
        XCTAssertEqual(PDASeed.vaultAuthority, "vault_authority")
        XCTAssertEqual(PDASeed.nullifierMarker, "nullifier")
        XCTAssertEqual(PDASeed.verifierConfig, "verifier")
    }

    func testMerkleConfigConstants() {
        XCTAssertEqual(MerkleConfig.depth, 12)
        XCTAssertEqual(MerkleConfig.maxLeaves, 4096)
        XCTAssertEqual(MerkleConfig.leavesPerChunk, 256)
    }

    // MARK: - Prepared Transaction Data Formats

    func testPreparedDepositFormat() throws {
        let km = makeKeyManager()
        let txb = makeTxBuilder()
        let deposit = try txb.prepareDeposit(
            amount: 1_000_000,
            recipientAddress: km.shieldedAddress,
            viewingKey: km.viewingKey
        )

        // Commitment must be 32 bytes (BN254 field element)
        XCTAssertEqual(deposit.commitment.count, 32)

        // Commitment must be in field
        let commitmentInt = BigUInt(deposit.commitment)
        XCTAssertTrue(Crypto.isInField(commitmentInt), "Commitment must be in BN254 field")

        // Encrypted note: 12 (nonce) + plaintext (130 min) + 16 (tag) = min 158 bytes
        XCTAssertTrue(deposit.encryptedNote.count >= 158)
    }

    // MARK: - Concurrent Deposits to Same Tree

    func testConcurrentDepositsToTree() throws {
        let km = makeKeyManager()
        let txb = makeTxBuilder()
        let tree = EpochMerkleTree(epoch: 0)

        // Simulate 10 deposits
        for _ in 0..<10 {
            let dep = try txb.prepareDeposit(
                amount: 100_000,
                recipientAddress: km.shieldedAddress,
                viewingKey: km.viewingKey
            )
            let _ = try tree.insert(dep.commitment)
        }

        XCTAssertEqual(tree.leafCount, 10)

        // All proofs should verify
        for i in 0..<10 {
            let proof = try tree.getProof(leafIndex: i)
            XCTAssertTrue(EpochMerkleTree.verifyProof(proof),
                          "Proof for leaf \(i) should verify after 10 inserts")
        }
    }

    // MARK: - Scanner Delegate (Event Tracking)

    func testScannerProcessesMultipleEventTypes() throws {
        let km = makeKeyManager()
        let keys = km.exportKeys()
        let mgr = makeNoteManager(keys: keys)
        mgr.setCurrentEpoch(0)

        let scanner = UTXOScanner(
            viewingKey: km.viewingKey,
            tokenMint: tokenMint,
            poolId: poolId,
            noteManager: mgr
        )

        // Deposit event
        let txb = makeTxBuilder()
        let dep = try txb.prepareDeposit(
            amount: 2_000_000,
            recipientAddress: km.shieldedAddress,
            viewingKey: km.viewingKey
        )

        var depositEvent = EventDiscriminators.depositV2
        var depEpoch: UInt64 = 0
        depositEvent.append(withUnsafeBytes(of: &depEpoch) { Data($0) })
        depositEvent.append(poolId)
        depositEvent.append(dep.commitment)
        var depLeafIdx: UInt64 = 0
        depositEvent.append(withUnsafeBytes(of: &depLeafIdx) { Data($0) })
        depositEvent.append(Data(repeating: 0, count: 32)) // root placeholder
        var depEncLen = UInt32(dep.encryptedNote.count)
        depositEvent.append(withUnsafeBytes(of: &depEncLen) { Data($0) })
        depositEvent.append(dep.encryptedNote)

        scanner.processEventData(depositEvent)
        XCTAssertEqual(mgr.calculateBalance(), 2_000_000)

        // Epoch rollover event
        var rolloverEvent = EventDiscriminators.epochRollover
        var prevE: UInt64 = 0; var newE: UInt64 = 1
        rolloverEvent.append(withUnsafeBytes(of: &prevE) { Data($0) })
        rolloverEvent.append(withUnsafeBytes(of: &newE) { Data($0) })
        rolloverEvent.append(poolId)

        scanner.processEventData(rolloverEvent)
        XCTAssertEqual(mgr.getCurrentEpoch(), 1)

        // Balance should still be there (note from epoch 0 still unspent)
        XCTAssertEqual(mgr.calculateBalance(), 2_000_000)
    }
}

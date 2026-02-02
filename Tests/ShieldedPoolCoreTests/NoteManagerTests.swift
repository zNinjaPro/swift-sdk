import XCTest
import BigInt
@testable import ShieldedPoolCore

/// NoteManager tests — note lifecycle, selection, balance, encryption/decryption, epoch expiry
final class NoteManagerTests: XCTestCase {

    // MARK: - Helpers

    private func makeNote(
        value: UInt64,
        epoch: UInt64? = nil,
        leafIndex: UInt32? = nil,
        spent: Bool = false,
        commitment: Data? = nil,
        owner: Data? = nil,
        randomness: Data? = nil
    ) -> Note {
        let own = owner ?? Data(repeating: 0xAA, count: 32)
        let rand = randomness ?? Crypto.sha256(Data("\(value)-\(epoch ?? 0)-\(leafIndex ?? 0)".utf8))
        let cm = commitment ?? (try! Crypto.computeCommitment(value: value, owner: own, randomness: rand))
        return Note(
            value: value,
            token: Data(count: 32),
            owner: own,
            blinding: rand,
            commitment: cm,
            leafIndex: leafIndex,
            epoch: epoch,
            nullifier: Data(count: 32),
            randomness: rand,
            spent: spent
        )
    }

    // MARK: - Basic Note Management

    func testAddAndRetrieveNotes() {
        let mgr = NoteManager()
        let n1 = makeNote(value: 1000, epoch: 1, leafIndex: 0)
        let n2 = makeNote(value: 2000, epoch: 1, leafIndex: 1)

        mgr.addNote(n1)
        mgr.addNote(n2)

        let notes = mgr.getNotes()
        XCTAssertEqual(notes.count, 2)
        XCTAssertEqual(notes[0].value, 1000)
        XCTAssertEqual(notes[1].value, 2000)
    }

    func testDeduplicationByCommitment() {
        let mgr = NoteManager()
        let n1 = makeNote(value: 1000, epoch: 1, leafIndex: 0)
        var n2 = n1
        n2.epoch = 2 // same commitment, different epoch

        mgr.addNote(n1)
        mgr.addNote(n2)

        let notes = mgr.getNotes()
        XCTAssertEqual(notes.count, 1, "Duplicate commitment should not add second note")
    }

    func testAddNoteUpdatesEpochAndLeafIndex() {
        let mgr = NoteManager()
        var n1 = makeNote(value: 1000)
        n1.epoch = nil
        n1.leafIndex = nil
        mgr.addNote(n1)

        // Re-add with epoch/leafIndex set
        var n2 = n1
        n2.epoch = 5
        n2.leafIndex = 42
        mgr.addNote(n2)

        let note = mgr.getNote(commitment: n1.commitment)
        XCTAssertEqual(note?.epoch, 5)
        XCTAssertEqual(note?.leafIndex, 42)
    }

    func testGetNotesByEpoch() {
        let mgr = NoteManager()
        mgr.addNote(makeNote(value: 100, epoch: 1, leafIndex: 0))
        mgr.addNote(makeNote(value: 200, epoch: 2, leafIndex: 0))
        mgr.addNote(makeNote(value: 300, epoch: 1, leafIndex: 1))

        let epoch1 = mgr.getNotesByEpoch(1)
        XCTAssertEqual(epoch1.count, 2)
        XCTAssertEqual(epoch1.map { $0.value }.sorted(), [100, 300])
    }

    // MARK: - Pending Notes

    func testPendingNotes() {
        let mgr = NoteManager()
        let pending = makeNote(value: 500)

        mgr.addPendingNote(pending)
        XCTAssertEqual(mgr.getPendingNotes().count, 1)

        // Confirming removes from pending
        mgr.addNote(pending)
        XCTAssertEqual(mgr.getPendingNotes().count, 0)
        XCTAssertEqual(mgr.getNotes().count, 1)
    }

    func testPendingDeduplication() {
        let mgr = NoteManager()
        let pending = makeNote(value: 500)

        mgr.addPendingNote(pending)
        mgr.addPendingNote(pending)
        XCTAssertEqual(mgr.getPendingNotes().count, 1)
    }

    // MARK: - Spending

    func testMarkSpentByCommitment() {
        let mgr = NoteManager()
        let note = makeNote(value: 1000, epoch: 1, leafIndex: 0)
        mgr.addNote(note)

        mgr.markSpent(commitment: note.commitment)
        XCTAssertEqual(mgr.getNotes().count, 0, "Spent notes excluded from getNotes()")
    }

    func testMarkSpentByNullifier() throws {
        let km = KeyManager.fromSeed(Data(0..<32))
        let mgr = NoteManager(spendingKeys: km.exportKeys())

        let owner = km.shieldedAddress
        let randomness = Crypto.sha256(Data("test".utf8))
        let commitment = try Crypto.computeCommitment(value: 1000, owner: owner, randomness: randomness)
        let nullifier = try Crypto.computeNullifier(
            commitment: commitment,
            nullifierKey: km.nullifierKey,
            epoch: 1,
            leafIndex: 0
        )

        var note = Note(
            value: 1000, token: Data(count: 32), owner: owner, blinding: randomness,
            commitment: commitment, leafIndex: 0, epoch: 1,
            nullifier: nullifier, randomness: randomness
        )
        mgr.addNote(note)

        mgr.markSpentByNullifier(nullifier, epoch: 1)
        XCTAssertEqual(mgr.getNotes().count, 0)
    }

    // MARK: - Balance

    func testCalculateBalance() {
        let mgr = NoteManager()
        mgr.addNote(makeNote(value: 1000, epoch: 1, leafIndex: 0))
        mgr.addNote(makeNote(value: 2000, epoch: 1, leafIndex: 1))
        mgr.addNote(makeNote(value: 500, epoch: 2, leafIndex: 0))

        XCTAssertEqual(mgr.calculateBalance(), 3500)
    }

    func testCalculateBalanceExcludesSpent() {
        let mgr = NoteManager()
        let n1 = makeNote(value: 1000, epoch: 1, leafIndex: 0)
        let n2 = makeNote(value: 2000, epoch: 1, leafIndex: 1)
        mgr.addNote(n1)
        mgr.addNote(n2)

        mgr.markSpent(commitment: n1.commitment)
        XCTAssertEqual(mgr.calculateBalance(), 2000)
    }

    func testCalculatePendingBalance() {
        let mgr = NoteManager()
        mgr.addPendingNote(makeNote(value: 500))
        mgr.addPendingNote(makeNote(value: 300))
        XCTAssertEqual(mgr.calculatePendingBalance(), 800)
    }

    func testBalanceInfo() {
        let mgr = NoteManager()
        mgr.addNote(makeNote(value: 1000, epoch: 5, leafIndex: 0))
        mgr.addNote(makeNote(value: 2000, epoch: 5, leafIndex: 1))
        mgr.addPendingNote(makeNote(value: 500))
        mgr.setCurrentEpoch(5)

        let info = mgr.calculateBalanceInfo()
        XCTAssertEqual(info.spendable, 3000)
        XCTAssertEqual(info.pending, 500)
        XCTAssertEqual(info.noteCount, 2)
    }

    // MARK: - Note Selection

    func testSelectNotesGreedy() throws {
        let mgr = NoteManager()
        mgr.addNote(makeNote(value: 1000, epoch: 1, leafIndex: 0))
        mgr.addNote(makeNote(value: 2000, epoch: 1, leafIndex: 1))
        mgr.addNote(makeNote(value: 500, epoch: 2, leafIndex: 0))

        let selected = try mgr.selectNotes(amount: 1500)
        let total = selected.reduce(0 as UInt64) { $0 + $1.value }
        XCTAssertTrue(total >= 1500)
    }

    func testSelectNotesPrioritizesOlderEpochs() throws {
        let mgr = NoteManager()
        mgr.addNote(makeNote(value: 1000, epoch: 3, leafIndex: 0))
        mgr.addNote(makeNote(value: 1000, epoch: 1, leafIndex: 0))
        mgr.addNote(makeNote(value: 1000, epoch: 2, leafIndex: 0))

        let selected = try mgr.selectNotes(amount: 1000)
        XCTAssertEqual(selected.first?.epoch, 1, "Should prioritize oldest epoch")
    }

    func testSelectNotesInsufficientBalance() {
        let mgr = NoteManager()
        mgr.addNote(makeNote(value: 100, epoch: 1, leafIndex: 0))

        XCTAssertThrowsError(try mgr.selectNotes(amount: 1000)) { error in
            guard case NoteManagerError.insufficientBalance = error else {
                return XCTFail("Expected insufficientBalance error")
            }
        }
    }

    func testSelectNotesInvalidMinNotes() {
        let mgr = NoteManager()
        XCTAssertThrowsError(try mgr.selectNotes(amount: 100, minNotes: 0)) { error in
            guard case NoteManagerError.invalidMinNotes = error else {
                return XCTFail("Expected invalidMinNotes error")
            }
        }
    }

    // MARK: - Epoch Expiry

    func testEpochManagement() {
        let mgr = NoteManager()
        XCTAssertEqual(mgr.getCurrentEpoch(), 0)
        mgr.setCurrentEpoch(42)
        XCTAssertEqual(mgr.getCurrentEpoch(), 42)
    }

    func testGetExpiringNotes() {
        // epochExpirySlots = 38_880_000, epochDuration = 3_024_000 → ~12.86 epochs
        // Expiring = epoch <= currentEpoch + 2 AND epoch < currentEpoch
        let mgr = NoteManager()
        mgr.setCurrentEpoch(10)

        // Epoch 8 and 9 are "expiring" (within warning threshold of 2, and < current)
        mgr.addNote(makeNote(value: 100, epoch: 8, leafIndex: 0))
        mgr.addNote(makeNote(value: 200, epoch: 9, leafIndex: 0))
        mgr.addNote(makeNote(value: 300, epoch: 10, leafIndex: 0)) // current, not expiring
        mgr.addNote(makeNote(value: 400, epoch: 11, leafIndex: 0)) // future, not expiring

        let expiring = mgr.getExpiringNotes()
        XCTAssertEqual(expiring.count, 2)
        XCTAssertEqual(Set(expiring.map { $0.value }), [100, 200])
    }

    func testSelectNotesForRenewal() {
        let mgr = NoteManager()
        mgr.setCurrentEpoch(10)

        mgr.addNote(makeNote(value: 100, epoch: 8, leafIndex: 0))
        mgr.addNote(makeNote(value: 200, epoch: 9, leafIndex: 0))

        let forRenewal = mgr.selectNotesForRenewal()
        XCTAssertEqual(forRenewal.count, 2)
        XCTAssertEqual(forRenewal.first?.epoch, 8, "Oldest epoch first")
    }

    // MARK: - Note Creation

    func testCreateNote() throws {
        let km = KeyManager.fromSeed(Data(0..<32))
        let mgr = NoteManager(spendingKeys: km.exportKeys())
        mgr.setCurrentEpoch(5)

        let note = try mgr.createNote(value: 1_000_000, owner: km.shieldedAddress)
        XCTAssertEqual(note.value, 1_000_000)
        XCTAssertEqual(note.owner, km.shieldedAddress)
        XCTAssertEqual(note.commitment.count, 32)
        XCTAssertEqual(note.epoch, 5)
        XCTAssertEqual(note.randomness.count, 32)
        XCTAssertFalse(note.spent)
    }

    // MARK: - Encrypt/Decrypt Note

    func testEncryptDecryptNoteRoundtrip() throws {
        let km = KeyManager.fromSeed(Data(0..<32))
        let mgr = NoteManager(spendingKeys: km.exportKeys())
        mgr.setCurrentEpoch(1)

        let note = try mgr.createNote(value: 1_000_000, owner: km.shieldedAddress)

        // Encrypt
        let encrypted = try NoteManager.encryptNote(note, viewingKey: km.viewingKey)
        XCTAssertTrue(encrypted.count > 12) // nonce + ciphertext + tag

        // Decrypt
        let decrypted = NoteManager.decryptNote(
            encryptedData: encrypted,
            viewingKey: km.viewingKey,
            token: note.token,
            leafIndex: 0,
            epoch: 1
        )
        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted?.value, 1_000_000)
        XCTAssertEqual(decrypted?.owner, km.shieldedAddress)
    }

    func testDecryptWithWrongKeyReturnsNil() throws {
        let km = KeyManager.fromSeed(Data(0..<32))
        let mgr = NoteManager(spendingKeys: km.exportKeys())
        let note = try mgr.createNote(value: 1_000_000, owner: km.shieldedAddress)

        let encrypted = try NoteManager.encryptNote(note, viewingKey: km.viewingKey)

        let wrongKey = Crypto.sha256(Data("wrong-key".utf8))
        let result = NoteManager.decryptNote(
            encryptedData: encrypted,
            viewingKey: wrongKey,
            token: note.token
        )
        XCTAssertNil(result, "Decryption with wrong key should return nil")
    }

    // MARK: - Clear & Prune

    func testClear() {
        let mgr = NoteManager()
        mgr.addNote(makeNote(value: 1000, epoch: 1, leafIndex: 0))
        mgr.addPendingNote(makeNote(value: 500))

        mgr.clear()
        XCTAssertEqual(mgr.getNotes().count, 0)
        XCTAssertEqual(mgr.getPendingNotes().count, 0)
    }
}

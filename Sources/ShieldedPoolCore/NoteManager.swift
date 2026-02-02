import Foundation
import BigInt

/// Warning threshold for expiring notes (2 epochs before expiration)
private let RENEWAL_WARNING_EPOCHS: UInt64 = 2

/// Default epoch duration in slots
private let DEFAULT_EPOCH_DURATION_SLOTS: UInt64 = 3_024_000

/// Default epoch expiry in slots (~6 months)
private let DEFAULT_EPOCH_EXPIRY_SLOTS: UInt64 = 38_880_000

/// Manages note collection with epoch awareness, selection, and balance tracking
public class NoteManager {
    
    /// All confirmed notes
    private var notes: [Note] = []
    
    /// Pending (unconfirmed) notes
    private var pendingNotes: [Note] = []
    
    /// Spending keys for nullifier computation
    private var spendingKeys: SpendingKeys?
    
    /// Current epoch number
    private var currentEpoch: UInt64 = 0
    
    /// Epoch expiry duration in slots
    private let epochExpirySlots: UInt64
    
    /// Initialize NoteManager
    /// - Parameters:
    ///   - spendingKeys: Optional spending keys for nullifier computation
    ///   - epochExpirySlots: Optional custom expiry duration
    public init(spendingKeys: SpendingKeys? = nil, epochExpirySlots: UInt64? = nil) {
        self.spendingKeys = spendingKeys
        self.epochExpirySlots = epochExpirySlots ?? DEFAULT_EPOCH_EXPIRY_SLOTS
    }
    
    // MARK: - Epoch Management
    
    /// Update the current epoch (called when syncing with chain)
    public func setCurrentEpoch(_ epoch: UInt64) {
        currentEpoch = epoch
    }
    
    /// Get the current epoch
    public func getCurrentEpoch() -> UInt64 {
        return currentEpoch
    }
    
    // MARK: - Note Management
    
    /// Add a confirmed note to the collection
    public func addNote(_ note: Note) {
        // Check for existing note by commitment
        if let index = notes.firstIndex(where: { $0.commitment == note.commitment }) {
            // Update epoch and leafIndex if not set
            if notes[index].epoch == nil && note.epoch != nil {
                notes[index].epoch = note.epoch
            }
            if notes[index].leafIndex == nil && note.leafIndex != nil {
                notes[index].leafIndex = note.leafIndex
            }
            return
        }
        
        notes.append(note)
        
        // Remove from pending if exists
        pendingNotes.removeAll { $0.commitment == note.commitment }
    }
    
    /// Add a pending (unconfirmed) note
    public func addPendingNote(_ note: Note) {
        guard !pendingNotes.contains(where: { $0.commitment == note.commitment }) else {
            return
        }
        pendingNotes.append(note)
    }
    
    /// Get all pending notes
    public func getPendingNotes() -> [Note] {
        return pendingNotes
    }
    
    /// Get all unspent notes
    public func getNotes() -> [Note] {
        return notes.filter { !$0.spent }
    }
    
    /// Get notes by epoch
    public func getNotesByEpoch(_ epoch: UInt64) -> [Note] {
        return notes.filter { !$0.spent && $0.epoch == epoch }
    }
    
    /// Get a note by commitment
    public func getNote(commitment: Data) -> Note? {
        return notes.first { $0.commitment == commitment }
    }
    
    // MARK: - Expiration Tracking
    
    /// Get notes that are expiring (within warning threshold)
    public func getExpiringNotes() -> [Note] {
        let expiryThreshold = currentEpoch + RENEWAL_WARNING_EPOCHS
        return notes.filter { note in
            guard !note.spent else { return false }
            let noteEpoch = note.epoch ?? 0
            return noteEpoch <= expiryThreshold && noteEpoch < currentEpoch
        }
    }
    
    /// Get notes that have expired and cannot be spent
    public func getExpiredNotes() -> [Note] {
        let expiryEpochs = epochExpirySlots / DEFAULT_EPOCH_DURATION_SLOTS
        let expiredBefore = currentEpoch > expiryEpochs ? currentEpoch - expiryEpochs : 0
        
        return notes.filter { note in
            guard !note.spent else { return false }
            let noteEpoch = note.epoch ?? 0
            return noteEpoch < expiredBefore
        }
    }
    
    // MARK: - Spending
    
    /// Mark a note as spent by commitment
    public func markSpent(commitment: Data) {
        if let index = notes.firstIndex(where: { $0.commitment == commitment }) {
            notes[index].spent = true
        }
    }
    
    /// Mark notes as spent by nullifier
    public func markSpentByNullifier(_ nullifier: Data, epoch: UInt64? = nil) {
        guard spendingKeys != nil else { return }
        
        for i in 0..<notes.count {
            guard !notes[i].spent else { continue }
            
            // If epoch specified, only check notes from that epoch
            if let epoch = epoch, notes[i].epoch != epoch {
                continue
            }
            
            if notes[i].nullifier == nullifier {
                notes[i].spent = true
                break
            }
        }
    }
    
    // MARK: - Note Creation
    
    /// Create a new note with the given parameters
    /// - Parameters:
    ///   - value: Token amount
    ///   - owner: Owner's shielded address (32 bytes)
    ///   - token: Optional token mint address
    /// - Returns: New note (epoch and leafIndex set on confirmation)
    public func createNote(
        value: UInt64,
        owner: Data,
        token: Data? = nil
    ) throws -> Note {
        let randomness = Crypto.randomBytes(32)
        let commitment = try Crypto.computeCommitment(
            value: value,
            owner: owner,
            randomness: randomness
        )
        
        // Compute placeholder nullifier
        var nullifier = Data(count: 32)
        if let keys = spendingKeys {
            nullifier = try Crypto.computeNullifier(
                commitment: commitment,
                nullifierKey: keys.nullifierKey,
                epoch: currentEpoch,
                leafIndex: 0 // Placeholder until confirmed
            )
        }
        
        return Note(
            value: value,
            token: token ?? Data(count: 32),
            owner: owner,
            blinding: randomness,
            memo: nil,
            commitment: commitment,
            leafIndex: nil,
            epoch: currentEpoch, // Tentative, updated on confirmation
            nullifier: nullifier,
            randomness: randomness,
            spent: false,
            expired: false
        )
    }
    
    /// Recompute nullifier for a note after confirmation
    public func recomputeNullifier(for note: inout Note) throws {
        guard let keys = spendingKeys else { return }
        guard let epoch = note.epoch, let leafIndex = note.leafIndex else { return }
        
        note.nullifier = try Crypto.computeNullifier(
            commitment: note.commitment,
            nullifierKey: keys.nullifierKey,
            epoch: epoch,
            leafIndex: leafIndex
        )
    }
    
    // MARK: - Note Selection
    
    /// Select notes for spending (greedy algorithm)
    /// Prioritizes notes from older epochs to encourage renewal
    /// - Parameters:
    ///   - amount: Target amount to select
    ///   - minNotes: Minimum number of notes to select
    /// - Returns: Selected notes
    public func selectNotes(amount: UInt64, minNotes: Int = 1) throws -> [Note] {
        guard minNotes >= 1 else {
            throw NoteManagerError.invalidMinNotes
        }
        
        // Deduplicate by commitment
        var seenCommitments = Set<Data>()
        let unspent = notes
            .filter { !$0.spent }
            .filter { note in
                if seenCommitments.contains(note.commitment) {
                    return false
                }
                seenCommitments.insert(note.commitment)
                return true
            }
            // Sort by epoch ascending (older first), then by value descending
            .sorted { a, b in
                let epochA = a.epoch ?? 0
                let epochB = b.epoch ?? 0
                if epochA != epochB {
                    return epochA < epochB
                }
                return a.value > b.value
            }
        
        var selected: [Note] = []
        var sum: UInt64 = 0
        
        for note in unspent {
            selected.append(note)
            sum += note.value
            if sum >= amount && selected.count >= minNotes {
                return selected
            }
        }
        
        if sum < amount {
            throw NoteManagerError.insufficientBalance(have: sum, need: amount)
        }
        
        throw NoteManagerError.insufficientNotes(have: selected.count, need: minNotes)
    }
    
    /// Select notes specifically for renewal (oldest epochs first)
    public func selectNotesForRenewal(maxNotes: Int = 10) -> [Note] {
        return getExpiringNotes()
            .sorted { ($0.epoch ?? 0) < ($1.epoch ?? 0) }
            .prefix(maxNotes)
            .map { $0 }
    }
    
    // MARK: - Balance Calculation
    
    /// Calculate total unspent balance
    public func calculateBalance() -> UInt64 {
        return notes
            .filter { !$0.spent }
            .reduce(0) { $0 + $1.value }
    }
    
    /// Calculate pending balance
    public func calculatePendingBalance() -> UInt64 {
        return pendingNotes.reduce(0) { $0 + $1.value }
    }
    
    /// Calculate detailed balance breakdown
    public func calculateBalanceInfo() -> BalanceInfo {
        let unspent = notes.filter { !$0.spent }
        let expiredNotes = getExpiredNotes()
        let expiringNotes = getExpiringNotes()
        
        let expiredSet = Set(expiredNotes.map { $0.commitment })
        let expiringSet = Set(expiringNotes.map { $0.commitment })
        
        var spendable: UInt64 = 0
        let pending = calculatePendingBalance()
        var expiring: UInt64 = 0
        var expired: UInt64 = 0
        
        for note in unspent {
            if expiredSet.contains(note.commitment) {
                expired += note.value
            } else if expiringSet.contains(note.commitment) {
                expiring += note.value
            } else {
                spendable += note.value
            }
        }
        
        let total = spendable + pending + expiring
        
        // Find earliest expiring epoch
        let earliestExpiry = expiringNotes
            .compactMap { $0.epoch }
            .min()
        
        return BalanceInfo(
            total: total,
            spendable: spendable,
            pending: pending,
            expiring: expiring,
            expired: expired,
            noteCount: unspent.count,
            expiringNoteCount: expiringNotes.count,
            expiredNoteCount: expiredNotes.count,
            earliestExpiry: earliestExpiry
        )
    }
    
    // MARK: - Note Encryption/Decryption
    
    /// Encrypt a note for on-chain storage
    public static func encryptNote(_ note: Note, viewingKey: Data) throws -> Data {
        let serialized = Crypto.serializeNote(
            value: note.value,
            token: note.token,
            owner: note.owner,
            blinding: note.blinding,
            memo: note.memo
        )
        
        let (encrypted, nonce) = try Crypto.encryptNote(
            noteData: serialized,
            viewingKey: viewingKey
        )
        
        // Prepend nonce to encrypted data
        return nonce + encrypted
    }
    
    /// Attempt to decrypt a note (returns nil if not owner)
    public static func decryptNote(
        encryptedData: Data,
        viewingKey: Data,
        token: Data,
        leafIndex: UInt32? = nil,
        epoch: UInt64? = nil
    ) -> Note? {
        guard encryptedData.count > 12 else { return nil }
        
        // Extract nonce (first 12 bytes for ChaChaPoly)
        let nonce = Data(encryptedData.prefix(12))
        let ciphertext = Data(encryptedData.dropFirst(12))
        
        guard let decrypted = Crypto.decryptNote(
            encryptedData: ciphertext,
            nonce: nonce,
            viewingKey: viewingKey
        ) else {
            return nil
        }
        
        // Deserialize note
        guard let deserializedNote = try? Crypto.deserializeNote(decrypted) else {
            return nil
        }
        
        // Build Note from deserialized data
        // Commitment will need to be recomputed
        guard let commitment = try? Crypto.computeCommitment(
            value: deserializedNote.value,
            owner: deserializedNote.owner,
            randomness: deserializedNote.blinding
        ) else {
            return nil
        }
        
        return Note(
            value: deserializedNote.value,
            token: token,
            owner: deserializedNote.owner,
            blinding: deserializedNote.blinding,
            memo: deserializedNote.memo,
            commitment: commitment,
            leafIndex: leafIndex,
            epoch: epoch,
            nullifier: Data(count: 32), // Will be computed with nullifier key
            randomness: deserializedNote.blinding,
            spent: false,
            expired: false
        )
    }
    
    // MARK: - Cleanup
    
    /// Clear all notes
    public func clear() {
        notes.removeAll()
        pendingNotes.removeAll()
    }
    
    /// Remove expired notes from tracking
    public func pruneExpiredNotes() {
        let expiredSet = Set(getExpiredNotes().map { $0.commitment })
        notes.removeAll { expiredSet.contains($0.commitment) }
    }
}

// MARK: - Note Manager Errors

public enum NoteManagerError: Error, CustomStringConvertible {
    case invalidMinNotes
    case insufficientBalance(have: UInt64, need: UInt64)
    case insufficientNotes(have: Int, need: Int)
    case noteNotFound
    
    public var description: String {
        switch self {
        case .invalidMinNotes:
            return "minNotes must be at least 1"
        case .insufficientBalance(let have, let need):
            return "Insufficient balance: have \(have), need \(need)"
        case .insufficientNotes(let have, let need):
            return "Insufficient note count: have \(have), need \(need)"
        case .noteNotFound:
            return "Note not found"
        }
    }
}

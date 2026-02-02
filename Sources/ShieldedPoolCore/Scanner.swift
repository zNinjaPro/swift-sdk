import Foundation
import BigInt

// MARK: - Event Discriminators

/// Event discriminators for parsing Solana transaction logs
/// These are the Anchor event discriminators from the shielded pool program
public struct EventDiscriminators {
    // V2 epoch-aware events
    public static let depositV2 = Data([0xa4, 0xd6, 0x2a, 0x2f, 0x25, 0xf5, 0x58, 0x6a])
    public static let withdrawV2 = Data([0xe7, 0xe7, 0x67, 0x4f, 0xbb, 0x93, 0x72, 0xb4])
    public static let transferV2 = Data([0x5c, 0x93, 0xfe, 0x4c, 0x44, 0xc9, 0xa0, 0x80])
    public static let renewV2 = Data([0x97, 0x7e, 0x4e, 0x25, 0x5c, 0x7d, 0x9e, 0xa7])
    public static let epochRollover = Data([0x12, 0xb3, 0x4a, 0x7f, 0x81, 0x5c, 0x2e, 0x9f])
    public static let epochFinalized = Data([0x3f, 0xa9, 0x8c, 0x12, 0x67, 0x4b, 0xd1, 0xe3])
    
    // Legacy V1 events (for historical data)
    public static let depositV1 = Data([0x24, 0x3b, 0xfc, 0xe9, 0xbf, 0x2c, 0x37, 0x4a])
    public static let withdrawV1 = Data([0xcd, 0x8c, 0xcd, 0x79, 0xbf, 0x9c, 0x25, 0x7d])
    public static let transferV1 = Data([0x84, 0x93, 0xfa, 0x63, 0xd2, 0x8c, 0x51, 0x3e])
}

// MARK: - Parsed Events

/// Parsed deposit event from on-chain data
public struct DepositEvent {
    public let epoch: UInt64
    public let poolId: Data
    public let commitment: Data
    public let leafIndex: UInt32
    public let newRoot: Data
    public let encryptedNote: Data
}

/// Parsed withdraw event from on-chain data
public struct WithdrawEvent {
    public let epoch: UInt64
    public let poolId: Data
    public let nullifier: Data
    public let amount: UInt64
    public let recipient: Data
}

/// Parsed transfer event from on-chain data
public struct TransferEvent {
    public let outputEpoch: UInt64
    public let poolId: Data
    public let nullifiers: [Data]
    public let inputEpochs: [UInt64]
    public let commitments: [Data]
    public let leafIndices: [UInt32]
    public let encryptedNotes: [Data]
}

/// Parsed renewal event from on-chain data
public struct RenewEvent {
    public let sourceEpoch: UInt64
    public let targetEpoch: UInt64
    public let poolId: Data
    public let nullifier: Data
    public let commitment: Data
    public let leafIndex: UInt32
    public let encryptedNote: Data
}

/// Parsed epoch rollover event
public struct EpochRolloverEvent {
    public let previousEpoch: UInt64
    public let newEpoch: UInt64
    public let poolId: Data
}

/// Parsed epoch finalized event
public struct EpochFinalizedEvent {
    public let epoch: UInt64
    public let poolId: Data
    public let merkleRoot: Data
}

// MARK: - Event Parser

/// Parser for shielded pool events from Solana transaction logs
public class EventParser {
    
    /// Try to parse a deposit event from raw event data
    public static func parseDepositV2(_ data: Data) -> DepositEvent? {
        // Layout: discriminator(8) | epoch(8) | pool_id(32) | cm(32) | leaf_index(8) | new_root(32) | enc_note(Vec<u8>)
        let minimum = 8 + 8 + 32 + 32 + 8 + 32 + 4
        guard data.count >= minimum else { return nil }
        
        var cursor = 8 // skip discriminator
        
        let epoch = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) }
        cursor += 8
        
        let poolId = data[cursor..<(cursor + 32)]
        cursor += 32
        
        let commitment = data[cursor..<(cursor + 32)]
        cursor += 32
        
        let leafIndex = UInt32(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) })
        cursor += 8
        
        let newRoot = data[cursor..<(cursor + 32)]
        cursor += 32
        
        guard data.count >= cursor + 4 else { return nil }
        let encLen = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) }
        cursor += 4
        
        guard data.count >= cursor + Int(encLen) else { return nil }
        let encryptedNote = data[cursor..<(cursor + Int(encLen))]
        
        return DepositEvent(
            epoch: epoch,
            poolId: Data(poolId),
            commitment: Data(commitment),
            leafIndex: leafIndex,
            newRoot: Data(newRoot),
            encryptedNote: Data(encryptedNote)
        )
    }
    
    /// Try to parse a withdraw event from raw event data
    public static func parseWithdrawV2(_ data: Data) -> WithdrawEvent? {
        // Layout: discriminator(8) | epoch(8) | pool_id(32) | nullifier(32) | amount(8) | recipient(32)
        let minimum = 8 + 8 + 32 + 32 + 8 + 32
        guard data.count >= minimum else { return nil }
        
        var cursor = 8
        
        let epoch = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) }
        cursor += 8
        
        let poolId = data[cursor..<(cursor + 32)]
        cursor += 32
        
        let nullifier = data[cursor..<(cursor + 32)]
        cursor += 32
        
        let amount = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) }
        cursor += 8
        
        let recipient = data[cursor..<(cursor + 32)]
        
        return WithdrawEvent(
            epoch: epoch,
            poolId: Data(poolId),
            nullifier: Data(nullifier),
            amount: amount,
            recipient: Data(recipient)
        )
    }
    
    /// Try to parse a transfer event from raw event data
    public static func parseTransferV2(_ data: Data) -> TransferEvent? {
        // Layout: discriminator(8) | output_epoch(8) | pool_id(32) |
        //         nullifiers(Vec<[u8;32]>) | input_epochs(Vec<u64>) |
        //         commitments(Vec<[u8;32]>) | leaf_indices(Vec<u64>) | enc_notes(Vec<Vec<u8>>)
        let minimum = 8 + 8 + 32 + 4
        guard data.count >= minimum else { return nil }
        
        var cursor = 8
        
        let outputEpoch = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) }
        cursor += 8
        
        let poolId = data[cursor..<(cursor + 32)]
        cursor += 32
        
        // Read nullifiers vector
        guard data.count >= cursor + 4 else { return nil }
        let nfLen = Int(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) })
        cursor += 4
        
        var nullifiers: [Data] = []
        for _ in 0..<nfLen {
            guard data.count >= cursor + 32 else { return nil }
            nullifiers.append(Data(data[cursor..<(cursor + 32)]))
            cursor += 32
        }
        
        // Read input epochs vector
        guard data.count >= cursor + 4 else { return nil }
        let epochLen = Int(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) })
        cursor += 4
        
        var inputEpochs: [UInt64] = []
        for _ in 0..<epochLen {
            guard data.count >= cursor + 8 else { return nil }
            let epoch = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) }
            inputEpochs.append(epoch)
            cursor += 8
        }
        
        // Read commitments vector
        guard data.count >= cursor + 4 else { return nil }
        let cmLen = Int(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) })
        cursor += 4
        
        var commitments: [Data] = []
        for _ in 0..<cmLen {
            guard data.count >= cursor + 32 else { return nil }
            commitments.append(Data(data[cursor..<(cursor + 32)]))
            cursor += 32
        }
        
        // Read leaf indices vector
        guard data.count >= cursor + 4 else { return nil }
        let idxLen = Int(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) })
        cursor += 4
        
        var leafIndices: [UInt32] = []
        for _ in 0..<idxLen {
            guard data.count >= cursor + 8 else { return nil }
            let idx = UInt32(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) })
            leafIndices.append(idx)
            cursor += 8
        }
        
        // Read encrypted notes vector
        guard data.count >= cursor + 4 else { return nil }
        let encNotesLen = Int(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) })
        cursor += 4
        
        var encryptedNotes: [Data] = []
        for _ in 0..<encNotesLen {
            guard data.count >= cursor + 4 else { return nil }
            let noteLen = Int(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) })
            cursor += 4
            guard data.count >= cursor + noteLen else { return nil }
            encryptedNotes.append(Data(data[cursor..<(cursor + noteLen)]))
            cursor += noteLen
        }
        
        return TransferEvent(
            outputEpoch: outputEpoch,
            poolId: Data(poolId),
            nullifiers: nullifiers,
            inputEpochs: inputEpochs,
            commitments: commitments,
            leafIndices: leafIndices,
            encryptedNotes: encryptedNotes
        )
    }
    
    /// Try to parse a renewal event from raw event data
    public static func parseRenewV2(_ data: Data) -> RenewEvent? {
        // Layout: discriminator(8) | source_epoch(8) | target_epoch(8) | pool_id(32) |
        //         nullifier(32) | commitment(32) | leaf_index(8) | enc_note(Vec<u8>)
        let minimum = 8 + 8 + 8 + 32 + 32 + 32 + 8 + 4
        guard data.count >= minimum else { return nil }
        
        var cursor = 8
        
        let sourceEpoch = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) }
        cursor += 8
        
        let targetEpoch = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) }
        cursor += 8
        
        let poolId = data[cursor..<(cursor + 32)]
        cursor += 32
        
        let nullifier = data[cursor..<(cursor + 32)]
        cursor += 32
        
        let commitment = data[cursor..<(cursor + 32)]
        cursor += 32
        
        let leafIndex = UInt32(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) })
        cursor += 8
        
        guard data.count >= cursor + 4 else { return nil }
        let encLen = Int(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) })
        cursor += 4
        
        guard data.count >= cursor + encLen else { return nil }
        let encryptedNote = data[cursor..<(cursor + encLen)]
        
        return RenewEvent(
            sourceEpoch: sourceEpoch,
            targetEpoch: targetEpoch,
            poolId: Data(poolId),
            nullifier: Data(nullifier),
            commitment: Data(commitment),
            leafIndex: leafIndex,
            encryptedNote: Data(encryptedNote)
        )
    }
    
    /// Parse epoch rollover event
    public static func parseEpochRollover(_ data: Data) -> EpochRolloverEvent? {
        // Layout: discriminator(8) | previous_epoch(8) | new_epoch(8) | pool_id(32)
        let minimum = 8 + 8 + 8 + 32
        guard data.count >= minimum else { return nil }
        
        var cursor = 8
        
        let previousEpoch = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) }
        cursor += 8
        
        let newEpoch = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) }
        cursor += 8
        
        let poolId = data[cursor..<(cursor + 32)]
        
        return EpochRolloverEvent(
            previousEpoch: previousEpoch,
            newEpoch: newEpoch,
            poolId: Data(poolId)
        )
    }
    
    /// Parse epoch finalized event
    public static func parseEpochFinalized(_ data: Data) -> EpochFinalizedEvent? {
        // Layout: discriminator(8) | epoch(8) | pool_id(32) | merkle_root(32)
        let minimum = 8 + 8 + 32 + 32
        guard data.count >= minimum else { return nil }
        
        var cursor = 8
        
        let epoch = data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) }
        cursor += 8
        
        let poolId = data[cursor..<(cursor + 32)]
        cursor += 32
        
        let merkleRoot = data[cursor..<(cursor + 32)]
        
        return EpochFinalizedEvent(
            epoch: epoch,
            poolId: Data(poolId),
            merkleRoot: Data(merkleRoot)
        )
    }
}

// MARK: - UTXO Scanner

/// Callback protocols for scanner events
public protocol ScannerDelegate: AnyObject {
    func scanner(_ scanner: UTXOScanner, didReceiveDeposit event: DepositEvent, note: Note?)
    func scanner(_ scanner: UTXOScanner, didReceiveWithdraw event: WithdrawEvent)
    func scanner(_ scanner: UTXOScanner, didReceiveTransfer event: TransferEvent, notes: [Note])
    func scanner(_ scanner: UTXOScanner, didReceiveRenewal event: RenewEvent, note: Note?)
    func scanner(_ scanner: UTXOScanner, didReceiveEpochRollover event: EpochRolloverEvent)
    func scanner(_ scanner: UTXOScanner, didReceiveEpochFinalized event: EpochFinalizedEvent)
    func scanner(_ scanner: UTXOScanner, didEncounterError error: ScannerError)
}

/// Default implementations for optional delegate methods
public extension ScannerDelegate {
    func scanner(_ scanner: UTXOScanner, didReceiveDeposit event: DepositEvent, note: Note?) {}
    func scanner(_ scanner: UTXOScanner, didReceiveWithdraw event: WithdrawEvent) {}
    func scanner(_ scanner: UTXOScanner, didReceiveTransfer event: TransferEvent, notes: [Note]) {}
    func scanner(_ scanner: UTXOScanner, didReceiveRenewal event: RenewEvent, note: Note?) {}
    func scanner(_ scanner: UTXOScanner, didReceiveEpochRollover event: EpochRolloverEvent) {}
    func scanner(_ scanner: UTXOScanner, didReceiveEpochFinalized event: EpochFinalizedEvent) {}
    func scanner(_ scanner: UTXOScanner, didEncounterError error: ScannerError) {}
}

/// Scans for UTXOs owned by a viewing key
public class UTXOScanner {
    
    /// Viewing key for decrypting notes
    private let viewingKey: Data
    
    /// Token mint address
    private let tokenMint: Data
    
    /// Note manager for tracking UTXOs
    private var noteManager: NoteManager?
    
    /// Pool ID being scanned
    private let poolId: Data
    
    /// Delegate for receiving events
    public weak var delegate: ScannerDelegate?
    
    /// Current epoch number
    private var currentEpoch: UInt64 = 0
    
    /// Initialize scanner
    /// - Parameters:
    ///   - viewingKey: Key for decrypting notes
    ///   - tokenMint: Token mint address
    ///   - poolId: Pool ID to scan
    ///   - noteManager: Optional note manager for UTXO tracking
    public init(
        viewingKey: Data,
        tokenMint: Data,
        poolId: Data,
        noteManager: NoteManager? = nil
    ) {
        self.viewingKey = viewingKey
        self.tokenMint = tokenMint
        self.poolId = poolId
        self.noteManager = noteManager
    }
    
    /// Set the note manager
    public func setNoteManager(_ manager: NoteManager) {
        self.noteManager = manager
    }
    
    /// Update current epoch
    public func setCurrentEpoch(_ epoch: UInt64) {
        self.currentEpoch = epoch
        noteManager?.setCurrentEpoch(epoch)
    }
    
    // MARK: - Log Processing
    
    /// Process transaction logs to extract events
    /// - Parameter logs: Array of log strings from Solana transaction
    public func processTransactionLogs(_ logs: [String]) {
        for log in logs {
            guard log.contains("Program data:") else { continue }
            
            // Extract base64 data from log
            guard let range = log.range(of: "Program data: "),
                  let dataString = log[range.upperBound...].split(separator: " ").first else {
                continue
            }
            
            guard let eventData = Data(base64Encoded: String(dataString)),
                  eventData.count >= 8 else {
                continue
            }
            
            processEventData(eventData)
        }
    }
    
    /// Process raw event data from a transaction
    public func processEventData(_ data: Data) {
        guard data.count >= 8 else { return }
        
        let discriminator = data.prefix(8)
        
        // V2 epoch-aware events
        if discriminator == EventDiscriminators.depositV2 {
            handleDepositV2(data)
        } else if discriminator == EventDiscriminators.withdrawV2 {
            handleWithdrawV2(data)
        } else if discriminator == EventDiscriminators.transferV2 {
            handleTransferV2(data)
        } else if discriminator == EventDiscriminators.renewV2 {
            handleRenewV2(data)
        } else if discriminator == EventDiscriminators.epochRollover {
            handleEpochRollover(data)
        } else if discriminator == EventDiscriminators.epochFinalized {
            handleEpochFinalized(data)
        }
        // Legacy V1 events
        else if discriminator == EventDiscriminators.depositV1 {
            handleDepositV1(data)
        } else if discriminator == EventDiscriminators.withdrawV1 {
            handleWithdrawV1(data)
        } else if discriminator == EventDiscriminators.transferV1 {
            handleTransferV1(data)
        }
    }
    
    // MARK: - V2 Event Handlers
    
    private func handleDepositV2(_ data: Data) {
        guard let event = EventParser.parseDepositV2(data) else { return }
        
        // Try to decrypt the note
        let note = tryDecryptNote(
            encryptedData: event.encryptedNote,
            commitment: event.commitment,
            leafIndex: event.leafIndex,
            epoch: event.epoch
        )
        
        if let note = note {
            noteManager?.addNote(note)
        }
        
        delegate?.scanner(self, didReceiveDeposit: event, note: note)
    }
    
    private func handleWithdrawV2(_ data: Data) {
        guard let event = EventParser.parseWithdrawV2(data) else { return }
        
        noteManager?.markSpentByNullifier(event.nullifier, epoch: event.epoch)
        delegate?.scanner(self, didReceiveWithdraw: event)
    }
    
    private func handleTransferV2(_ data: Data) {
        guard let event = EventParser.parseTransferV2(data) else { return }
        
        // Mark inputs as spent
        for (i, nullifier) in event.nullifiers.enumerated() {
            let epoch = i < event.inputEpochs.count ? event.inputEpochs[i] : 0
            noteManager?.markSpentByNullifier(nullifier, epoch: epoch)
        }
        
        // Try to decrypt output notes
        var decryptedNotes: [Note] = []
        for (i, commitment) in event.commitments.enumerated() {
            let encryptedNote = i < event.encryptedNotes.count ? event.encryptedNotes[i] : Data()
            let leafIndex = i < event.leafIndices.count ? event.leafIndices[i] : 0
            
            if let note = tryDecryptNote(
                encryptedData: encryptedNote,
                commitment: commitment,
                leafIndex: leafIndex,
                epoch: event.outputEpoch
            ) {
                decryptedNotes.append(note)
                noteManager?.addNote(note)
            }
        }
        
        delegate?.scanner(self, didReceiveTransfer: event, notes: decryptedNotes)
    }
    
    private func handleRenewV2(_ data: Data) {
        guard let event = EventParser.parseRenewV2(data) else { return }
        
        // Mark old note as spent
        noteManager?.markSpentByNullifier(event.nullifier, epoch: event.sourceEpoch)
        
        // Try to decrypt renewed note
        let note = tryDecryptNote(
            encryptedData: event.encryptedNote,
            commitment: event.commitment,
            leafIndex: event.leafIndex,
            epoch: event.targetEpoch
        )
        
        if let note = note {
            noteManager?.addNote(note)
        }
        
        delegate?.scanner(self, didReceiveRenewal: event, note: note)
    }
    
    private func handleEpochRollover(_ data: Data) {
        guard let event = EventParser.parseEpochRollover(data) else { return }
        
        currentEpoch = event.newEpoch
        noteManager?.setCurrentEpoch(event.newEpoch)
        
        delegate?.scanner(self, didReceiveEpochRollover: event)
    }
    
    private func handleEpochFinalized(_ data: Data) {
        guard let event = EventParser.parseEpochFinalized(data) else { return }
        delegate?.scanner(self, didReceiveEpochFinalized: event)
    }
    
    // MARK: - V1 Legacy Handlers (simplified)
    
    private func handleDepositV1(_ data: Data) {
        // V1 deposits have no epoch - process with epoch 0
        // Layout: discriminator(8) | version(1) | pool_id(32) | chain_id(32) | cm(32) | leaf_index(8) | ...
        let minimum = 8 + 1 + 32 + 32 + 32 + 8 + 32 + 32 + 16 + 4
        guard data.count >= minimum else { return }
        
        var cursor = 8 + 1 + 32 + 32 // skip to commitment
        let commitment = Data(data[cursor..<(cursor + 32)])
        cursor += 32
        
        let leafIndex = UInt32(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt64.self) })
        cursor += 8 + 32 + 32 + 16 // skip to enc_note length
        
        guard data.count >= cursor + 4 else { return }
        let encLen = Int(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) })
        cursor += 4
        
        guard data.count >= cursor + encLen else { return }
        let encryptedNote = Data(data[cursor..<(cursor + encLen)])
        
        let note = tryDecryptNote(
            encryptedData: encryptedNote,
            commitment: commitment,
            leafIndex: leafIndex,
            epoch: 0
        )
        
        if let note = note {
            noteManager?.addNote(note)
        }
    }
    
    private func handleWithdrawV1(_ data: Data) {
        // V1 withdraws - mark nullifiers as spent
        let baseOffset = 8 + 1 + 32 + 32 + 32 + 32 + 32
        guard data.count >= baseOffset + 1 else { return }
        
        let _ = Int(data[baseOffset]) // nIn (reserved for future use)
        var cursor = baseOffset + 1
        
        guard data.count >= cursor + 4 else { return }
        let nfLen = Int(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) })
        cursor += 4
        
        for i in 0..<nfLen {
            let start = cursor + i * 32
            guard start + 32 <= data.count else { break }
            let nullifier = Data(data[start..<(start + 32)])
            noteManager?.markSpentByNullifier(nullifier)
        }
    }
    
    private func handleTransferV1(_ data: Data) {
        // V1 transfers - mark nullifiers as spent
        let baseOffset = 8 + 1 + 32 + 32 + 32 + 32 + 32
        guard data.count >= baseOffset + 2 else { return }
        
        let _ = Int(data[baseOffset]) // nIn (reserved for future use)
        let _ = Int(data[baseOffset + 1]) // nOut (reserved for future use)
        var cursor = baseOffset + 2
        
        guard data.count >= cursor + 4 else { return }
        let nfLen = Int(data.withUnsafeBytes { $0.load(fromByteOffset: cursor, as: UInt32.self) })
        cursor += 4
        
        for i in 0..<nfLen {
            let start = cursor + i * 32
            guard start + 32 <= data.count else { break }
            let nullifier = Data(data[start..<(start + 32)])
            noteManager?.markSpentByNullifier(nullifier)
        }
    }
    
    // MARK: - Note Decryption
    
    /// Try to decrypt a note using the viewing key
    private func tryDecryptNote(
        encryptedData: Data,
        commitment: Data,
        leafIndex: UInt32,
        epoch: UInt64
    ) -> Note? {
        return NoteManager.decryptNote(
            encryptedData: encryptedData,
            viewingKey: viewingKey,
            token: tokenMint,
            leafIndex: leafIndex,
            epoch: epoch
        )
    }
}

// MARK: - Scanner Errors

public enum ScannerError: Error, CustomStringConvertible {
    case invalidEventData
    case decryptionFailed
    case parseError(String)
    case networkError(String)
    
    public var description: String {
        switch self {
        case .invalidEventData:
            return "Invalid event data format"
        case .decryptionFailed:
            return "Failed to decrypt note"
        case .parseError(let msg):
            return "Parse error: \(msg)"
        case .networkError(let msg):
            return "Network error: \(msg)"
        }
    }
}

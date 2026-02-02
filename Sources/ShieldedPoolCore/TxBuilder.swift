import Foundation
import BigInt

// MARK: - Constants

/// PDA seeds for deriving program addresses
public struct PDASeed {
    public static let poolConfig = "pool_config"
    public static let epochTree = "epoch_tree"
    public static let leafChunk = "leaves"
    public static let vaultAuthority = "vault_authority"
    public static let nullifierMarker = "nullifier"
    public static let verifierConfig = "verifier"
}

/// Merkle configuration constants
public struct MerkleConfig {
    public static let depth: Int = 12
    public static let maxLeaves: Int = 4096
    public static let leavesPerChunk: Int = 256
}

// MARK: - Prepared Transaction Data

/// Data prepared for a deposit transaction
public struct PreparedDeposit {
    /// Encrypted note data (nonce + ciphertext)
    public let encryptedNote: Data
    
    /// Note commitment
    public let commitment: Data
    
    /// Deposit amount in lamports
    public let amount: UInt64
    
    /// Epoch to deposit into
    public let epoch: UInt64
    
    /// The output note (for pending tracking)
    public let outputNote: Note
    
    public init(
        encryptedNote: Data,
        commitment: Data,
        amount: UInt64,
        epoch: UInt64,
        outputNote: Note
    ) {
        self.encryptedNote = encryptedNote
        self.commitment = commitment
        self.amount = amount
        self.epoch = epoch
        self.outputNote = outputNote
    }
}

/// Data prepared for a withdrawal transaction
public struct PreparedWithdraw {
    /// ZK proof bytes (a || b || c)
    public let proof: Data
    
    /// Public inputs for verification
    public let publicInputs: [Data]
    
    /// Nullifier being spent
    public let nullifier: Data
    
    /// Withdrawal amount
    public let amount: UInt64
    
    /// Epoch of the spent note
    public let epoch: UInt64
    
    /// Leaf index of the spent note
    public let leafIndex: UInt32
    
    /// Recipient address (32 bytes)
    public let recipient: Data
    
    public init(
        proof: Data,
        publicInputs: [Data],
        nullifier: Data,
        amount: UInt64,
        epoch: UInt64,
        leafIndex: UInt32,
        recipient: Data
    ) {
        self.proof = proof
        self.publicInputs = publicInputs
        self.nullifier = nullifier
        self.amount = amount
        self.epoch = epoch
        self.leafIndex = leafIndex
        self.recipient = recipient
    }
}

/// Data prepared for a shielded transfer transaction
public struct PreparedTransfer {
    /// ZK proof bytes (a || b || c)
    public let proof: Data
    
    /// Public inputs for verification
    public let publicInputs: [Data]
    
    /// Input nullifiers (2 for 2-in-2-out transfer)
    public let inputNullifiers: [Data]
    
    /// Input epochs
    public let inputEpochs: [UInt64]
    
    /// Input leaf indices
    public let inputLeafIndices: [UInt32]
    
    /// Output commitments
    public let outputCommitments: [Data]
    
    /// Encrypted output notes
    public let encryptedOutputs: [Data]
    
    /// Output epoch
    public let outputEpoch: UInt64
    
    /// Output notes (for pending tracking)
    public let outputNotes: [Note]
    
    public init(
        proof: Data,
        publicInputs: [Data],
        inputNullifiers: [Data],
        inputEpochs: [UInt64],
        inputLeafIndices: [UInt32],
        outputCommitments: [Data],
        encryptedOutputs: [Data],
        outputEpoch: UInt64,
        outputNotes: [Note]
    ) {
        self.proof = proof
        self.publicInputs = publicInputs
        self.inputNullifiers = inputNullifiers
        self.inputEpochs = inputEpochs
        self.inputLeafIndices = inputLeafIndices
        self.outputCommitments = outputCommitments
        self.encryptedOutputs = encryptedOutputs
        self.outputEpoch = outputEpoch
        self.outputNotes = outputNotes
    }
}

/// Data prepared for a renewal transaction
public struct PreparedRenew {
    /// ZK proof bytes (a || b || c)
    public let proof: Data
    
    /// Public inputs for verification
    public let publicInputs: [Data]
    
    /// Nullifier of old note being spent
    public let oldNullifier: Data
    
    /// Commitment of new note
    public let newCommitment: Data
    
    /// Encrypted new note
    public let encryptedNote: Data
    
    /// Source (old) epoch
    public let sourceEpoch: UInt64
    
    /// Source leaf index
    public let sourceLeafIndex: UInt32
    
    /// Target (new) epoch
    public let targetEpoch: UInt64
    
    /// New note (for pending tracking)
    public let newNote: Note
    
    public init(
        proof: Data,
        publicInputs: [Data],
        oldNullifier: Data,
        newCommitment: Data,
        encryptedNote: Data,
        sourceEpoch: UInt64,
        sourceLeafIndex: UInt32,
        targetEpoch: UInt64,
        newNote: Note
    ) {
        self.proof = proof
        self.publicInputs = publicInputs
        self.oldNullifier = oldNullifier
        self.newCommitment = newCommitment
        self.encryptedNote = encryptedNote
        self.sourceEpoch = sourceEpoch
        self.sourceLeafIndex = sourceLeafIndex
        self.targetEpoch = targetEpoch
        self.newNote = newNote
    }
}

// MARK: - Transaction Builder

/// Builds shielded pool transaction data for Solana
public class TxBuilder {
    
    /// Prover for ZK proofs
    private let prover: ZKProver
    
    /// Pool ID
    private let poolId: Data
    
    /// Token mint address (32 bytes)
    private let tokenMint: Data
    
    /// Current epoch
    private var currentEpoch: UInt64 = 0
    
    /// Initialize transaction builder
    /// - Parameters:
    ///   - prover: ZK prover instance
    ///   - poolId: Shielded pool ID (32 bytes)
    ///   - tokenMint: Token mint address (32 bytes)
    public init(prover: ZKProver, poolId: Data, tokenMint: Data) {
        self.prover = prover
        self.poolId = poolId
        self.tokenMint = tokenMint
    }
    
    /// Update current epoch
    public func setCurrentEpoch(_ epoch: UInt64) {
        self.currentEpoch = epoch
    }
    
    // MARK: - Deposit
    
    /// Prepare a deposit transaction
    /// - Parameters:
    ///   - amount: Amount to deposit in lamports
    ///   - recipientAddress: Shielded address of recipient (32 bytes)
    ///   - viewingKey: Viewing key for encryption
    /// - Returns: Prepared deposit data
    public func prepareDeposit(
        amount: UInt64,
        recipientAddress: Data,
        viewingKey: Data
    ) throws -> PreparedDeposit {
        // Create output note
        let randomness = Crypto.randomBytes(32)
        let commitment = try Crypto.computeCommitment(
            value: amount,
            owner: recipientAddress,
            randomness: randomness
        )
        
        let outputNote = Note(
            value: amount,
            token: tokenMint,
            owner: recipientAddress,
            blinding: randomness,
            memo: nil,
            commitment: commitment,
            leafIndex: nil,
            epoch: currentEpoch,
            nullifier: Data(count: 32),
            randomness: randomness,
            spent: false,
            expired: false
        )
        
        // Serialize and encrypt note
        let serialized = Crypto.serializeNote(
            value: amount,
            token: tokenMint,
            owner: recipientAddress,
            blinding: randomness,
            memo: nil
        )
        
        let (encrypted, nonce) = try Crypto.encryptNote(
            noteData: serialized,
            viewingKey: viewingKey
        )
        
        // Prepend nonce to encrypted data
        let encryptedNote = nonce + encrypted
        
        return PreparedDeposit(
            encryptedNote: encryptedNote,
            commitment: commitment,
            amount: amount,
            epoch: currentEpoch,
            outputNote: outputNote
        )
    }
    
    // MARK: - Withdraw
    
    /// Prepare a withdrawal transaction
    /// - Parameters:
    ///   - inputNote: Note to spend
    ///   - spendingKeys: Keys for spending
    ///   - recipient: Recipient public key (32 bytes)
    ///   - amount: Amount to withdraw
    ///   - merkleTree: Epoch Merkle tree containing the note
    /// - Returns: Prepared withdrawal data
    public func prepareWithdraw(
        inputNote: Note,
        spendingKeys: SpendingKeys,
        recipient: Data,
        amount: UInt64,
        merkleTree: EpochMerkleTree
    ) async throws -> PreparedWithdraw {
        guard let epoch = inputNote.epoch else {
            throw TxBuilderError.noteNotConfirmed
        }
        guard let leafIndex = inputNote.leafIndex else {
            throw TxBuilderError.noteNotConfirmed
        }
        
        // Validate epoch matches tree
        guard epoch == merkleTree.epoch else {
            throw TxBuilderError.epochMismatch(noteEpoch: epoch, treeEpoch: merkleTree.epoch)
        }
        
        // Get Merkle proof
        let merkleProof = try merkleTree.getProof(leafIndex: Int(leafIndex))
        let merkleRoot = merkleTree.getRoot()
        
        // Compute nullifier
        let nullifier = try Crypto.computeNullifier(
            commitment: inputNote.commitment,
            nullifierKey: spendingKeys.nullifierKey,
            epoch: epoch,
            leafIndex: leafIndex
        )
        
        // Generate ZK proof
        let inputs = WithdrawInputs(
            note: inputNote,
            spendingKeys: spendingKeys,
            merkleProof: merkleProof,
            merkleRoot: merkleRoot,
            recipient: recipient,
            amount: amount,
            epoch: epoch,
            leafIndex: leafIndex
        )
        
        let proofResult = try await prover.proveWithdraw(inputs)
        
        // Serialize proof
        let proofBytes = proofResult.proof.a + proofResult.proof.b + proofResult.proof.c
        
        return PreparedWithdraw(
            proof: proofBytes,
            publicInputs: proofResult.publicInputs,
            nullifier: nullifier,
            amount: amount,
            epoch: epoch,
            leafIndex: leafIndex,
            recipient: recipient
        )
    }
    
    // MARK: - Transfer
    
    /// Prepare a shielded transfer transaction
    /// - Parameters:
    ///   - inputNotes: Notes to spend (max 2)
    ///   - outputs: Output recipients and amounts
    ///   - spendingKeys: Keys for spending
    ///   - epochTrees: Map of epoch -> Merkle tree
    /// - Returns: Prepared transfer data
    public func prepareTransfer(
        inputNotes: [Note],
        outputs: [(address: Data, amount: UInt64)],
        spendingKeys: SpendingKeys,
        epochTrees: [UInt64: EpochMerkleTree]
    ) async throws -> PreparedTransfer {
        // Pad inputs to 2
        var inputs = inputNotes
        while inputs.count < 2 {
            inputs.append(createDummyNote())
        }
        guard inputs.count == 2 else {
            throw TxBuilderError.tooManyInputs
        }
        
        // Create output notes
        var outputNotes: [Note] = []
        var encryptedOutputs: [Data] = []
        
        for output in outputs.prefix(2) {
            let randomness = Crypto.randomBytes(32)
            let commitment = try Crypto.computeCommitment(
                value: output.amount,
                owner: output.address,
                randomness: randomness
            )
            
            let note = Note(
                value: output.amount,
                token: tokenMint,
                owner: output.address,
                blinding: randomness,
                memo: nil,
                commitment: commitment,
                leafIndex: nil,
                epoch: currentEpoch,
                nullifier: Data(count: 32),
                randomness: randomness,
                spent: false,
                expired: false
            )
            outputNotes.append(note)
            
            // Encrypt note
            let serialized = Crypto.serializeNote(
                value: output.amount,
                token: tokenMint,
                owner: output.address,
                blinding: randomness,
                memo: nil
            )
            let (encrypted, nonce) = try Crypto.encryptNote(
                noteData: serialized,
                viewingKey: output.address
            )
            encryptedOutputs.append(nonce + encrypted)
        }
        
        // Pad outputs to 2
        while outputNotes.count < 2 {
            let dummyNote = createDummyNote()
            outputNotes.append(dummyNote)
            encryptedOutputs.append(Data(count: 64)) // Empty encrypted data
        }
        
        // Get Merkle proofs and compute nullifiers
        var inputNullifiers: [Data] = []
        var inputEpochs: [UInt64] = []
        var inputLeafIndices: [UInt32] = []
        var merkleProofs: [MerkleProof] = []
        
        for input in inputs {
            let epoch = input.epoch ?? 0
            let leafIndex = input.leafIndex ?? 0
            inputEpochs.append(epoch)
            inputLeafIndices.append(leafIndex)
            
            // Get tree for this epoch
            guard let tree = epochTrees[epoch] ?? epochTrees[currentEpoch] else {
                throw TxBuilderError.epochTreeNotFound(epoch: epoch)
            }
            
            // Get proof
            let proof = try tree.getProof(leafIndex: Int(leafIndex))
            merkleProofs.append(proof)
            
            // Compute nullifier
            let nullifier = try Crypto.computeNullifier(
                commitment: input.commitment,
                nullifierKey: spendingKeys.nullifierKey,
                epoch: epoch,
                leafIndex: leafIndex
            )
            inputNullifiers.append(nullifier)
        }
        
        // Get root from first input's tree
        let merkleRoot = epochTrees[inputEpochs[0]]?.getRoot() ?? Data(count: 32)
        
        // Generate ZK proof
        let transferInputs = TransferInputs(
            inputNotes: (inputs[0], inputs[1]),
            spendingKeys: spendingKeys,
            outputNotes: (outputNotes[0], outputNotes[1]),
            merkleProofs: (merkleProofs[0], merkleProofs[1]),
            merkleRoot: merkleRoot,
            epoch: currentEpoch,
            inputLeafIndices: (inputLeafIndices[0], inputLeafIndices[1])
        )
        
        let proofResult = try await prover.proveTransfer(transferInputs)
        let proofBytes = proofResult.proof.a + proofResult.proof.b + proofResult.proof.c
        
        return PreparedTransfer(
            proof: proofBytes,
            publicInputs: proofResult.publicInputs,
            inputNullifiers: inputNullifiers,
            inputEpochs: inputEpochs,
            inputLeafIndices: inputLeafIndices,
            outputCommitments: outputNotes.map { $0.commitment },
            encryptedOutputs: encryptedOutputs,
            outputEpoch: currentEpoch,
            outputNotes: outputNotes
        )
    }
    
    // MARK: - Renew
    
    /// Prepare a renewal transaction to migrate a note to the current epoch
    /// - Parameters:
    ///   - oldNote: Note to renew
    ///   - spendingKeys: Keys for spending
    ///   - viewingKey: Viewing key for encryption
    ///   - oldTree: Merkle tree for old epoch
    /// - Returns: Prepared renewal data
    public func prepareRenew(
        oldNote: Note,
        spendingKeys: SpendingKeys,
        viewingKey: Data,
        oldTree: EpochMerkleTree
    ) async throws -> PreparedRenew {
        guard let oldEpoch = oldNote.epoch else {
            throw TxBuilderError.noteNotConfirmed
        }
        guard let oldLeafIndex = oldNote.leafIndex else {
            throw TxBuilderError.noteNotConfirmed
        }
        
        // Validate old epoch is older than current
        guard oldEpoch < currentEpoch else {
            throw TxBuilderError.renewNotNeeded
        }
        
        // Create new note with same value
        let randomness = Crypto.randomBytes(32)
        let commitment = try Crypto.computeCommitment(
            value: oldNote.value,
            owner: oldNote.owner,
            randomness: randomness
        )
        
        let newNote = Note(
            value: oldNote.value,
            token: tokenMint,
            owner: oldNote.owner,
            blinding: randomness,
            memo: oldNote.memo,
            commitment: commitment,
            leafIndex: nil,
            epoch: currentEpoch,
            nullifier: Data(count: 32),
            randomness: randomness,
            spent: false,
            expired: false
        )
        
        // Encrypt new note
        let serialized = Crypto.serializeNote(
            value: newNote.value,
            token: tokenMint,
            owner: newNote.owner,
            blinding: randomness,
            memo: newNote.memo
        )
        let (encrypted, nonce) = try Crypto.encryptNote(
            noteData: serialized,
            viewingKey: viewingKey
        )
        let encryptedNote = nonce + encrypted
        
        // Get Merkle proof for old note
        let merkleProof = try oldTree.getProof(leafIndex: Int(oldLeafIndex))
        let merkleRoot = oldTree.getRoot()
        
        // Compute old nullifier
        let oldNullifier = try Crypto.computeNullifier(
            commitment: oldNote.commitment,
            nullifierKey: spendingKeys.nullifierKey,
            epoch: oldEpoch,
            leafIndex: oldLeafIndex
        )
        
        // Generate ZK proof
        let renewInputs = RenewInputs(
            oldNote: oldNote,
            newNote: newNote,
            spendingKeys: spendingKeys,
            merkleProof: merkleProof,
            merkleRoot: merkleRoot,
            poolId: poolId,
            oldEpoch: oldEpoch,
            newEpoch: currentEpoch,
            oldLeafIndex: oldLeafIndex
        )
        
        let proofResult = try await prover.proveRenew(renewInputs)
        let proofBytes = proofResult.proof.a + proofResult.proof.b + proofResult.proof.c
        
        return PreparedRenew(
            proof: proofBytes,
            publicInputs: proofResult.publicInputs,
            oldNullifier: oldNullifier,
            newCommitment: commitment,
            encryptedNote: encryptedNote,
            sourceEpoch: oldEpoch,
            sourceLeafIndex: oldLeafIndex,
            targetEpoch: currentEpoch,
            newNote: newNote
        )
    }
    
    // MARK: - Helpers
    
    /// Create a dummy note for padding
    private func createDummyNote() -> Note {
        return Note(
            value: 0,
            token: Data(count: 32),
            owner: Data(count: 32),
            blinding: Data(count: 32),
            memo: nil,
            commitment: Data(count: 32),
            leafIndex: 0,
            epoch: 0,
            nullifier: Data(count: 32),
            randomness: Data(count: 32),
            spent: false,
            expired: false
        )
    }
    
    /// Validate note conservation (sum of inputs == sum of outputs)
    public func validateConservation(
        inputNotes: [Note],
        outputValues: [UInt64],
        fee: UInt64 = 0
    ) throws {
        let inputSum = inputNotes.reduce(0) { $0 + $1.value }
        let outputSum = outputValues.reduce(0, +) + fee
        
        guard inputSum == outputSum else {
            throw TxBuilderError.conservationViolation(
                inputs: inputSum,
                outputs: outputSum
            )
        }
    }
}

// MARK: - Renew Inputs (for prover)

/// Inputs for renewal proof generation
public struct RenewInputs {
    public let oldNote: Note
    public let newNote: Note
    public let spendingKeys: SpendingKeys
    public let merkleProof: MerkleProof
    public let merkleRoot: Data
    public let poolId: Data
    public let oldEpoch: UInt64
    public let newEpoch: UInt64
    public let oldLeafIndex: UInt32
    
    public init(
        oldNote: Note,
        newNote: Note,
        spendingKeys: SpendingKeys,
        merkleProof: MerkleProof,
        merkleRoot: Data,
        poolId: Data,
        oldEpoch: UInt64,
        newEpoch: UInt64,
        oldLeafIndex: UInt32
    ) {
        self.oldNote = oldNote
        self.newNote = newNote
        self.spendingKeys = spendingKeys
        self.merkleProof = merkleProof
        self.merkleRoot = merkleRoot
        self.poolId = poolId
        self.oldEpoch = oldEpoch
        self.newEpoch = newEpoch
        self.oldLeafIndex = oldLeafIndex
    }
}

// MARK: - Transaction Builder Errors

public enum TxBuilderError: Error, CustomStringConvertible {
    case noteNotConfirmed
    case epochMismatch(noteEpoch: UInt64, treeEpoch: UInt64)
    case epochTreeNotFound(epoch: UInt64)
    case tooManyInputs
    case renewNotNeeded
    case conservationViolation(inputs: UInt64, outputs: UInt64)
    case proofGenerationFailed(String)
    
    public var description: String {
        switch self {
        case .noteNotConfirmed:
            return "Note has not been confirmed (missing epoch or leafIndex)"
        case .epochMismatch(let noteEpoch, let treeEpoch):
            return "Note epoch \(noteEpoch) does not match tree epoch \(treeEpoch)"
        case .epochTreeNotFound(let epoch):
            return "Merkle tree not found for epoch \(epoch)"
        case .tooManyInputs:
            return "Maximum 2 input notes allowed per transfer"
        case .renewNotNeeded:
            return "Note is already in current epoch, renewal not needed"
        case .conservationViolation(let inputs, let outputs):
            return "Value conservation violated: inputs=\(inputs), outputs=\(outputs)"
        case .proofGenerationFailed(let reason):
            return "Proof generation failed: \(reason)"
        }
    }
}

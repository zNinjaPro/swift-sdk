import Foundation

/// Constants for the epoch-based shielded pool
public enum Constants {
    /// BN254 field size for public inputs
    public static let bn254FieldSize = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    
    /// BN254 prime as hex string
    public static let bn254PrimeHex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
    
    /// Merkle tree depth per epoch (2^12 = 4,096 deposits per epoch)
    public static let merkleDepth = 12
    
    /// Number of leaves per EpochLeafChunk PDA
    public static let leafChunkSize = 256
    
    /// Size of a BN254 scalar in bytes
    public static let scalarSize = 32
    
    /// Size of a commitment in bytes
    public static let commitmentSize = 32
    
    /// Size of a nullifier in bytes
    public static let nullifierSize = 32
    
    /// Size of an encrypted note tag
    public static let tagSize = 16
    
    /// Default epoch duration in slots (~2 weeks at 400ms slots)
    public static let defaultEpochDurationSlots: UInt64 = 3_024_000
    
    /// Default grace period before epoch can be garbage collected (~6 months)
    public static let defaultEpochExpirySlots: UInt64 = 38_880_000
    
    /// Default finalization delay after epoch ends (~1 day)
    public static let defaultFinalizationDelaySlots: UInt64 = 216_000
}

/// Epoch state enum matching on-chain representation
public enum EpochState: UInt8, Codable, Sendable {
    /// Epoch is active and accepting deposits
    case active = 0
    /// Epoch is frozen, no more deposits, pending finalization
    case frozen = 1
    /// Epoch is finalized with committed root, can be spent from
    case finalized = 2
}

/// Information about an epoch
public struct EpochInfo: Codable, Sendable {
    /// Epoch number
    public let epoch: UInt64
    /// Slot when epoch started
    public let startSlot: UInt64
    /// Slot when epoch ended (0 if still active)
    public let endSlot: UInt64
    /// Slot when epoch was finalized (0 if not finalized)
    public let finalizedSlot: UInt64
    /// Current state of the epoch
    public let state: EpochState
    /// Finalized merkle root (zero if not finalized)
    public let finalRoot: Data
    /// Number of deposits in this epoch
    public let depositCount: UInt32
    /// Slot when epoch will expire (can be garbage collected)
    public let expirySlot: UInt64
    
    public init(
        epoch: UInt64,
        startSlot: UInt64,
        endSlot: UInt64,
        finalizedSlot: UInt64,
        state: EpochState,
        finalRoot: Data,
        depositCount: UInt32,
        expirySlot: UInt64
    ) {
        self.epoch = epoch
        self.startSlot = startSlot
        self.endSlot = endSlot
        self.finalizedSlot = finalizedSlot
        self.state = state
        self.finalRoot = finalRoot
        self.depositCount = depositCount
        self.expirySlot = expirySlot
    }
}

/// Represents a note (UTXO) in the shielded pool
public struct Note: Codable, Sendable {
    /// Token amount (in lamports/smallest unit)
    public var value: UInt64
    
    /// Token mint address (32 bytes)
    public var token: Data
    
    /// Shielded address of the owner (32 bytes)
    public var owner: Data
    
    /// Random blinding factor for commitment
    public var blinding: Data
    
    /// Optional memo/message
    public var memo: String?
    
    /// Commitment: Hash(value, token, owner, randomness) - used as leaf in tree
    public var commitment: Data
    
    /// Position in Merkle tree within the epoch (set on confirmation)
    public var leafIndex: UInt32?
    
    /// Epoch this note belongs to (set on confirmation)
    public var epoch: UInt64?
    
    /// Nullifier: Hash(commitment, nullifierKey, epoch, leafIndex)
    public var nullifier: Data
    
    /// Random entropy for commitment
    public var randomness: Data
    
    /// Whether this note has been spent
    public var spent: Bool
    
    /// Whether this note is in an expired epoch (needs renewal)
    public var expired: Bool
    
    public init(
        value: UInt64,
        token: Data,
        owner: Data,
        blinding: Data,
        memo: String? = nil,
        commitment: Data = Data(count: 32),
        leafIndex: UInt32? = nil,
        epoch: UInt64? = nil,
        nullifier: Data = Data(count: 32),
        randomness: Data,
        spent: Bool = false,
        expired: Bool = false
    ) {
        self.value = value
        self.token = token
        self.owner = owner
        self.blinding = blinding
        self.memo = memo
        self.commitment = commitment
        self.leafIndex = leafIndex
        self.epoch = epoch
        self.nullifier = nullifier
        self.randomness = randomness
        self.spent = spent
        self.expired = expired
    }
}

/// Spending keys derived from master seed
public struct SpendingKeys: Sendable {
    /// Master seed (32 bytes)
    public let seed: Data
    
    /// Spending key for signing transactions
    public let spendingKey: Data
    
    /// Viewing key for decrypting notes
    public let viewingKey: Data
    
    /// Nullifier key for generating nullifiers
    public let nullifierKey: Data
    
    /// Public shielded address (derived from keys)
    public let shieldedAddress: Data
    
    public init(
        seed: Data,
        spendingKey: Data,
        viewingKey: Data,
        nullifierKey: Data,
        shieldedAddress: Data
    ) {
        self.seed = seed
        self.spendingKey = spendingKey
        self.viewingKey = viewingKey
        self.nullifierKey = nullifierKey
        self.shieldedAddress = shieldedAddress
    }
}

/// Merkle proof for a leaf in an epoch tree
public struct MerkleProof: Codable, Sendable {
    /// Leaf value (commitment)
    public let leaf: Data
    
    /// Leaf index in epoch tree
    public let leafIndex: UInt32
    
    /// Epoch this proof is for
    public let epoch: UInt64
    
    /// Sibling hashes from leaf to root (MERKLE_DEPTH levels)
    public let siblings: [Data]
    
    /// Computed or finalized root
    public let root: Data
    
    public init(
        leaf: Data,
        leafIndex: UInt32,
        epoch: UInt64,
        siblings: [Data],
        root: Data
    ) {
        self.leaf = leaf
        self.leafIndex = leafIndex
        self.epoch = epoch
        self.siblings = siblings
        self.root = root
    }
}

/// Balance information with epoch details
public struct BalanceInfo: Sendable {
    /// Total balance (spendable + pending + expiring, excludes expired)
    public let total: UInt64
    
    /// Total spendable balance (in finalized, non-expired epochs)
    public let spendable: UInt64
    
    /// Balance in active epoch (pending finalization)
    public let pending: UInt64
    
    /// Balance in epochs approaching expiry (needs renewal)
    public let expiring: UInt64
    
    /// Balance in expired epochs (lost if not renewed)
    public let expired: UInt64
    
    /// Total number of unspent notes
    public let noteCount: Int
    
    /// Number of notes in expiring epochs
    public let expiringNoteCount: Int
    
    /// Number of notes in expired epochs
    public let expiredNoteCount: Int
    
    /// Earliest expiry slot for any note
    public let earliestExpiry: UInt64?
    
    public init(
        total: UInt64,
        spendable: UInt64,
        pending: UInt64,
        expiring: UInt64,
        expired: UInt64,
        noteCount: Int,
        expiringNoteCount: Int,
        expiredNoteCount: Int,
        earliestExpiry: UInt64?
    ) {
        self.total = total
        self.spendable = spendable
        self.pending = pending
        self.expiring = expiring
        self.expired = expired
        self.noteCount = noteCount
        self.expiringNoteCount = expiringNoteCount
        self.expiredNoteCount = expiredNoteCount
        self.earliestExpiry = earliestExpiry
    }
}

/// Groth16 proof structure
public struct Groth16Proof: Codable, Sendable {
    public let a: Data
    public let b: Data
    public let c: Data
    
    public init(a: Data, b: Data, c: Data) {
        self.a = a
        self.b = b
        self.c = c
    }
}

/// Prover output containing proof and public inputs
public struct ProverOutput: Sendable {
    public let proof: Groth16Proof
    public let publicInputs: [Data]
    
    public init(proof: Groth16Proof, publicInputs: [Data]) {
        self.proof = proof
        self.publicInputs = publicInputs
    }
}

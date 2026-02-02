import Foundation
import BigInt

/// Merkle tree depth constant
private let MERKLE_DEPTH = 12

/// Pre-computed zero hashes for depth 12 merkle tree
/// z[0] = 0, z[i] = Poseidon(z[i-1], z[i-1])
/// Cross-validated against TS SDK (sdk/dist/poseidon/solanaPoseidon.js)
private let ZERO_HASHES_DEPTH_12: [String] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
    "1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
    "18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
    "07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
    "2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
    "2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
    "078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
    "2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
    "0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
    "1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
    "1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
    // Level 12 (root of empty tree)
    "2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
]

/// Epoch-aware Merkle tree for the shielded pool
/// Depth = 12 (4,096 leaves per epoch)
public class EpochMerkleTree {
    
    /// Maximum number of leaves (2^12 = 4096)
    public static let maxLeaves = 1 << MERKLE_DEPTH
    
    /// The epoch this tree belongs to
    public let epoch: UInt64
    
    /// Current state of the epoch
    public private(set) var state: EpochState = .active
    
    /// Final root (set when epoch is finalized)
    public private(set) var finalRoot: Data?
    
    /// Leaves stored by index
    private var leaves: [Int: Data] = [:]
    
    /// Pre-computed zero hashes for each level
    private var zeroHashes: [Data] = []
    
    /// History of roots (after each insert)
    private var roots: [Data] = []
    
    /// Next available leaf index
    private var nextIndex: Int = 0
    
    /// Initialize a new Merkle tree for an epoch
    public init(epoch: UInt64) {
        self.epoch = epoch
        initZeroHashes()
    }
    
    /// Initialize zero hashes from precomputed constants
    private func initZeroHashes() {
        zeroHashes = ZERO_HASHES_DEPTH_12.map { hex in
            Data(hexString: hex) ?? Data(repeating: 0, count: 32)
        }
    }
    
    /// Get the current epoch state
    public func getState() -> EpochState {
        return state
    }
    
    /// Set the epoch state
    public func setState(_ newState: EpochState) {
        state = newState
    }
    
    /// Set the final root (for finalized epochs)
    public func setFinalRoot(_ root: Data) {
        finalRoot = root
        state = .finalized
    }
    
    /// Get the final root (for finalized epochs)
    public func getFinalRoot() -> Data? {
        return finalRoot
    }
    
    /// Insert a leaf and return (leafIndex, newRoot)
    /// - Parameter leaf: The 32-byte commitment to insert
    /// - Returns: Tuple of (leafIndex, newRoot)
    /// - Throws: If epoch is not active or tree is full
    public func insert(_ leaf: Data) throws -> (leafIndex: Int, root: Data) {
        guard state == .active else {
            throw MerkleError.epochNotActive(epoch: epoch, state: state)
        }
        
        guard nextIndex < Self.maxLeaves else {
            throw MerkleError.treeFull(epoch: epoch, maxLeaves: Self.maxLeaves)
        }
        
        let leafIndex = nextIndex
        leaves[leafIndex] = leaf
        nextIndex += 1
        
        let root = computeRoot()
        roots.append(root)
        
        return (leafIndex, root)
    }
    
    /// Bulk insert leaves (for syncing from chain)
    /// - Parameter newLeaves: Array of 32-byte commitments
    public func insertMany(_ newLeaves: [Data]) {
        for leaf in newLeaves {
            leaves[nextIndex] = leaf
            nextIndex += 1
        }
        // Only compute root once at the end
        if !newLeaves.isEmpty {
            roots.append(computeRoot())
        }
    }
    
    /// Compute the current Merkle root
    public func computeRoot() -> Data {
        // Level 0: initialize with existing leaves (sparse)
        var levelNodes: [Data] = []
        for i in 0..<nextIndex {
            levelNodes.append(leaves[i]!)
        }
        
        var currentCount = nextIndex
        
        // Build up to MERKLE_DEPTH, padding with zero hashes as needed
        for level in 0..<MERKLE_DEPTH {
            var nextLevel: [Data] = []
            let levelSize = max(1, (currentCount + 1) / 2)
            
            for i in 0..<levelSize {
                let leftIdx = i * 2
                let rightIdx = i * 2 + 1
                
                let left = leftIdx < levelNodes.count ? levelNodes[leftIdx] : zeroHashes[level]
                let right = rightIdx < levelNodes.count ? levelNodes[rightIdx] : zeroHashes[level]
                
                nextLevel.append(hashNodes(left, right))
            }
            
            levelNodes = nextLevel
            currentCount = levelNodes.count
        }
        
        return levelNodes.first ?? zeroHashes[MERKLE_DEPTH]
    }
    
    /// Get Merkle proof for a leaf
    /// - Parameter leafIndex: Index of the leaf to prove
    /// - Returns: MerkleProof containing siblings and path
    /// - Throws: If leaf not found
    public func getProof(leafIndex: Int) throws -> MerkleProof {
        guard let leaf = leaves[leafIndex] else {
            throw MerkleError.leafNotFound(index: leafIndex, epoch: epoch)
        }
        
        var siblings: [Data] = []
        
        // Build level-by-level arrays
        var levelNodes: [Data] = []
        for i in 0..<nextIndex {
            levelNodes.append(leaves[i]!)
        }
        
        var currentIndex = leafIndex
        for level in 0..<MERKLE_DEPTH {
            let isLeft = currentIndex % 2 == 0
            let siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1
            
            let sibling: Data
            if siblingIndex >= 0 && siblingIndex < levelNodes.count {
                sibling = levelNodes[siblingIndex]
            } else {
                sibling = zeroHashes[level]
            }
            siblings.append(sibling)
            
            var nextLevel: [Data] = []
            let levelSize = max(1, (levelNodes.count + 1) / 2)
            for i in 0..<levelSize {
                let leftIdx = i * 2
                let rightIdx = i * 2 + 1
                
                let left = leftIdx < levelNodes.count ? levelNodes[leftIdx] : zeroHashes[level]
                let right = rightIdx < levelNodes.count ? levelNodes[rightIdx] : zeroHashes[level]
                
                nextLevel.append(hashNodes(left, right))
            }
            
            levelNodes = nextLevel
            currentIndex = currentIndex / 2
        }
        
        let root = finalRoot ?? levelNodes.first ?? zeroHashes[MERKLE_DEPTH]
        
        return MerkleProof(
            leaf: leaf,
            leafIndex: UInt32(leafIndex),
            epoch: epoch,
            siblings: siblings,
            root: root
        )
    }
    
    /// Verify a Merkle proof
    /// - Parameter proof: The proof to verify
    /// - Returns: true if proof is valid
    public static func verifyProof(_ proof: MerkleProof) -> Bool {
        var current = proof.leaf
        var index = Int(proof.leafIndex)
        
        for sibling in proof.siblings {
            if index % 2 == 0 {
                current = hashNodesStatic(current, sibling)
            } else {
                current = hashNodesStatic(sibling, current)
            }
            index = index / 2
        }
        
        return current == proof.root
    }
    
    /// Static hash function for use in static methods
    private static func hashNodesStatic(_ left: Data, _ right: Data) -> Data {
        return (try? Poseidon.hash2(left, right)) ?? Data(repeating: 0, count: 32)
    }
    
    /// Check if a root exists in the root history
    public func isKnownRoot(_ root: Data) -> Bool {
        if let fr = finalRoot, fr == root {
            return true
        }
        return roots.contains(root)
    }
    
    /// Get current root (or final root if finalized)
    public func getRoot() -> Data {
        if let fr = finalRoot {
            return fr
        }
        return roots.last ?? zeroHashes[MERKLE_DEPTH]
    }
    
    /// Get next leaf index
    public func getNextIndex() -> Int {
        return nextIndex
    }
    
    /// Get a leaf by index
    public func getLeaf(_ index: Int) -> Data? {
        return leaves[index]
    }
    
    /// Find leaf index for a commitment
    public func findLeafIndex(_ commitment: Data) -> Int? {
        for i in 0..<nextIndex {
            if let leaf = leaves[i], leaf == commitment {
                return i
            }
        }
        return nil
    }
    
    /// Clear all data
    public func clear() {
        leaves.removeAll()
        roots.removeAll()
        nextIndex = 0
        finalRoot = nil
        state = .active
    }
    
    /// Get the number of leaves currently in the tree
    public var leafCount: Int {
        return nextIndex
    }
    
    // MARK: - Private Helpers
    
    /// Hash two nodes using Poseidon (matches on-chain program and circuit)
    private func hashNodes(_ left: Data, _ right: Data) -> Data {
        return (try? Poseidon.hash2(left, right)) ?? Data(repeating: 0, count: 32)
    }
}

// MARK: - Merkle Errors

public enum MerkleError: Error, CustomStringConvertible {
    case epochNotActive(epoch: UInt64, state: EpochState)
    case treeFull(epoch: UInt64, maxLeaves: Int)
    case leafNotFound(index: Int, epoch: UInt64)
    
    public var description: String {
        switch self {
        case .epochNotActive(let epoch, let state):
            return "Cannot insert into epoch \(epoch) with state \(state)"
        case .treeFull(let epoch, let maxLeaves):
            return "Epoch \(epoch) is full (\(maxLeaves) leaves)"
        case .leafNotFound(let index, let epoch):
            return "Leaf \(index) not found in epoch \(epoch)"
        }
    }
}

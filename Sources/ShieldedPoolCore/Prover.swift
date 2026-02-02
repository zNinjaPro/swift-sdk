import Foundation
import BigInt

// Note: This file provides the prover interface for ZK proofs.
// It requires the rapidsnark and witnesscalc frameworks to be integrated.
// 
// Integration options:
// 1. CocoaPods: pod 'rapidsnark' (from iden3/ios-rapidsnark)
// 2. SPM: Add https://github.com/nicklash/ios-rapidsnark as a dependency
//
// For witness calculation, you need witnesscalc compiled for your circuit.
// See: https://github.com/nicklash/circom-witnesscalc-swift

/// Circuit types supported by the prover
public enum CircuitType: String, Sendable {
    case withdraw = "withdraw"
    case transfer = "transfer"
    case joinsplit = "joinsplit"
    case renew = "renew"
}

/// Prover configuration
public struct ProverConfig: Sendable {
    /// Path to the .zkey file for proving
    public let zkeyPath: String
    /// Path to the .witnesscalc file for witness generation (native)
    public let witnesscalcPath: String?
    /// Circuit type
    public let circuitType: CircuitType
    
    public init(
        zkeyPath: String,
        witnesscalcPath: String? = nil,
        circuitType: CircuitType
    ) {
        self.zkeyPath = zkeyPath
        self.witnesscalcPath = witnesscalcPath
        self.circuitType = circuitType
    }
}

/// Withdraw circuit inputs
public struct WithdrawInputs: Sendable {
    public let note: Note
    public let spendingKeys: SpendingKeys
    public let merkleProof: MerkleProof
    public let merkleRoot: Data
    public let recipient: Data // 32-byte recipient pubkey
    public let amount: UInt64
    public let epoch: UInt64
    public let leafIndex: UInt32
    
    public init(
        note: Note,
        spendingKeys: SpendingKeys,
        merkleProof: MerkleProof,
        merkleRoot: Data,
        recipient: Data,
        amount: UInt64,
        epoch: UInt64,
        leafIndex: UInt32
    ) {
        self.note = note
        self.spendingKeys = spendingKeys
        self.merkleProof = merkleProof
        self.merkleRoot = merkleRoot
        self.recipient = recipient
        self.amount = amount
        self.epoch = epoch
        self.leafIndex = leafIndex
    }
}

/// Transfer circuit inputs (2-in, 2-out)
public struct TransferInputs: Sendable {
    public let inputNotes: (Note, Note)
    public let spendingKeys: SpendingKeys
    public let outputNotes: (Note, Note)
    public let merkleProofs: (MerkleProof, MerkleProof)
    public let merkleRoot: Data
    public let epoch: UInt64
    public let inputLeafIndices: (UInt32, UInt32)
    
    public init(
        inputNotes: (Note, Note),
        spendingKeys: SpendingKeys,
        outputNotes: (Note, Note),
        merkleProofs: (MerkleProof, MerkleProof),
        merkleRoot: Data,
        epoch: UInt64,
        inputLeafIndices: (UInt32, UInt32)
    ) {
        self.inputNotes = inputNotes
        self.spendingKeys = spendingKeys
        self.outputNotes = outputNotes
        self.merkleProofs = merkleProofs
        self.merkleRoot = merkleRoot
        self.epoch = epoch
        self.inputLeafIndices = inputLeafIndices
    }
}

// Note: ProverOutput is defined in Types.swift

/// ZK Prover using rapidsnark for native proof generation
public class ZKProver {
    
    private let config: ProverConfig
    
    /// Initialize the prover with configuration
    public init(config: ProverConfig) {
        self.config = config
    }
    
    /// Generate a withdraw proof
    /// - Parameter inputs: Withdraw circuit inputs
    /// - Returns: Prover output with proof and public inputs
    public func proveWithdraw(_ inputs: WithdrawInputs) async throws -> ProverOutput {
        // Build witness inputs as JSON
        let witnessInputs = try buildWithdrawWitnessInputs(inputs)
        
        // Generate witness (requires witnesscalc framework)
        let witness = try await generateWitness(witnessInputs)
        
        // Generate proof using rapidsnark
        let (proof, publicInputs) = try await generateProof(witness: witness)
        
        return ProverOutput(proof: proof, publicInputs: publicInputs)
    }
    
    /// Generate a transfer proof
    /// - Parameter inputs: Transfer circuit inputs
    /// - Returns: Prover output with proof and public inputs
    public func proveTransfer(_ inputs: TransferInputs) async throws -> ProverOutput {
        // Build witness inputs as JSON
        let witnessInputs = try buildTransferWitnessInputs(inputs)
        
        // Generate witness (requires witnesscalc framework)
        let witness = try await generateWitness(witnessInputs)
        
        // Generate proof using rapidsnark
        let (proof, publicInputs) = try await generateProof(witness: witness)
        
        return ProverOutput(proof: proof, publicInputs: publicInputs)
    }
    
    /// Generate a renewal proof
    /// - Parameter inputs: Renew circuit inputs
    /// - Returns: Prover output with proof and public inputs
    public func proveRenew(_ inputs: RenewInputs) async throws -> ProverOutput {
        // Build witness inputs as JSON
        let witnessInputs = try buildRenewWitnessInputs(inputs)
        
        // Generate witness (requires witnesscalc framework)
        let witness = try await generateWitness(witnessInputs)
        
        // Generate proof using rapidsnark
        let (proof, publicInputs) = try await generateProof(witness: witness)
        
        return ProverOutput(proof: proof, publicInputs: publicInputs)
    }
    
    // MARK: - Private Methods
    
    /// Build witness inputs for withdraw circuit
    private func buildWithdrawWitnessInputs(_ inputs: WithdrawInputs) throws -> [String: Any] {
        let BN254_PRIME = Poseidon.BN254_PRIME
        
        // Compute nullifier key from spending key
        let nullifierKey = inputs.spendingKeys.nullifierKey
        
        // Compute commitment (should match note.commitment)
        let commitment = inputs.note.commitment
        
        // Compute nullifier: H(commitment, nullifierKey, epoch, leafIndex)
        let nullifier = try Crypto.computeNullifier(
            commitment: commitment,
            nullifierKey: nullifierKey,
            epoch: inputs.epoch,
            leafIndex: inputs.leafIndex
        )
        
        // Build path indices (bits of leaf index, bottom-up)
        var pathIndices: [Int] = []
        var idx = Int(inputs.leafIndex)
        for _ in 0..<12 { // MERKLE_DEPTH
            pathIndices.append(idx % 2)
            idx = idx / 2
        }
        
        // Convert siblings to field element strings
        let pathElements = inputs.merkleProof.siblings.map { sibling -> String in
            let value = BigUInt(sibling)
            return String(value % BN254_PRIME, radix: 10)
        }
        
        // Build the witness inputs object
        let witnessInputs: [String: Any] = [
            // Private inputs
            "value": String(inputs.note.value),
            "token": bytesToFieldString(inputs.note.token),
            "blinding": bytesToFieldString(inputs.note.randomness),
            "nullifierKey": bytesToFieldString(nullifierKey),
            "pathElements": pathElements,
            "pathIndices": pathIndices,
            
            // Public inputs
            "root": bytesToFieldString(inputs.merkleRoot),
            "nullifierHash": bytesToFieldString(nullifier),
            "recipient": bytesToFieldString(inputs.recipient),
            "amount": String(inputs.amount),
            "epoch": String(inputs.epoch),
        ]
        
        return witnessInputs
    }
    
    /// Build witness inputs for transfer circuit
    private func buildTransferWitnessInputs(_ inputs: TransferInputs) throws -> [String: Any] {
        let BN254_PRIME = Poseidon.BN254_PRIME
        
        // Compute nullifiers for both input notes
        let nullifier0 = try Crypto.computeNullifier(
            commitment: inputs.inputNotes.0.commitment,
            nullifierKey: inputs.spendingKeys.nullifierKey,
            epoch: inputs.epoch,
            leafIndex: inputs.inputLeafIndices.0
        )
        let nullifier1 = try Crypto.computeNullifier(
            commitment: inputs.inputNotes.1.commitment,
            nullifierKey: inputs.spendingKeys.nullifierKey,
            epoch: inputs.epoch,
            leafIndex: inputs.inputLeafIndices.1
        )
        
        // Helper to build path for a proof
        func buildPath(_ proof: MerkleProof, leafIndex: UInt32) -> ([String], [Int]) {
            var pathIndices: [Int] = []
            var idx = Int(leafIndex)
            for _ in 0..<12 {
                pathIndices.append(idx % 2)
                idx = idx / 2
            }
            let pathElements = proof.siblings.map { sibling -> String in
                let value = BigUInt(sibling)
                return String(value % BN254_PRIME, radix: 10)
            }
            return (pathElements, pathIndices)
        }
        
        let (path0, indices0) = buildPath(inputs.merkleProofs.0, leafIndex: inputs.inputLeafIndices.0)
        let (path1, indices1) = buildPath(inputs.merkleProofs.1, leafIndex: inputs.inputLeafIndices.1)
        
        // Output commitments
        let outCommitment0 = inputs.outputNotes.0.commitment
        let outCommitment1 = inputs.outputNotes.1.commitment
        
        let witnessInputs: [String: Any] = [
            // Input note 0
            "inValue": [String(inputs.inputNotes.0.value), String(inputs.inputNotes.1.value)],
            "inToken": [bytesToFieldString(inputs.inputNotes.0.token), bytesToFieldString(inputs.inputNotes.1.token)],
            "inBlinding": [bytesToFieldString(inputs.inputNotes.0.randomness), bytesToFieldString(inputs.inputNotes.1.randomness)],
            "nullifierKey": bytesToFieldString(inputs.spendingKeys.nullifierKey),
            "pathElements": [path0, path1],
            "pathIndices": [indices0, indices1],
            
            // Output notes
            "outValue": [String(inputs.outputNotes.0.value), String(inputs.outputNotes.1.value)],
            "outToken": [bytesToFieldString(inputs.outputNotes.0.token), bytesToFieldString(inputs.outputNotes.1.token)],
            "outBlinding": [bytesToFieldString(inputs.outputNotes.0.randomness), bytesToFieldString(inputs.outputNotes.1.randomness)],
            "outOwner": [bytesToFieldString(inputs.outputNotes.0.owner), bytesToFieldString(inputs.outputNotes.1.owner)],
            
            // Public inputs
            "root": bytesToFieldString(inputs.merkleRoot),
            "nullifierHash": [bytesToFieldString(nullifier0), bytesToFieldString(nullifier1)],
            "outCommitment": [bytesToFieldString(outCommitment0), bytesToFieldString(outCommitment1)],
            "epoch": String(inputs.epoch),
        ]
        
        return witnessInputs
    }
    
    /// Build witness inputs for renew circuit
    private func buildRenewWitnessInputs(_ inputs: RenewInputs) throws -> [String: Any] {
        let BN254_PRIME = Poseidon.BN254_PRIME
        
        // Compute nullifier for old note
        let nullifier = try Crypto.computeNullifier(
            commitment: inputs.oldNote.commitment,
            nullifierKey: inputs.spendingKeys.nullifierKey,
            epoch: inputs.oldEpoch,
            leafIndex: inputs.oldLeafIndex
        )
        
        // Build path indices
        var pathIndices: [Int] = []
        var idx = Int(inputs.oldLeafIndex)
        for _ in 0..<12 {
            pathIndices.append(idx % 2)
            idx = idx / 2
        }
        
        let pathElements = inputs.merkleProof.siblings.map { sibling -> String in
            let value = BigUInt(sibling)
            return String(value % BN254_PRIME, radix: 10)
        }
        
        let witnessInputs: [String: Any] = [
            // Old note (input)
            "inValue": String(inputs.oldNote.value),
            "inToken": bytesToFieldString(inputs.oldNote.token),
            "inBlinding": bytesToFieldString(inputs.oldNote.randomness),
            "nullifierKey": bytesToFieldString(inputs.spendingKeys.nullifierKey),
            "pathElements": pathElements,
            "pathIndices": pathIndices,
            
            // New note (output)
            "outBlinding": bytesToFieldString(inputs.newNote.randomness),
            "outOwner": bytesToFieldString(inputs.newNote.owner),
            
            // Public inputs
            "oldRoot": bytesToFieldString(inputs.merkleRoot),
            "nullifierHash": bytesToFieldString(nullifier),
            "outCommitment": bytesToFieldString(inputs.newNote.commitment),
            "oldEpoch": String(inputs.oldEpoch),
            "newEpoch": String(inputs.newEpoch),
        ]
        
        return witnessInputs
    }
    
    /// Convert bytes to field element string (decimal)
    private func bytesToFieldString(_ bytes: Data) -> String {
        let value = BigUInt(bytes)
        let reduced = value % Poseidon.BN254_PRIME
        return String(reduced, radix: 10)
    }
    
    /// Generate witness from inputs
    /// This requires the witnesscalc framework to be integrated
    private func generateWitness(_ inputs: [String: Any]) async throws -> Data {
        // Convert inputs to JSON
        guard let _ = try? JSONSerialization.data(withJSONObject: inputs) else {
            throw ProverError.invalidInputs("Failed to serialize witness inputs")
        }
        
        // TODO: Integrate with witnesscalc framework
        // For now, throw an error indicating the framework is not yet integrated
        //
        // When integrated, this would look like:
        // let witnessCalc = WitnessCalculator(path: config.witnesscalcPath!)
        // return try await witnessCalc.calculate(jsonString)
        
        throw ProverError.frameworkNotIntegrated(
            "witnesscalc framework not integrated. " +
            "Add 'pod \"rapidsnark\"' to your Podfile or integrate via SPM."
        )
    }
    
    /// Generate proof from witness
    /// This requires the rapidsnark framework to be integrated
    private func generateProof(witness: Data) async throws -> (Groth16Proof, [Data]) {
        // TODO: Integrate with rapidsnark framework
        // When integrated, this would look like:
        //
        // import rapidsnark
        //
        // let witnessBase64 = witness.base64EncodedString()
        // let (proofJson, publicSignalsJson) = try groth16ProveWithZKeyFilePath(
        //     config.zkeyPath,
        //     witnessBase64
        // )
        //
        // let proof = try parseProofJson(proofJson)
        // let publicInputs = try parsePublicSignalsJson(publicSignalsJson)
        // return (proof, publicInputs)
        
        throw ProverError.frameworkNotIntegrated(
            "rapidsnark framework not integrated. " +
            "Add 'pod \"rapidsnark\"' to your Podfile or integrate via SPM."
        )
    }
}

// MARK: - Prover Errors

public enum ProverError: Error, CustomStringConvertible {
    case invalidInputs(String)
    case witnessGenerationFailed(String)
    case proofGenerationFailed(String)
    case frameworkNotIntegrated(String)
    
    public var description: String {
        switch self {
        case .invalidInputs(let msg):
            return "Invalid prover inputs: \(msg)"
        case .witnessGenerationFailed(let msg):
            return "Witness generation failed: \(msg)"
        case .proofGenerationFailed(let msg):
            return "Proof generation failed: \(msg)"
        case .frameworkNotIntegrated(let msg):
            return "Framework not integrated: \(msg)"
        }
    }
}

// MARK: - Proof Parsing (for when rapidsnark is integrated)

extension ZKProver {
    
    /// Parse proof JSON from rapidsnark into Groth16Proof structure
    static func parseProofJson(_ json: String) throws -> Groth16Proof {
        guard let data = json.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ProverError.proofGenerationFailed("Invalid proof JSON")
        }
        
        // rapidsnark returns proof as:
        // { "pi_a": [...], "pi_b": [...], "pi_c": [...], "protocol": "groth16" }
        
        guard let piA = dict["pi_a"] as? [String],
              let piB = dict["pi_b"] as? [[String]],
              let piC = dict["pi_c"] as? [String] else {
            throw ProverError.proofGenerationFailed("Missing proof components")
        }
        
        // Convert string arrays to combined Data
        // For Solana, proof components are serialized as concatenated bytes
        func parseAndCombine(_ strings: [String]) -> Data {
            var result = Data()
            for str in strings {
                if let bigInt = BigUInt(str, radix: 10) {
                    result.append(Crypto.bigintToBytes32(bigInt))
                }
            }
            return result
        }
        
        let a = parseAndCombine(piA)
        let b = piB.reduce(Data()) { result, arr in
            result + parseAndCombine(arr)
        }
        let c = parseAndCombine(piC)
        
        return Groth16Proof(a: a, b: b, c: c)
    }
    
    /// Parse public signals JSON from rapidsnark
    static func parsePublicSignalsJson(_ json: String) throws -> [Data] {
        guard let data = json.data(using: .utf8),
              let array = try? JSONSerialization.jsonObject(with: data) as? [String] else {
            throw ProverError.proofGenerationFailed("Invalid public signals JSON")
        }
        
        return array.compactMap { str -> Data? in
            guard let bigInt = BigUInt(str, radix: 10) else { return nil }
            return Crypto.bigintToBytes32(bigInt)
        }
    }
}

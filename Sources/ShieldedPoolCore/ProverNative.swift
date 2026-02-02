import Foundation
import BigInt

#if canImport(rapidsnark) && canImport(CircomWitnesscalc)
import rapidsnark
import CircomWitnesscalc
#endif

#if canImport(JavaScriptCore)
import JavaScriptCore
#endif

// MARK: - Native Prover (iOS)

/// Native ZK Prover using rapidsnark and circom-witnesscalc
/// This provides 10-50x faster proof generation compared to WASM
public class NativeProver {
    
    /// Circuit type for this prover
    private let circuitType: CircuitType
    
    /// Artifact manager for accessing circuit files
    private let artifactManager: CircuitArtifactManager
    
    /// Whether to use WASM fallback when native fails
    private var wasmFallbackEnabled: Bool = true
    
    /// WASM fallback prover (lazy loaded)
    private var wasmFallback: WASMWitnessCalculator?
    
    /// Initialize native prover for a specific circuit
    /// - Parameter circuitType: The circuit type to prove
    public init(circuitType: CircuitType) {
        self.circuitType = circuitType
        self.artifactManager = CircuitArtifactManager.shared
    }
    
    /// Enable or disable WASM fallback
    public func setWASMFallback(enabled: Bool) {
        self.wasmFallbackEnabled = enabled
    }
    
    /// Check if native proving is available
    public var isNativeAvailable: Bool {
        #if canImport(rapidsnark) && canImport(CircomWitnesscalc)
        let circuit = CircuitArtifact(rawValue: circuitType.rawValue)!
        return artifactManager.isCircuitReady(circuit)
        #else
        return false
        #endif
    }
    
    /// Check if WASM fallback is available
    public var isWASMAvailable: Bool {
        let circuit = CircuitArtifact(rawValue: circuitType.rawValue)!
        return artifactManager.isWASMFallbackAvailable(circuit)
    }
    
    // MARK: - Proof Generation
    
    /// Generate a withdraw proof
    public func proveWithdraw(_ inputs: WithdrawInputs) async throws -> ProverOutput {
        let witnessInputs = try buildWithdrawWitnessInputs(inputs)
        return try await generateProofInternal(witnessInputs: witnessInputs)
    }
    
    /// Generate a transfer proof
    public func proveTransfer(_ inputs: TransferInputs) async throws -> ProverOutput {
        let witnessInputs = try buildTransferWitnessInputs(inputs)
        return try await generateProofInternal(witnessInputs: witnessInputs)
    }
    
    /// Generate a renewal proof
    public func proveRenew(_ inputs: RenewInputs) async throws -> ProverOutput {
        let witnessInputs = try buildRenewWitnessInputs(inputs)
        return try await generateProofInternal(witnessInputs: witnessInputs)
    }
    
    // MARK: - Internal Proof Generation
    
    private func generateProofInternal(witnessInputs: [String: Any]) async throws -> ProverOutput {
        // Try native first
        #if canImport(rapidsnark) && canImport(CircomWitnesscalc)
        if isNativeAvailable {
            do {
                return try await generateProofNative(witnessInputs: witnessInputs)
            } catch {
                // Fall through to WASM if enabled
                if !wasmFallbackEnabled {
                    throw error
                }
                print("⚠️ Native proof failed, trying WASM fallback: \(error)")
            }
        }
        #endif
        
        // Try WASM fallback
        if wasmFallbackEnabled && isWASMAvailable {
            return try await generateProofWASM(witnessInputs: witnessInputs)
        }
        
        // No prover available
        let circuit = CircuitArtifact(rawValue: circuitType.rawValue)!
        throw ArtifactError.artifactNotFound(circuit)
    }
    
    // MARK: - Native Implementation
    
    #if canImport(rapidsnark) && canImport(CircomWitnesscalc)
    private func generateProofNative(witnessInputs: [String: Any]) async throws -> ProverOutput {
        let circuit = CircuitArtifact(rawValue: circuitType.rawValue)!
        
        // Get paths
        let zkeyPath = artifactManager.artifactPath(circuit: circuit, fileType: .zkey).path
        let wcdPath = artifactManager.artifactPath(circuit: circuit, fileType: .witnessGraph).path
        
        // Convert inputs to JSON
        guard let inputsData = try? JSONSerialization.data(withJSONObject: witnessInputs),
              let inputsJson = String(data: inputsData, encoding: .utf8) else {
            throw ProverError.invalidInputs("Failed to serialize witness inputs")
        }
        
        // Generate witness using native witnesscalc
        let witnessData: Data
        do {
            // Load circuit graph
            let graphData = try Data(contentsOf: URL(fileURLWithPath: wcdPath))
            
            // Calculate witness
            let witness = try calculateWitness(graphData: graphData, inputsJson: inputsJson)
            witnessData = witness
        } catch {
            throw ProverError.witnessGenerationFailed("Native witnesscalc error: \(error)")
        }
        
        // Generate proof using rapidsnark
        let proofResult: (proof: String, publicSignals: String)
        do {
            // Read zkey file
            let zkeyData = try Data(contentsOf: URL(fileURLWithPath: zkeyPath))
            
            // Generate Groth16 proof
            let result = try groth16Prove(zkey: zkeyData, witness: witnessData)
            proofResult = result
        } catch {
            throw ProverError.proofGenerationFailed("Rapidsnark error: \(error)")
        }
        
        // Parse proof
        let proof = try ZKProver.parseProofJson(proofResult.proof)
        let publicInputs = try ZKProver.parsePublicSignalsJson(proofResult.publicSignals)
        
        return ProverOutput(proof: proof, publicInputs: publicInputs)
    }
    #endif
    
    // MARK: - WASM Fallback Implementation
    
    private func generateProofWASM(witnessInputs: [String: Any]) async throws -> ProverOutput {
        let circuit = CircuitArtifact(rawValue: circuitType.rawValue)!
        
        // Initialize WASM calculator if needed
        if wasmFallback == nil {
            let wasmPath = artifactManager.artifactPath(circuit: circuit, fileType: .wasm)
            wasmFallback = try WASMWitnessCalculator(wasmPath: wasmPath)
        }
        
        guard let calculator = wasmFallback else {
            throw ProverError.witnessGenerationFailed("Failed to initialize WASM calculator")
        }
        
        // Generate witness using WASM
        let witnessData = try await calculator.calculateWitness(inputs: witnessInputs)
        
        // For WASM fallback, we still need rapidsnark for proof generation
        // If rapidsnark isn't available, we can't generate proofs
        #if canImport(rapidsnark)
        let zkeyPath = artifactManager.artifactPath(circuit: circuit, fileType: .zkey)
        let zkeyData = try Data(contentsOf: zkeyPath)
        
        let result = try groth16Prove(zkey: zkeyData, witness: witnessData)
        let proof = try ZKProver.parseProofJson(result.proof)
        let publicInputs = try ZKProver.parsePublicSignalsJson(result.publicSignals)
        
        return ProverOutput(proof: proof, publicInputs: publicInputs)
        #else
        throw ProverError.frameworkNotIntegrated("rapidsnark required for proof generation")
        #endif
    }
    
    // MARK: - Witness Input Builders
    
    private func buildWithdrawWitnessInputs(_ inputs: WithdrawInputs) throws -> [String: Any] {
        let BN254_PRIME = Poseidon.BN254_PRIME
        
        let nullifier = try Crypto.computeNullifier(
            commitment: inputs.note.commitment,
            nullifierKey: inputs.spendingKeys.nullifierKey,
            epoch: inputs.epoch,
            leafIndex: inputs.leafIndex
        )
        
        var pathIndices: [Int] = []
        var idx = Int(inputs.leafIndex)
        for _ in 0..<12 {
            pathIndices.append(idx % 2)
            idx = idx / 2
        }
        
        let pathElements = inputs.merkleProof.siblings.map { sibling -> String in
            let value = BigUInt(sibling)
            return String(value % BN254_PRIME, radix: 10)
        }
        
        return [
            "value": String(inputs.note.value),
            "token": bytesToFieldString(inputs.note.token),
            "blinding": bytesToFieldString(inputs.note.randomness),
            "nullifierKey": bytesToFieldString(inputs.spendingKeys.nullifierKey),
            "pathElements": pathElements,
            "pathIndices": pathIndices,
            "root": bytesToFieldString(inputs.merkleRoot),
            "nullifierHash": bytesToFieldString(nullifier),
            "recipient": bytesToFieldString(inputs.recipient),
            "amount": String(inputs.amount),
            "epoch": String(inputs.epoch),
        ]
    }
    
    private func buildTransferWitnessInputs(_ inputs: TransferInputs) throws -> [String: Any] {
        let BN254_PRIME = Poseidon.BN254_PRIME
        
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
        
        return [
            "inValue": [String(inputs.inputNotes.0.value), String(inputs.inputNotes.1.value)],
            "inToken": [bytesToFieldString(inputs.inputNotes.0.token), bytesToFieldString(inputs.inputNotes.1.token)],
            "inBlinding": [bytesToFieldString(inputs.inputNotes.0.randomness), bytesToFieldString(inputs.inputNotes.1.randomness)],
            "nullifierKey": bytesToFieldString(inputs.spendingKeys.nullifierKey),
            "pathElements": [path0, path1],
            "pathIndices": [indices0, indices1],
            "outValue": [String(inputs.outputNotes.0.value), String(inputs.outputNotes.1.value)],
            "outToken": [bytesToFieldString(inputs.outputNotes.0.token), bytesToFieldString(inputs.outputNotes.1.token)],
            "outBlinding": [bytesToFieldString(inputs.outputNotes.0.randomness), bytesToFieldString(inputs.outputNotes.1.randomness)],
            "outOwner": [bytesToFieldString(inputs.outputNotes.0.owner), bytesToFieldString(inputs.outputNotes.1.owner)],
            "root": bytesToFieldString(inputs.merkleRoot),
            "nullifierHash": [bytesToFieldString(nullifier0), bytesToFieldString(nullifier1)],
            "outCommitment": [bytesToFieldString(inputs.outputNotes.0.commitment), bytesToFieldString(inputs.outputNotes.1.commitment)],
            "epoch": String(inputs.epoch),
        ]
    }
    
    private func buildRenewWitnessInputs(_ inputs: RenewInputs) throws -> [String: Any] {
        let BN254_PRIME = Poseidon.BN254_PRIME
        
        let nullifier = try Crypto.computeNullifier(
            commitment: inputs.oldNote.commitment,
            nullifierKey: inputs.spendingKeys.nullifierKey,
            epoch: inputs.oldEpoch,
            leafIndex: inputs.oldLeafIndex
        )
        
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
        
        return [
            "inValue": String(inputs.oldNote.value),
            "inToken": bytesToFieldString(inputs.oldNote.token),
            "inBlinding": bytesToFieldString(inputs.oldNote.randomness),
            "nullifierKey": bytesToFieldString(inputs.spendingKeys.nullifierKey),
            "pathElements": pathElements,
            "pathIndices": pathIndices,
            "outBlinding": bytesToFieldString(inputs.newNote.randomness),
            "outOwner": bytesToFieldString(inputs.newNote.owner),
            "oldRoot": bytesToFieldString(inputs.merkleRoot),
            "nullifierHash": bytesToFieldString(nullifier),
            "outCommitment": bytesToFieldString(inputs.newNote.commitment),
            "oldEpoch": String(inputs.oldEpoch),
            "newEpoch": String(inputs.newEpoch),
        ]
    }
    
    private func bytesToFieldString(_ bytes: Data) -> String {
        let value = BigUInt(bytes)
        let reduced = value % Poseidon.BN254_PRIME
        return String(reduced, radix: 10)
    }
}

// MARK: - WASM Witness Calculator (Fallback)

/// WASM-based witness calculator using JavaScriptCore
/// Provides fallback when native witnesscalc is unavailable or fails
public class WASMWitnessCalculator {
    
    #if canImport(JavaScriptCore)
    
    private var jsContext: JSContext?
    private let wasmPath: URL
    
    /// Initialize with path to WASM file
    public init(wasmPath: URL) throws {
        self.wasmPath = wasmPath
        try loadWASM()
    }
    
    private func loadWASM() throws {
        guard let context = JSContext() else {
            throw ProverError.witnessGenerationFailed("Failed to create JSContext")
        }
        
        // Set up exception handler
        context.exceptionHandler = { context, exception in
            print("JS Exception: \(exception?.toString() ?? "unknown")")
        }
        
        // Load witness calculator JS wrapper
        let wrapperJS = Self.witnessCalculatorJS
        context.evaluateScript(wrapperJS)
        
        // Load WASM binary
        let wasmData = try Data(contentsOf: wasmPath)
        let wasmBase64 = wasmData.base64EncodedString()
        
        // Initialize WASM module
        let initScript = "initWasm('\(wasmBase64)');"
        context.evaluateScript(initScript)
        
        self.jsContext = context
    }
    
    /// Calculate witness from inputs
    public func calculateWitness(inputs: [String: Any]) async throws -> Data {
        guard let context = jsContext else {
            throw ProverError.witnessGenerationFailed("JSContext not initialized")
        }
        
        // Convert inputs to JSON
        guard let inputsData = try? JSONSerialization.data(withJSONObject: inputs),
              let inputsJson = String(data: inputsData, encoding: .utf8) else {
            throw ProverError.invalidInputs("Failed to serialize inputs")
        }
        
        // Call witness calculator
        let script = "calculateWitness(\(inputsJson));"
        guard let result = context.evaluateScript(script),
              let witnessBase64 = result.toString(),
              let witnessData = Data(base64Encoded: witnessBase64) else {
            throw ProverError.witnessGenerationFailed("WASM witness calculation failed")
        }
        
        return witnessData
    }
    
    /// Minimal JS wrapper for circom WASM witness calculator
    private static let witnessCalculatorJS = """
    var wasmModule = null;
    var witnessCalculator = null;
    
    async function initWasm(wasmBase64) {
        const wasmBytes = Uint8Array.from(atob(wasmBase64), c => c.charCodeAt(0));
        const wasmModule = await WebAssembly.instantiate(wasmBytes, {});
        witnessCalculator = wasmModule.instance;
    }
    
    function calculateWitness(inputs) {
        if (!witnessCalculator) {
            throw new Error('WASM not initialized');
        }
        
        // Allocate memory for inputs
        const inputBytes = new TextEncoder().encode(JSON.stringify(inputs));
        const inputPtr = witnessCalculator.exports.allocate(inputBytes.length);
        new Uint8Array(witnessCalculator.exports.memory.buffer, inputPtr, inputBytes.length).set(inputBytes);
        
        // Calculate witness
        const witnessPtr = witnessCalculator.exports.calculateWitness(inputPtr, inputBytes.length);
        const witnessLen = witnessCalculator.exports.getWitnessLength();
        
        // Read witness
        const witnessBytes = new Uint8Array(witnessCalculator.exports.memory.buffer, witnessPtr, witnessLen);
        
        // Convert to base64
        return btoa(String.fromCharCode.apply(null, witnessBytes));
    }
    """
    
    #else
    
    private let wasmPath: URL
    
    public init(wasmPath: URL) throws {
        self.wasmPath = wasmPath
        throw ProverError.frameworkNotIntegrated("JavaScriptCore not available on this platform")
    }
    
    public func calculateWitness(inputs: [String: Any]) async throws -> Data {
        throw ProverError.frameworkNotIntegrated("JavaScriptCore not available on this platform")
    }
    
    #endif
}

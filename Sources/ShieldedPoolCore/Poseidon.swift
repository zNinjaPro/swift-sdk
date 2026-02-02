import Foundation
import BigInt

/// Poseidon hash function implementation for BN254 field
/// This is a direct port of the TypeScript implementation in solanaPoseidon.ts
public enum Poseidon {
    
    /// A field element in the BN254 scalar field
    public typealias FieldElement = BigUInt
    
    /// BN254 prime: 21888242871839275222246405745257275088548364400416034343698204186575808495617
    public static let BN254_PRIME = BigUInt("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", radix: 16)!
    
    /// Poseidon parameters for a given width
    public struct Parameters {
        let width: Int
        let fullRounds: Int
        let partialRounds: Int
        let alpha: Int
        let ark: [FieldElement]
        let mds: [[FieldElement]]
    }
    
    /// Error types for Poseidon operations
    public enum PoseidonError: Error, LocalizedError {
        case invalidInputCount(got: Int, expected: ClosedRange<Int>)
        case noParametersForWidth(Int)
        case arkLengthMismatch
        
        public var errorDescription: String? {
            switch self {
            case .invalidInputCount(let got, let expected):
                return "Poseidon supports \(expected.lowerBound)-\(expected.upperBound) inputs, received \(got)"
            case .noParametersForWidth(let width):
                return "No Poseidon parameters for width=\(width)"
            case .arkLengthMismatch:
                return "Poseidon ark length mismatch"
            }
        }
    }
    
    // MARK: - Field Arithmetic
    
    /// Reduce a value modulo BN254_PRIME
    @inlinable
    static func modPrime(_ value: FieldElement) -> FieldElement {
        value % BN254_PRIME
    }
    
    /// Add two field elements
    @inlinable
    static func addMod(_ a: FieldElement, _ b: FieldElement) -> FieldElement {
        modPrime(a + b)
    }
    
    /// Multiply two field elements
    @inlinable
    static func mulMod(_ a: FieldElement, _ b: FieldElement) -> FieldElement {
        modPrime(a * b)
    }
    
    /// Compute x^alpha in the field (optimized for alpha=5)
    @inlinable
    static func powAlpha(_ value: FieldElement, alpha: Int) -> FieldElement {
        if alpha == 5 {
            // Optimized for alpha=5: x^5 = x^4 * x = (x^2)^2 * x
            let x2 = mulMod(value, value)
            let x4 = mulMod(x2, x2)
            return mulMod(x4, value)
        }
        // General case using modular exponentiation
        return value.power(BigUInt(alpha), modulus: BN254_PRIME)
    }
    
    /// Convert bytes to field element (big-endian)
    public static func bytesToField(_ bytes: Data) -> FieldElement {
        guard !bytes.isEmpty else { return FieldElement.zero }
        let value = FieldElement(Data(bytes))
        return modPrime(value)
    }
    
    /// Convert field element to 32-byte big-endian representation
    public static func fieldToBytes(_ value: FieldElement) -> Data {
        var hex = String(value, radix: 16)
        // Pad to 64 hex characters (32 bytes)
        while hex.count < 64 {
            hex = "0" + hex
        }
        return Data(hexString: hex) ?? Data(count: 32)
    }
    
    // MARK: - MDS Matrix
    
    /// Apply MDS matrix to state
    static func applyMds(_ state: [FieldElement], mds: [[FieldElement]]) -> [FieldElement] {
        let width = state.count
        var next = [FieldElement](repeating: .zero, count: width)
        
        for i in 0..<width {
            var acc = FieldElement.zero
            for j in 0..<width {
                acc = addMod(acc, mulMod(state[j], mds[i][j]))
            }
            next[i] = acc
        }
        
        return next
    }
    
    // MARK: - Core Poseidon
    
    /// Core Poseidon permutation
    static func poseidon(inputs: [FieldElement], params: Parameters) throws -> FieldElement {
        guard inputs.count == params.width - 1 else {
            throw PoseidonError.invalidInputCount(
                got: inputs.count,
                expected: (params.width - 1)...(params.width - 1)
            )
        }
        
        // Initialize state with domain tag (0) and inputs
        var state = [FieldElement](repeating: .zero, count: params.width)
        state[0] = .zero // domain tag
        for i in 0..<inputs.count {
            state[i + 1] = modPrime(inputs[i])
        }
        
        let totalRounds = params.fullRounds + params.partialRounds
        let halfRounds = params.fullRounds / 2
        var arkOffset = 0
        
        // Helper to apply ARK (Add Round Key)
        func applyArk() {
            for i in 0..<params.width {
                state[i] = addMod(state[i], params.ark[arkOffset + i])
            }
            arkOffset += params.width
        }
        
        // Full S-box (apply to all elements)
        func sboxFull() {
            for i in 0..<params.width {
                state[i] = powAlpha(state[i], alpha: params.alpha)
            }
        }
        
        // Partial S-box (apply only to first element)
        func sboxPartial() {
            state[0] = powAlpha(state[0], alpha: params.alpha)
        }
        
        // First half of full rounds
        for _ in 0..<halfRounds {
            applyArk()
            sboxFull()
            state = applyMds(state, mds: params.mds)
        }
        
        // Partial rounds
        for _ in 0..<params.partialRounds {
            applyArk()
            sboxPartial()
            state = applyMds(state, mds: params.mds)
        }
        
        // Second half of full rounds
        for _ in 0..<halfRounds {
            applyArk()
            sboxFull()
            state = applyMds(state, mds: params.mds)
        }
        
        // Verify we used all ARK constants
        guard arkOffset == totalRounds * params.width else {
            throw PoseidonError.arkLengthMismatch
        }
        
        return modPrime(state[0])
    }
    
    // MARK: - Public API
    
    /// Hash 1-3 byte arrays using Poseidon, returns 32-byte result
    public static func hash(_ inputs: [Data]) throws -> Data {
        guard (1...4).contains(inputs.count) else {
            throw PoseidonError.invalidInputCount(got: inputs.count, expected: 1...4)
        }
        
        let width = inputs.count + 1
        guard let params = PoseidonParams.table[width] else {
            throw PoseidonError.noParametersForWidth(width)
        }
        
        let felts = inputs.map { bytesToField($0) }
        let result = try poseidon(inputs: felts, params: params)
        return fieldToBytes(result)
    }
    
    /// Hash 1-3 byte arrays using Poseidon, returns field element
    public static func hashToField(_ inputs: [Data]) throws -> FieldElement {
        guard (1...4).contains(inputs.count) else {
            throw PoseidonError.invalidInputCount(got: inputs.count, expected: 1...4)
        }
        
        let width = inputs.count + 1
        guard let params = PoseidonParams.table[width] else {
            throw PoseidonError.noParametersForWidth(width)
        }
        
        let felts = inputs.map { bytesToField($0) }
        return try poseidon(inputs: felts, params: params)
    }
    
    /// Hash two byte arrays (common case for Merkle tree nodes)
    public static func hash2(_ left: Data, _ right: Data) throws -> Data {
        try hash([left, right])
    }
}

// MARK: - Data Extensions

extension Data {
    /// Initialize Data from a hex string
    init?(hexString: String) {
        let hex = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        guard hex.count % 2 == 0 else { return nil }
        
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        
        self = data
    }
    
    /// Convert Data to hex string
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - BigUInt Extensions

// BigUInt already has a Data initializer in the BigInt library
// No extension needed

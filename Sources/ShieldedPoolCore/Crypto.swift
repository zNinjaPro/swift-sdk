import Foundation
import BigInt
import CryptoKit

/// Cryptographic utilities for shielded pool operations
public enum Crypto {
    
    // MARK: - SHA-256
    
    /// SHA-256 hash function
    public static func sha256(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }
    
    // MARK: - Random
    
    /// Generate cryptographically secure random bytes
    public static func randomBytes(_ count: Int) -> Data {
        var bytes = Data(count: count)
        _ = bytes.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, count, ptr.baseAddress!)
        }
        return bytes
    }
    
    // MARK: - Poseidon Hash Wrappers
    
    /// Compute Poseidon hash of multiple inputs
    public static func poseidonHash(_ inputs: [Data]) throws -> Data {
        return try Poseidon.hash(inputs)
    }
    
    /// Synchronous Poseidon hash (for merkle tree operations)
    public static func poseidonHashSync(_ inputs: [Data]) -> Data {
        return (try? Poseidon.hash(inputs)) ?? Data(repeating: 0, count: 32)
    }
    
    // MARK: - Commitment & Nullifier
    
    /// Compute commitment: Hash(value || owner || randomness)
    /// - Parameters:
    ///   - value: Token amount
    ///   - owner: 32-byte owner public key hash
    ///   - randomness: 32-byte random blinding factor
    /// - Returns: 32-byte commitment
    public static func computeCommitment(
        value: UInt64,
        owner: Data,
        randomness: Data
    ) throws -> Data {
        // Encode value as 32-byte big-endian
        let valueData = bigintToBytes32(BigUInt(value))
        return try Poseidon.hash([valueData, owner, randomness])
    }
    
    /// Compute nullifier: Hash(commitment, nullifierKey, epoch, leafIndex)
    /// This matches the circuit's Nullifier template which takes 4 inputs.
    public static func computeNullifier(
        commitment: Data,
        nullifierKey: Data,
        epoch: UInt64,
        leafIndex: UInt32
    ) throws -> Data {
        // Encode epoch as 32-byte little-endian (matching circuit)
        var epochData = Data(count: 32)
        var epochVal = epoch
        for i in 0..<8 {
            epochData[i] = UInt8(epochVal & 0xFF)
            epochVal >>= 8
        }
        
        // Encode leafIndex as 32-byte little-endian
        var leafIndexData = Data(count: 32)
        leafIndexData[0] = UInt8(leafIndex & 0xFF)
        leafIndexData[1] = UInt8((leafIndex >> 8) & 0xFF)
        leafIndexData[2] = UInt8((leafIndex >> 16) & 0xFF)
        leafIndexData[3] = UInt8((leafIndex >> 24) & 0xFF)
        
        return try Poseidon.hash([commitment, nullifierKey, epochData, leafIndexData])
    }
    
    // MARK: - Note Encryption (XChaCha20-Poly1305 using CryptoKit)
    
    /// Encrypt note data using ChaChaPoly (CryptoKit's ChaCha20-Poly1305)
    /// - Parameters:
    ///   - noteData: The plaintext note data
    ///   - viewingKey: 32-byte symmetric key
    /// - Returns: Tuple of (encrypted data with auth tag, nonce)
    public static func encryptNote(
        noteData: Data,
        viewingKey: Data
    ) throws -> (encrypted: Data, nonce: Data) {
        let nonce = randomBytes(12) // ChaChaPoly uses 12-byte nonce
        let key = SymmetricKey(data: viewingKey)
        let sealedBox = try ChaChaPoly.seal(noteData, using: key, nonce: ChaChaPoly.Nonce(data: nonce))
        
        // Combined ciphertext + tag
        return (encrypted: sealedBox.ciphertext + sealedBox.tag, nonce: nonce)
    }
    
    /// Decrypt note data
    /// - Parameters:
    ///   - encryptedData: Ciphertext + auth tag
    ///   - nonce: 12-byte nonce
    ///   - viewingKey: 32-byte symmetric key
    /// - Returns: Decrypted plaintext, or nil if decryption fails
    public static func decryptNote(
        encryptedData: Data,
        nonce: Data,
        viewingKey: Data
    ) -> Data? {
        guard encryptedData.count > 16 else { return nil } // Must have at least tag
        
        let key = SymmetricKey(data: viewingKey)
        let ciphertext = encryptedData.prefix(encryptedData.count - 16)
        let tag = encryptedData.suffix(16)
        
        do {
            let sealedBox = try ChaChaPoly.SealedBox(
                nonce: ChaChaPoly.Nonce(data: nonce),
                ciphertext: ciphertext,
                tag: tag
            )
            return try ChaChaPoly.open(sealedBox, using: key)
        } catch {
            return nil
        }
    }
    
    // MARK: - Note Serialization
    
    /// Serialize note for encryption
    /// Format: value (32) || token (32) || owner (32) || blinding (32) || memo_len (2) || memo
    public static func serializeNote(
        value: UInt64,
        token: Data,
        owner: Data,
        blinding: Data,
        memo: String? = nil
    ) -> Data {
        let valueData = bigintToBytes32(BigUInt(value))
        let memoData = memo?.data(using: .utf8) ?? Data()
        
        var result = Data()
        result.append(valueData)
        result.append(token)
        result.append(owner)
        result.append(blinding)
        
        // Memo length as 2-byte little-endian
        var memoLen = UInt16(memoData.count)
        result.append(Data(bytes: &memoLen, count: 2))
        result.append(memoData)
        
        return result
    }
    
    /// Deserialize note from bytes
    public static func deserializeNote(_ data: Data) throws -> DeserializedNote {
        guard data.count >= 130 else {
            throw CryptoError.invalidNoteDataLength(got: data.count, expected: 130)
        }
        
        let value = bytes32ToBigUInt(Data(data[0..<32]))
        let token = Data(data[32..<64])
        let owner = Data(data[64..<96])
        let blinding = Data(data[96..<128])
        
        let memoLen = Int(data[128]) | (Int(data[129]) << 8)
        var memo: String?
        if memoLen > 0 && data.count >= 130 + memoLen {
            memo = String(data: data[130..<(130 + memoLen)], encoding: .utf8)
        }
        
        return DeserializedNote(
            value: UInt64(value),
            token: token,
            owner: owner,
            blinding: blinding,
            memo: memo
        )
    }
    
    // MARK: - BigInt Conversion
    
    /// Convert BigUInt to 32-byte big-endian
    public static func bigintToBytes32(_ value: BigUInt) -> Data {
        var hex = String(value, radix: 16)
        while hex.count < 64 {
            hex = "0" + hex
        }
        return Data(hexString: hex) ?? Data(count: 32)
    }
    
    /// Convert 32-byte big-endian to BigUInt
    public static func bytes32ToBigUInt(_ bytes: Data) -> BigUInt {
        guard bytes.count == 32 else { return BigUInt.zero }
        return BigUInt(bytes)
    }
    
    /// Check if value is in BN254 field
    public static func isInField(_ value: BigUInt) -> Bool {
        let BN254_FIELD_SIZE = BigUInt("21888242871839275222246405745257275088548364400416034343698204186575808495617")
        return value < BN254_FIELD_SIZE
    }
}

// MARK: - Deserialized Note

public struct DeserializedNote: Sendable {
    public let value: UInt64
    public let token: Data
    public let owner: Data
    public let blinding: Data
    public let memo: String?
}

// MARK: - Crypto Errors

public enum CryptoError: Error, CustomStringConvertible {
    case invalidNoteDataLength(got: Int, expected: Int)
    case encryptionFailed(String)
    case decryptionFailed
    
    public var description: String {
        switch self {
        case .invalidNoteDataLength(let got, let expected):
            return "Invalid note data length: got \(got), expected at least \(expected)"
        case .encryptionFailed(let reason):
            return "Encryption failed: \(reason)"
        case .decryptionFailed:
            return "Decryption failed"
        }
    }
}

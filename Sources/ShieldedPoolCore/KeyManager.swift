import Foundation
import BigInt
import CryptoKit

/// Derivation path for shielded pool keys (BIP44 Solana-compatible)
private let DERIVATION_PATH = "m/44'/501'/0'/0'"

/// Key management for shielded pool operations
/// Derives spending, viewing, and nullifier keys from a master seed
public class KeyManager {
    
    private let keys: SpendingKeys
    
    private init(keys: SpendingKeys) {
        self.keys = keys
    }
    
    // MARK: - Factory Methods
    
    /// Generate new random keys with a fresh mnemonic
    /// - Returns: Tuple of (KeyManager, mnemonic phrase)
    public static func generate() throws -> (manager: KeyManager, mnemonic: String) {
        // Generate 16 bytes of entropy for 12-word mnemonic
        let entropy = Crypto.randomBytes(16)
        let mnemonic = try Mnemonic.fromEntropy(entropy)
        let manager = try fromMnemonic(mnemonic)
        return (manager, mnemonic)
    }
    
    /// Restore keys from BIP39 mnemonic phrase
    /// - Parameter mnemonic: 12 or 24 word mnemonic phrase
    /// - Returns: KeyManager with derived keys
    public static func fromMnemonic(_ mnemonic: String) throws -> KeyManager {
        guard Mnemonic.validate(mnemonic) else {
            throw KeyManagerError.invalidMnemonic
        }
        
        // Convert mnemonic to seed (using empty passphrase)
        let seed = try Mnemonic.toSeed(mnemonic: mnemonic, passphrase: "")
        
        // Derive key using Ed25519 HD derivation
        let derivedKey = try Ed25519HD.derivePath(DERIVATION_PATH, seed: seed)
        
        return fromSeed(derivedKey)
    }
    
    /// Restore keys from raw 32-byte seed
    /// - Parameter seed: 32-byte seed
    /// - Returns: KeyManager with derived keys
    public static func fromSeed(_ seed: Data) -> KeyManager {
        precondition(seed.count == 32, "Seed must be 32 bytes")
        
        // Derive specialized keys using domain separation
        let spendingKey = Crypto.sha256(Data("spending".utf8) + seed)
        let viewingKey = Crypto.sha256(Data("viewing".utf8) + seed)
        let nullifierKey = Crypto.sha256(Data("nullifier".utf8) + seed)
        
        // Derive shielded address from spending key
        let shieldedAddress = Crypto.sha256(Data("address".utf8) + spendingKey)
        
        let keys = SpendingKeys(
            seed: seed,
            spendingKey: spendingKey,
            viewingKey: viewingKey,
            nullifierKey: nullifierKey,
            shieldedAddress: shieldedAddress
        )
        
        return KeyManager(keys: keys)
    }
    
    // MARK: - Key Accessors
    
    /// Get spending key (signs transactions)
    public var spendingKey: Data {
        return keys.spendingKey
    }
    
    /// Get viewing key (decrypts notes)
    public var viewingKey: Data {
        return keys.viewingKey
    }
    
    /// Get nullifier key (generates nullifiers)
    public var nullifierKey: Data {
        return keys.nullifierKey
    }
    
    /// Get shielded address (public identifier)
    public var shieldedAddress: Data {
        return keys.shieldedAddress
    }
    
    /// Get shielded address as base58 string
    public var shieldedAddressString: String {
        return Base58.encode(shieldedAddress)
    }
    
    /// Export all keys (WARNING: sensitive data)
    public func exportKeys() -> SpendingKeys {
        return keys
    }
    
    // MARK: - Validation
    
    /// Validate a shielded address string
    public static func validateShieldedAddress(_ address: String) -> Bool {
        guard let decoded = Base58.decode(address) else {
            return false
        }
        return decoded.count == 32
    }
    
    /// Decode a shielded address from base58
    public static func decodeShieldedAddress(_ address: String) throws -> Data {
        guard let decoded = Base58.decode(address) else {
            throw KeyManagerError.invalidAddress
        }
        guard decoded.count == 32 else {
            throw KeyManagerError.invalidAddress
        }
        return decoded
    }
}

// MARK: - Key Manager Errors

public enum KeyManagerError: Error, CustomStringConvertible {
    case invalidMnemonic
    case invalidSeed
    case invalidAddress
    case derivationFailed(String)
    
    public var description: String {
        switch self {
        case .invalidMnemonic:
            return "Invalid mnemonic phrase"
        case .invalidSeed:
            return "Seed must be 32 bytes"
        case .invalidAddress:
            return "Invalid shielded address"
        case .derivationFailed(let reason):
            return "Key derivation failed: \(reason)"
        }
    }
}

// MARK: - BIP39 Mnemonic Support

/// Simple BIP39 mnemonic implementation
public enum Mnemonic {
    
    /// BIP39 English wordlist (2048 words)
    /// Note: In production, load from a resource file
    private static let wordlist: [String] = loadWordlist()
    
    private static func loadWordlist() -> [String] {
        // Simplified: Return first few words for structure
        // In production, load full 2048 word BIP39 list
        return [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            // ... (2048 words total)
            // For now, generate placeholder wordlist
        ] + (0..<2032).map { "word\($0)" }
    }
    
    /// Generate mnemonic from entropy
    public static func fromEntropy(_ entropy: Data) throws -> String {
        guard entropy.count == 16 || entropy.count == 20 || entropy.count == 24 ||
              entropy.count == 28 || entropy.count == 32 else {
            throw KeyManagerError.invalidSeed
        }
        
        // Calculate checksum
        let hash = Crypto.sha256(entropy)
        let checksumBits = entropy.count / 4 // 4 bits per 32 bits of entropy
        
        // Combine entropy + checksum bits
        var bits = entropy.toBits()
        let checksumBitsArray = hash.toBits().prefix(checksumBits)
        bits.append(contentsOf: checksumBitsArray)
        
        // Split into 11-bit groups
        var words: [String] = []
        for i in stride(from: 0, to: bits.count, by: 11) {
            let chunk = Array(bits[i..<min(i + 11, bits.count)])
            let index = chunk.reduce(0) { ($0 << 1) | ($1 ? 1 : 0) }
            words.append(wordlist[index % wordlist.count])
        }
        
        return words.joined(separator: " ")
    }
    
    /// Validate a mnemonic phrase
    public static func validate(_ mnemonic: String) -> Bool {
        let words = mnemonic.lowercased().split(separator: " ").map(String.init)
        guard words.count == 12 || words.count == 15 || words.count == 18 ||
              words.count == 21 || words.count == 24 else {
            return false
        }
        
        // Check all words are in wordlist
        let wordSet = Set(wordlist)
        return words.allSatisfy { wordSet.contains($0) }
    }
    
    /// Convert mnemonic to seed using PBKDF2
    public static func toSeed(mnemonic: String, passphrase: String) throws -> Data {
        let password = mnemonic.decomposedStringWithCompatibilityMapping
        let salt = "mnemonic" + passphrase
        
        // PBKDF2-HMAC-SHA512 with 2048 iterations
        let passwordData = Data(password.utf8)
        let saltData = Data(salt.utf8)
        
        return try pbkdf2(password: passwordData, salt: saltData, iterations: 2048, keyLength: 64)
    }
    
    /// PBKDF2-HMAC-SHA512 implementation
    private static func pbkdf2(password: Data, salt: Data, iterations: Int, keyLength: Int) throws -> Data {
        var derivedKey = Data()
        var blockNum: UInt32 = 1
        
        while derivedKey.count < keyLength {
            // U1 = PRF(Password, Salt || INT(blockNum))
            var saltWithBlock = salt
            withUnsafeBytes(of: blockNum.bigEndian) { saltWithBlock.append(contentsOf: $0) }
            
            var u = hmacSHA512(key: password, data: saltWithBlock)
            var result = u
            
            // Ui = PRF(Password, U_{i-1})
            for _ in 1..<iterations {
                u = hmacSHA512(key: password, data: u)
                for j in 0..<result.count {
                    result[j] ^= u[j]
                }
            }
            
            derivedKey.append(result)
            blockNum += 1
        }
        
        return Data(derivedKey.prefix(keyLength))
    }
    
    private static func hmacSHA512(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey)
        return Data(mac)
    }
}

// MARK: - Ed25519 HD Key Derivation

/// Ed25519 hierarchical deterministic key derivation (SLIP-0010)
public enum Ed25519HD {
    
    private static let ed25519Curve = "ed25519 seed"
    
    /// Derive a key from a path like "m/44'/501'/0'/0'"
    public static func derivePath(_ path: String, seed: Data) throws -> Data {
        guard path.hasPrefix("m/") else {
            throw KeyManagerError.derivationFailed("Path must start with 'm/'")
        }
        
        // Get master key
        var (key, chainCode) = getMasterKeyFromSeed(seed)
        
        // Parse and derive each segment
        let segments = path.dropFirst(2).split(separator: "/")
        for segment in segments {
            let hardened = segment.hasSuffix("'")
            let indexStr = hardened ? String(segment.dropLast()) : String(segment)
            guard let index = UInt32(indexStr) else {
                throw KeyManagerError.derivationFailed("Invalid path segment: \(segment)")
            }
            
            let hardenedIndex = hardened ? (0x80000000 + index) : index
            (key, chainCode) = deriveChild(parentKey: key, chainCode: chainCode, index: hardenedIndex)
        }
        
        return key
    }
    
    private static func getMasterKeyFromSeed(_ seed: Data) -> (key: Data, chainCode: Data) {
        let key = SymmetricKey(data: Data(ed25519Curve.utf8))
        let mac = HMAC<SHA512>.authenticationCode(for: seed, using: key)
        let macData = Data(mac)
        return (Data(macData.prefix(32)), Data(macData.suffix(32)))
    }
    
    private static func deriveChild(parentKey: Data, chainCode: Data, index: UInt32) -> (key: Data, chainCode: Data) {
        var data = Data([0x00])
        data.append(parentKey)
        withUnsafeBytes(of: index.bigEndian) { data.append(contentsOf: $0) }
        
        let key = SymmetricKey(data: chainCode)
        let mac = HMAC<SHA512>.authenticationCode(for: data, using: key)
        let macData = Data(mac)
        
        return (Data(macData.prefix(32)), Data(macData.suffix(32)))
    }
}

// MARK: - Base58 Encoding

/// Base58 encoding/decoding (Bitcoin/Solana style)
public enum Base58 {
    
    private static let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private static let alphabetArray = Array(alphabet)
    private static let baseCount = BigUInt(58)
    
    /// Encode data to base58 string
    public static func encode(_ data: Data) -> String {
        var num = BigUInt(data)
        var result = ""
        
        while num > 0 {
            let (quotient, remainder) = num.quotientAndRemainder(dividingBy: baseCount)
            result = String(alphabetArray[Int(remainder)]) + result
            num = quotient
        }
        
        // Add leading '1's for leading zeros
        for byte in data {
            if byte == 0 {
                result = "1" + result
            } else {
                break
            }
        }
        
        return result
    }
    
    /// Decode base58 string to data
    public static func decode(_ string: String) -> Data? {
        var num = BigUInt.zero
        
        for char in string {
            guard let index = alphabet.firstIndex(of: char) else {
                return nil
            }
            num = num * baseCount + BigUInt(alphabet.distance(from: alphabet.startIndex, to: index))
        }
        
        var bytes = Crypto.bigintToBytes32(num)
        
        // Handle leading '1's (zeros)
        var leadingZeros = 0
        for char in string {
            if char == "1" {
                leadingZeros += 1
            } else {
                break
            }
        }
        
        if leadingZeros > 0 {
            bytes = Data(repeating: 0, count: leadingZeros) + bytes.dropFirst(leadingZeros)
        }
        
        return bytes
    }
}

// MARK: - Data Extensions

extension Data {
    /// Convert data to array of bits
    func toBits() -> [Bool] {
        var bits: [Bool] = []
        for byte in self {
            for i in (0..<8).reversed() {
                bits.append((byte >> i) & 1 == 1)
            }
        }
        return bits
    }
}

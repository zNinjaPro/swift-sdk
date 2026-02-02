// ShieldedPoolSDK - Full SDK with Solana integration
// This module depends on ShieldedPoolCore and SolanaSwift

import Foundation
import ShieldedPoolCore
import SolanaSwift

// MARK: - Re-export Core Types
public typealias Note = ShieldedPoolCore.Note
public typealias SpendingKeys = ShieldedPoolCore.SpendingKeys
public typealias MerkleProof = ShieldedPoolCore.MerkleProof
public typealias BalanceInfo = ShieldedPoolCore.BalanceInfo
public typealias Groth16Proof = ShieldedPoolCore.Groth16Proof
public typealias EpochState = ShieldedPoolCore.EpochState
public typealias ProverConfig = ShieldedPoolCore.ProverConfig
public typealias CircuitType = ShieldedPoolCore.CircuitType

// MARK: - SDK Configuration

/// Configuration for the ShieldedPool SDK
public struct ShieldedPoolConfig: Sendable {
    /// RPC endpoint URL
    public let rpcURL: String
    
    /// WebSocket endpoint URL (for subscriptions)
    public let wsURL: String?
    
    /// Shielded pool program ID
    public let programId: String
    
    /// Pool configuration account
    public let poolConfig: String
    
    /// Token mint address
    public let tokenMint: String
    
    /// Burn rate in basis points (10 = 0.1%)
    public let burnRateBps: UInt16
    
    /// Path to withdraw circuit zkey
    public let withdrawZkeyPath: String
    
    /// Path to transfer circuit zkey
    public let transferZkeyPath: String
    
    /// Path to renew circuit zkey (optional)
    public let renewZkeyPath: String?
    
    /// Network cluster
    public let cluster: Cluster
    
    /// Enum for Solana clusters
    public enum Cluster: String, Sendable {
        case mainnet = "mainnet-beta"
        case devnet = "devnet"
        case localnet = "localnet"
    }
    
    public init(
        rpcURL: String,
        wsURL: String? = nil,
        programId: String,
        poolConfig: String,
        tokenMint: String,
        burnRateBps: UInt16 = 10,
        withdrawZkeyPath: String,
        transferZkeyPath: String,
        renewZkeyPath: String? = nil,
        cluster: Cluster = .devnet
    ) {
        self.rpcURL = rpcURL
        self.wsURL = wsURL
        self.programId = programId
        self.poolConfig = poolConfig
        self.tokenMint = tokenMint
        self.burnRateBps = burnRateBps
        self.withdrawZkeyPath = withdrawZkeyPath
        self.transferZkeyPath = transferZkeyPath
        self.renewZkeyPath = renewZkeyPath
        self.cluster = cluster
    }
    
    /// Create devnet configuration
    public static func devnet(
        programId: String,
        poolConfig: String,
        tokenMint: String,
        burnRateBps: UInt16 = 10,
        zkeyBasePath: String
    ) -> ShieldedPoolConfig {
        return ShieldedPoolConfig(
            rpcURL: "https://api.devnet.solana.com",
            wsURL: "wss://api.devnet.solana.com",
            programId: programId,
            poolConfig: poolConfig,
            tokenMint: tokenMint,
            burnRateBps: burnRateBps,
            withdrawZkeyPath: "\(zkeyBasePath)/withdraw.zkey",
            transferZkeyPath: "\(zkeyBasePath)/transfer.zkey",
            renewZkeyPath: "\(zkeyBasePath)/renew.zkey",
            cluster: .devnet
        )
    }
    
    /// Create localnet configuration
    public static func localnet(
        programId: String,
        poolConfig: String,
        tokenMint: String,
        burnRateBps: UInt16 = 10,
        zkeyBasePath: String
    ) -> ShieldedPoolConfig {
        return ShieldedPoolConfig(
            rpcURL: "http://localhost:8899",
            wsURL: "ws://localhost:8900",
            programId: programId,
            poolConfig: poolConfig,
            tokenMint: tokenMint,
            burnRateBps: burnRateBps,
            withdrawZkeyPath: "\(zkeyBasePath)/withdraw.zkey",
            transferZkeyPath: "\(zkeyBasePath)/transfer.zkey",
            renewZkeyPath: "\(zkeyBasePath)/renew.zkey",
            cluster: .localnet
        )
    }
}

// MARK: - Shielded Pool Client

/// Main client for interacting with the shielded pool
public class ShieldedPoolClient {
    
    // MARK: - Properties
    
    /// SDK configuration
    public let config: ShieldedPoolConfig
    
    /// SolanaSwift API client
    public let solana: SolanaAPIClient
    
    /// Key manager for wallet operations
    public let keyManager: ShieldedPoolCore.KeyManager
    
    /// Note manager for UTXO tracking
    public let noteManager: ShieldedPoolCore.NoteManager
    
    /// Transaction builder
    public let txBuilder: ShieldedPoolCore.TxBuilder
    
    /// Event scanner
    public let scanner: ShieldedPoolCore.UTXOScanner
    
    /// Current epoch
    private var currentEpoch: UInt64 = 0
    
    /// Epoch Merkle trees
    private var epochTrees: [UInt64: ShieldedPoolCore.EpochMerkleTree] = [:]
    
    /// Program ID as data
    private let programIdData: Data
    
    /// Pool config as data
    private let poolConfigData: Data
    
    /// Token mint as data
    private let tokenMintData: Data
    
    // MARK: - Initialization
    
    /// Initialize the shielded pool client
    /// - Parameters:
    ///   - config: SDK configuration
    ///   - mnemonic: BIP39 mnemonic for wallet
    public init(config: ShieldedPoolConfig, mnemonic: String) throws {
        self.config = config
        
        // Decode addresses
        guard let programId = Base58.decode(config.programId),
              let poolConfig = Base58.decode(config.poolConfig),
              let tokenMint = Base58.decode(config.tokenMint) else {
            throw ShieldedPoolError.invalidAddress
        }
        self.programIdData = programId
        self.poolConfigData = poolConfig
        self.tokenMintData = tokenMint
        
        // Initialize Solana client
        self.solana = JSONRPCAPIClient(endpoint: APIEndPoint(address: config.rpcURL, network: .devnet))
        
        // Initialize key manager
        self.keyManager = try ShieldedPoolCore.KeyManager.fromMnemonic(mnemonic)
        
        // Initialize note manager
        let spendingKeys = keyManager.exportKeys()
        self.noteManager = ShieldedPoolCore.NoteManager(spendingKeys: spendingKeys)
        
        // Initialize prover (for transaction building)
        let proverConfig = ProverConfig(
            zkeyPath: config.withdrawZkeyPath,
            witnesscalcPath: nil,
            circuitType: .withdraw
        )
        let prover = ShieldedPoolCore.ZKProver(config: proverConfig)
        
        // Initialize transaction builder
        self.txBuilder = ShieldedPoolCore.TxBuilder(
            prover: prover,
            poolId: poolConfig,
            tokenMint: tokenMint
        )
        
        // Initialize scanner
        self.scanner = ShieldedPoolCore.UTXOScanner(
            viewingKey: keyManager.viewingKey,
            tokenMint: tokenMint,
            poolId: poolConfig,
            noteManager: noteManager
        )
    }
    
    /// Initialize from seed bytes
    public init(config: ShieldedPoolConfig, seed: Data) throws {
        self.config = config
        
        // Decode addresses
        guard let programId = Base58.decode(config.programId),
              let poolConfig = Base58.decode(config.poolConfig),
              let tokenMint = Base58.decode(config.tokenMint) else {
            throw ShieldedPoolError.invalidAddress
        }
        self.programIdData = programId
        self.poolConfigData = poolConfig
        self.tokenMintData = tokenMint
        
        // Initialize Solana client
        self.solana = JSONRPCAPIClient(endpoint: APIEndPoint(address: config.rpcURL, network: .devnet))
        
        // Initialize key manager
        self.keyManager = ShieldedPoolCore.KeyManager.fromSeed(seed)
        
        // Initialize note manager
        let spendingKeys2 = keyManager.exportKeys()
        self.noteManager = ShieldedPoolCore.NoteManager(spendingKeys: spendingKeys2)
        
        // Initialize prover
        let proverConfig = ProverConfig(
            zkeyPath: config.withdrawZkeyPath,
            witnesscalcPath: nil,
            circuitType: .withdraw
        )
        let prover = ShieldedPoolCore.ZKProver(config: proverConfig)
        
        // Initialize transaction builder
        self.txBuilder = ShieldedPoolCore.TxBuilder(
            prover: prover,
            poolId: poolConfig,
            tokenMint: tokenMint
        )
        
        // Initialize scanner
        self.scanner = ShieldedPoolCore.UTXOScanner(
            viewingKey: keyManager.viewingKey,
            tokenMint: tokenMint,
            poolId: poolConfig,
            noteManager: noteManager
        )
    }
    
    // MARK: - Wallet Info
    
    /// Get the shielded address (for receiving deposits)
    public func getShieldedAddress() -> String {
        return Base58.encode(keyManager.shieldedAddress)
    }
    
    /// Get the viewing key (for read-only access)
    public func getViewingKey() -> Data {
        return keyManager.viewingKey
    }
    
    /// Get the spending keys
    public func getSpendingKeys() -> SpendingKeys {
        return keyManager.exportKeys()
    }
    
    // MARK: - Balance
    
    /// Get the current shielded balance
    public func getBalance() -> BalanceInfo {
        return noteManager.calculateBalanceInfo()
    }
    
    /// Get all unspent notes
    public func getNotes() -> [Note] {
        return noteManager.getNotes()
    }
    
    /// Get notes that need renewal
    public func getExpiringNotes() -> [Note] {
        return noteManager.getExpiringNotes()
    }
    
    // MARK: - Epoch Management
    
    /// Sync with on-chain epoch state
    public func syncEpoch() async throws {
        // Fetch pool config to get current epoch
        // This would use Solana RPC to fetch and decode the pool config account
        // For now, just update the txBuilder
        txBuilder.setCurrentEpoch(currentEpoch)
        noteManager.setCurrentEpoch(currentEpoch)
        scanner.setCurrentEpoch(currentEpoch)
    }
    
    /// Get the current epoch number
    public func getCurrentEpoch() -> UInt64 {
        return currentEpoch
    }
    
    /// Get or create a Merkle tree for an epoch
    public func getEpochTree(_ epoch: UInt64) -> ShieldedPoolCore.EpochMerkleTree? {
        if let tree = epochTrees[epoch] {
            return tree
        }
        
        // Create new tree for epoch
        let tree = ShieldedPoolCore.EpochMerkleTree(epoch: epoch)
        epochTrees[epoch] = tree
        return tree
    }
    
    // MARK: - Deposits
    
    /// Prepare a deposit transaction
    /// - Parameters:
    ///   - amount: Amount to deposit in lamports
    /// - Returns: Prepared deposit data
    public func prepareDeposit(amount: UInt64) throws -> PreparedDeposit {
        return try txBuilder.prepareDeposit(
            amount: amount,
            recipientAddress: keyManager.shieldedAddress,
            viewingKey: keyManager.viewingKey
        )
    }
    
    /// Prepare a deposit to another address
    /// - Parameters:
    ///   - amount: Amount to deposit
    ///   - recipient: Recipient's shielded address (base58)
    /// - Returns: Prepared deposit data
    public func prepareDepositTo(amount: UInt64, recipient: String) throws -> PreparedDeposit {
        guard let recipientData = Base58.decode(recipient) else {
            throw ShieldedPoolError.invalidAddress
        }
        return try txBuilder.prepareDeposit(
            amount: amount,
            recipientAddress: recipientData,
            viewingKey: recipientData // Use recipient as viewing key
        )
    }
    
    // MARK: - Withdrawals
    
    /// Prepare a withdrawal transaction
    /// - Parameters:
    ///   - amount: Amount to withdraw
    ///   - recipient: Recipient public key (base58)
    /// - Returns: Prepared withdrawal data
    public func prepareWithdraw(amount: UInt64, recipient: String) async throws -> PreparedWithdraw {
        guard let recipientData = Base58.decode(recipient) else {
            throw ShieldedPoolError.invalidAddress
        }
        
        // Select notes to spend
        let notes = try noteManager.selectNotes(amount: amount)
        guard let note = notes.first else {
            throw ShieldedPoolError.insufficientBalance
        }
        
        // Get epoch tree
        guard let epoch = note.epoch,
              let tree = getEpochTree(epoch) else {
            throw ShieldedPoolError.epochNotFound
        }
        
        return try await txBuilder.prepareWithdraw(
            inputNote: note,
            spendingKeys: keyManager.exportKeys(),
            recipient: recipientData,
            amount: amount,
            merkleTree: tree
        )
    }
    
    // MARK: - Transfers
    
    /// Prepare a shielded transfer
    /// - Parameters:
    ///   - amount: Amount to transfer
    ///   - recipient: Recipient's shielded address (base58)
    /// - Returns: Prepared transfer data
    public func prepareTransfer(amount: UInt64, recipient: String) async throws -> PreparedTransfer {
        guard let recipientData = Base58.decode(recipient) else {
            throw ShieldedPoolError.invalidAddress
        }
        
        // Select notes to spend
        let notes = try noteManager.selectNotes(amount: amount)
        
        // Build outputs
        let outputs: [(address: Data, amount: UInt64)] = [
            (address: recipientData, amount: amount)
        ]
        
        // Add change output if needed
        let inputSum = notes.reduce(0) { $0 + $1.value }
        var finalOutputs = outputs
        if inputSum > amount {
            let change = inputSum - amount
            finalOutputs.append((address: keyManager.shieldedAddress, amount: change))
        }
        
        return try await txBuilder.prepareTransfer(
            inputNotes: notes,
            outputs: finalOutputs,
            spendingKeys: keyManager.exportKeys(),
            epochTrees: epochTrees
        )
    }
    
    // MARK: - Renewals
    
    /// Prepare renewal transactions for expiring notes
    /// - Returns: Array of prepared renewal transactions
    public func prepareRenewals() async throws -> [PreparedRenew] {
        let expiringNotes = noteManager.getExpiringNotes()
        var renewals: [PreparedRenew] = []
        
        for note in expiringNotes {
            guard let epoch = note.epoch,
                  let tree = getEpochTree(epoch) else {
                continue
            }
            
            let renewal = try await txBuilder.prepareRenew(
                oldNote: note,
                spendingKeys: keyManager.exportKeys(),
                viewingKey: keyManager.viewingKey,
                oldTree: tree
            )
            renewals.append(renewal)
        }
        
        return renewals
    }
    
    // MARK: - Event Processing
    
    /// Process transaction logs to update UTXO state
    public func processTransactionLogs(_ logs: [String]) {
        scanner.processTransactionLogs(logs)
    }
    
    /// Process raw event data
    public func processEventData(_ data: Data) {
        scanner.processEventData(data)
    }
    
    // MARK: - State Management
    
    /// Add a pending note (for optimistic updates)
    public func addPendingNote(_ note: Note) {
        noteManager.addPendingNote(note)
    }
    
    /// Clear all cached state
    public func clearState() {
        noteManager.clear()
        epochTrees.removeAll()
    }
}

// MARK: - Base58 Helper

/// Base58 encoding/decoding utility
public enum Base58 {
    private static let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private static let alphabetArray = Array(alphabet)
    
    /// Encode data to Base58 string
    public static func encode(_ data: Data) -> String {
        var bytes = Array(data)
        var result: [Character] = []
        
        // Count leading zeros
        var leadingZeros = 0
        for byte in bytes {
            if byte == 0 {
                leadingZeros += 1
            } else {
                break
            }
        }
        
        // Convert to base58
        while !bytes.isEmpty && bytes.contains(where: { $0 != 0 }) {
            var carry = 0
            var newBytes: [UInt8] = []
            
            for byte in bytes {
                carry = carry * 256 + Int(byte)
                if !newBytes.isEmpty || carry >= 58 {
                    newBytes.append(UInt8(carry / 58))
                }
                carry = carry % 58
            }
            
            result.insert(alphabetArray[carry], at: 0)
            bytes = newBytes
        }
        
        // Add leading '1's for zeros
        let leadingOnes = String(repeating: "1", count: leadingZeros)
        return leadingOnes + String(result)
    }
    
    /// Decode Base58 string to data
    public static func decode(_ string: String) -> Data? {
        var result: [UInt8] = [0]
        
        for char in string {
            guard let index = alphabet.firstIndex(of: char) else {
                return nil
            }
            let digit = alphabet.distance(from: alphabet.startIndex, to: index)
            
            var carry = digit
            for i in (0..<result.count).reversed() {
                carry += Int(result[i]) * 58
                result[i] = UInt8(carry % 256)
                carry /= 256
            }
            
            while carry > 0 {
                result.insert(UInt8(carry % 256), at: 0)
                carry /= 256
            }
        }
        
        // Handle leading '1's
        var leadingZeros = 0
        for char in string {
            if char == "1" {
                leadingZeros += 1
            } else {
                break
            }
        }
        
        let leadingZeroBytes = [UInt8](repeating: 0, count: leadingZeros)
        return Data(leadingZeroBytes + result.drop(while: { $0 == 0 }))
    }
}

// MARK: - Errors

public enum ShieldedPoolError: Error, CustomStringConvertible {
    case invalidAddress
    case insufficientBalance
    case epochNotFound
    case noteNotFound
    case proofGenerationFailed
    case transactionFailed(String)
    case networkError(String)
    
    public var description: String {
        switch self {
        case .invalidAddress:
            return "Invalid address format"
        case .insufficientBalance:
            return "Insufficient shielded balance"
        case .epochNotFound:
            return "Epoch tree not found"
        case .noteNotFound:
            return "Note not found"
        case .proofGenerationFailed:
            return "Failed to generate ZK proof"
        case .transactionFailed(let msg):
            return "Transaction failed: \(msg)"
        case .networkError(let msg):
            return "Network error: \(msg)"
        }
    }
}

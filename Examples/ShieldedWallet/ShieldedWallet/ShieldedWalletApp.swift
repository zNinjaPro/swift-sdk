import SwiftUI
import ShieldedPoolSDK
import ShieldedPoolCore

@main
struct ShieldedWalletApp: App {
    @StateObject private var walletManager = WalletManager()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(walletManager)
        }
    }
}

// MARK: - Wallet Manager

@MainActor
class WalletManager: ObservableObject {
    
    // MARK: - Published State
    
    @Published var isInitialized = false
    @Published var isLoading = false
    @Published var errorMessage: String?
    
    @Published var shieldedAddress: String = ""
    @Published var balance: BalanceInfo?
    @Published var notes: [Note] = []
    @Published var circuitStatus: [CircuitArtifact: CircuitArtifactManager.CircuitStatus] = [:]
    
    // MARK: - Private
    
    private var client: ShieldedPoolClient?
    private let artifactManager = CircuitArtifactManager.shared
    
    // MARK: - Configuration
    
    /// Default devnet configuration
    private var config: ShieldedPoolConfig {
        // TODO: Replace with actual deployed addresses
        ShieldedPoolConfig.devnet(
            programId: "ShieLdxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            poolConfig: "PoooLxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxX",
            tokenMint: "So11111111111111111111111111111111111111112", // Wrapped SOL
            zkeyBasePath: artifactManager.artifactsDirectory.path
        )
    }
    
    // MARK: - Initialization
    
    init() {
        // Configure artifact manager with download URL
        // TODO: Replace with actual artifact hosting URL
        if let baseURL = URL(string: "https://artifacts.shieldedpool.dev/circuits/") {
            artifactManager.configure(
                baseURL: baseURL,
                appGroupIdentifier: "group.dev.shieldedpool.wallet"
            )
        }
        
        // Try to copy bundled artifacts
        try? artifactManager.copyBundledArtifacts()
        
        // Update circuit status
        updateCircuitStatus()
    }
    
    // MARK: - Wallet Setup
    
    /// Create a new wallet with a fresh mnemonic
    func createWallet() async throws -> String {
        isLoading = true
        defer { isLoading = false }
        
        // Generate mnemonic (in production, use secure generation)
        let mnemonic = generateMnemonic()
        
        try await initializeClient(mnemonic: mnemonic)
        
        return mnemonic
    }
    
    /// Import wallet from mnemonic
    func importWallet(mnemonic: String) async throws {
        isLoading = true
        defer { isLoading = false }
        
        try await initializeClient(mnemonic: mnemonic)
    }
    
    private func initializeClient(mnemonic: String) async throws {
        do {
            client = try ShieldedPoolClient(config: config, mnemonic: mnemonic)
            shieldedAddress = client!.getShieldedAddress()
            
            // Sync with chain
            try await client?.syncEpoch()
            
            // Update balance
            refreshBalance()
            
            isInitialized = true
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
            throw error
        }
    }
    
    // MARK: - Balance & Notes
    
    func refreshBalance() {
        guard let client = client else { return }
        balance = client.getBalance()
        notes = client.getNotes()
    }
    
    // MARK: - Transactions
    
    /// Prepare a deposit transaction
    func prepareDeposit(amount: UInt64) async throws -> PreparedDeposit {
        guard let client = client else {
            throw WalletError.notInitialized
        }
        
        // Ensure withdraw circuit is ready (for change handling)
        let withdrawReady = artifactManager.isCircuitReady(.withdraw)
        if !withdrawReady {
            throw WalletError.circuitNotReady(.withdraw)
        }
        
        return try client.prepareDeposit(amount: amount)
    }
    
    /// Prepare a withdrawal transaction
    func prepareWithdraw(amount: UInt64, recipient: String) async throws -> PreparedWithdraw {
        guard let client = client else {
            throw WalletError.notInitialized
        }
        
        // Ensure withdraw circuit is ready
        let withdrawReady = artifactManager.isCircuitReady(.withdraw)
        if !withdrawReady {
            throw WalletError.circuitNotReady(.withdraw)
        }
        
        isLoading = true
        defer { isLoading = false }
        
        return try await client.prepareWithdraw(amount: amount, recipient: recipient)
    }
    
    /// Prepare a shielded transfer
    func prepareTransfer(amount: UInt64, recipient: String) async throws -> PreparedTransfer {
        guard let client = client else {
            throw WalletError.notInitialized
        }
        
        // Ensure transfer circuit is ready
        let transferReady = artifactManager.isCircuitReady(.transfer)
        if !transferReady {
            throw WalletError.circuitNotReady(.transfer)
        }
        
        isLoading = true
        defer { isLoading = false }
        
        return try await client.prepareTransfer(amount: amount, recipient: recipient)
    }
    
    // MARK: - Circuit Management
    
    func updateCircuitStatus() {
        circuitStatus = artifactManager.getCircuitStatus()
    }
    
    func downloadCircuit(_ circuit: CircuitArtifact) async throws {
        isLoading = true
        defer { 
            isLoading = false
            updateCircuitStatus()
        }
        
        try await artifactManager.downloadCircuit(circuit)
    }
    
    // MARK: - Helpers
    
    private func generateMnemonic() -> String {
        // Simple 12-word mnemonic generation
        // In production, use a proper BIP39 implementation
        let words = [
            "abandon", "ability", "able", "about", "above", "absent",
            "absorb", "abstract", "absurd", "abuse", "access", "accident"
        ]
        return words.joined(separator: " ")
    }
}

// MARK: - Errors

enum WalletError: Error, LocalizedError {
    case notInitialized
    case circuitNotReady(CircuitArtifact)
    case invalidAmount
    case invalidAddress
    
    var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "Wallet not initialized"
        case .circuitNotReady(let circuit):
            return "Circuit '\(circuit.rawValue)' not downloaded. Please download required circuits first."
        case .invalidAmount:
            return "Invalid amount"
        case .invalidAddress:
            return "Invalid address"
        }
    }
}

import Foundation
import SolanaSwift
import ShieldedPoolCore

/// High-level transaction submission layer for the shielded pool.
/// Combines TxBuilder (data prep) → ShieldedPoolInstructions (serialization) → SolanaSwift (RPC).
///
/// Usage:
/// ```swift
/// let transactor = try ShieldedPoolTransactor(config: .localnet(...), seed: seed)
/// let txId = try await transactor.deposit(amount: 1_000_000)
/// let txId = try await transactor.withdraw(amount: 500_000, recipient: recipientPubkey)
/// ```
public class ShieldedPoolTransactor {

    // MARK: - Properties

    public let programId: PublicKey
    public let mint: PublicKey
    public let poolConfigPDA: PublicKey
    public let vaultAuthorityPDA: PublicKey
    public let vaultPDA: PublicKey

    private let apiClient: SolanaAPIClient
    private let blockchainClient: SolanaBlockchainClient
    private let keyManager: ShieldedPoolCore.KeyManager
    private let solanaKeyPair: KeyPair
    private let noteManager: ShieldedPoolCore.NoteManager
    private let txBuilder: ShieldedPoolCore.TxBuilder
    private let scanner: ShieldedPoolCore.UTXOScanner
    private let tokenMintData: Data

    private var currentEpoch: UInt64 = 0
    private var epochTrees: [UInt64: ShieldedPoolCore.EpochMerkleTree] = [:]

    // MARK: - Initialization

    /// Create a transactor from a 32-byte seed.
    /// The seed derives both the shielded pool keys AND the Solana keypair for signing.
    public init(
        config: ShieldedPoolConfig,
        seed: Data,
        solanaKeyPair: KeyPair
    ) throws {
        guard let progId = try? PublicKey(string: config.programId),
              let mintKey = try? PublicKey(string: config.tokenMint) else {
            throw ShieldedPoolError.invalidAddress
        }

        self.programId = progId
        self.mint = mintKey
        self.solanaKeyPair = solanaKeyPair
        self.tokenMintData = mintKey.data

        // Derive PDAs
        let (poolCfg, _) = try ShieldedPoolPDAs.poolConfig(mint: mintKey, programId: progId)
        self.poolConfigPDA = poolCfg
        let (va, _) = try ShieldedPoolPDAs.vaultAuthority(poolConfig: poolCfg, programId: progId)
        self.vaultAuthorityPDA = va
        let (v, _) = try ShieldedPoolPDAs.vault(poolConfig: poolCfg, programId: progId)
        self.vaultPDA = v

        // Initialize crypto layer
        self.keyManager = ShieldedPoolCore.KeyManager.fromSeed(seed)
        let keys = keyManager.exportKeys()
        self.noteManager = ShieldedPoolCore.NoteManager(spendingKeys: keys)

        // Initialize Solana clients
        let endpoint = APIEndPoint(address: config.rpcURL, network: .devnet)
        self.apiClient = JSONRPCAPIClient(endpoint: endpoint)
        self.blockchainClient = BlockchainClient(apiClient: apiClient)

        // Initialize TxBuilder (prover will throw frameworkNotIntegrated — use mock proofs for now)
        let proverConfig = ShieldedPoolCore.ProverConfig(
            zkeyPath: config.withdrawZkeyPath,
            circuitType: .withdraw
        )
        let prover = ShieldedPoolCore.ZKProver(config: proverConfig)
        self.txBuilder = ShieldedPoolCore.TxBuilder(
            prover: prover,
            poolId: poolCfg.data,
            tokenMint: mintKey.data
        )

        // Initialize scanner
        self.scanner = ShieldedPoolCore.UTXOScanner(
            viewingKey: keyManager.viewingKey,
            tokenMint: mintKey.data,
            poolId: poolCfg.data,
            noteManager: noteManager
        )
    }

    // MARK: - Epoch Management

    /// Set current epoch (call after syncing with chain)
    public func setCurrentEpoch(_ epoch: UInt64) {
        currentEpoch = epoch
        txBuilder.setCurrentEpoch(epoch)
        noteManager.setCurrentEpoch(epoch)
        scanner.setCurrentEpoch(epoch)
    }

    /// Get or create a local Merkle tree for an epoch
    public func getOrCreateTree(epoch: UInt64) -> ShieldedPoolCore.EpochMerkleTree {
        if let tree = epochTrees[epoch] {
            return tree
        }
        let tree = ShieldedPoolCore.EpochMerkleTree(epoch: epoch)
        epochTrees[epoch] = tree
        return tree
    }

    // MARK: - Deposit

    /// Deposit tokens into the shielded pool.
    /// Returns the transaction signature.
    public func deposit(
        amount: UInt64,
        depositorTokenAccount: PublicKey
    ) async throws -> String {
        // 1. Prepare deposit data
        let prepared = try txBuilder.prepareDeposit(
            amount: amount,
            recipientAddress: keyManager.shieldedAddress,
            viewingKey: keyManager.viewingKey
        )

        // 2. Derive epoch tree + leaf chunk PDAs
        let (epochTreePDA, _) = try ShieldedPoolPDAs.epochTree(
            poolConfig: poolConfigPDA, epoch: currentEpoch, programId: programId)

        // Leaf chunk 0 for now (TODO: track deposit count per epoch)
        let (leafChunkPDA, _) = try ShieldedPoolPDAs.leafChunk(
            poolConfig: poolConfigPDA, epoch: currentEpoch, chunkIndex: 0, programId: programId)

        // 3. Build instruction
        let ix = ShieldedPoolInstructions.depositV2(
            commitment: prepared.commitment,
            amount: amount,
            encryptedNote: prepared.encryptedNote,
            accounts: ShieldedPoolInstructions.DepositV2Accounts(
                poolConfig: poolConfigPDA,
                epochTree: epochTreePDA,
                leafChunk: leafChunkPDA,
                vault: vaultPDA,
                depositorTokenAccount: depositorTokenAccount,
                mint: mint,
                depositor: solanaKeyPair.publicKey
            ),
            programId: programId
        )

        // 4. Send transaction
        let preparedTx = try await blockchainClient.prepareTransaction(
            instructions: [ix],
            signers: [solanaKeyPair],
            feePayer: solanaKeyPair.publicKey,
            feeCalculator: nil
        )

        let txId = try await blockchainClient.sendTransaction(preparedTransaction: preparedTx)

        // 5. Track pending note
        noteManager.addPendingNote(prepared.outputNote)

        return txId
    }

    // MARK: - Withdraw (Mock Proof)

    /// Withdraw from the shielded pool using mock proofs.
    /// Only works against programs built with `mock-verifier` feature.
    /// Returns the transaction signature.
    public func withdrawWithMockProof(
        amount: UInt64,
        recipientTokenAccount: PublicKey,
        recipient: PublicKey
    ) async throws -> String {
        // 1. Select notes
        let notes = try noteManager.selectNotes(amount: amount)
        guard let note = notes.first,
              let epoch = note.epoch,
              let leafIndex = note.leafIndex else {
            throw ShieldedPoolError.noteNotFound
        }

        // 2. Get Merkle proof
        let tree = getOrCreateTree(epoch: epoch)
        let merkleRoot = tree.getRoot()

        // 3. Compute nullifier
        let keys = keyManager.exportKeys()
        let nullifier = try ShieldedPoolCore.Crypto.computeNullifier(
            commitment: note.commitment,
            nullifierKey: keys.nullifierKey,
            epoch: epoch,
            leafIndex: leafIndex
        )

        // 4. Derive PDAs
        let (epochTreePDA, _) = try ShieldedPoolPDAs.epochTree(
            poolConfig: poolConfigPDA, epoch: epoch, programId: programId)
        let (nullifierMarkerPDA, _) = try ShieldedPoolPDAs.nullifierMarker(
            poolConfig: poolConfigPDA, nullifier: nullifier, programId: programId)
        let (verifierConfigPDA, _) = try ShieldedPoolPDAs.verifierConfig(
            poolConfig: poolConfigPDA, circuitName: "withdraw", programId: programId)

        // 5. Build instruction with mock proof (all zeros)
        let publicInputs = ShieldedPoolInstructions.WithdrawPublicInputs(
            root: merkleRoot,
            nullifier: nullifier,
            amount: amount,
            recipient: recipient,
            epoch: epoch,
            txAnchor: Data(count: 32), // zero for mock
            poolId: poolConfigPDA.data
        )

        let ix = ShieldedPoolInstructions.withdrawV2(
            proofBytes: ShieldedPoolInstructions.mockProofBytes(),
            publicInputs: publicInputs,
            accounts: ShieldedPoolInstructions.WithdrawV2Accounts(
                poolConfig: poolConfigPDA,
                epochTree: epochTreePDA,
                nullifierMarker: nullifierMarkerPDA,
                verifierConfig: verifierConfigPDA,
                vaultAuthority: vaultAuthorityPDA,
                vault: vaultPDA,
                recipientTokenAccount: recipientTokenAccount,
                mint: mint,
                payer: solanaKeyPair.publicKey
            ),
            programId: programId
        )

        // 6. Send transaction
        let preparedTx = try await blockchainClient.prepareTransaction(
            instructions: [ix],
            signers: [solanaKeyPair],
            feePayer: solanaKeyPair.publicKey,
            feeCalculator: nil
        )

        let txId = try await blockchainClient.sendTransaction(preparedTransaction: preparedTx)

        // 7. Mark note as spent locally
        noteManager.markSpent(commitment: note.commitment)

        return txId
    }

    // MARK: - Transfer (Mock Proof)

    /// Shielded transfer using mock proofs.
    /// Only works against programs built with `mock-verifier` feature.
    public func transferWithMockProof(
        amount: UInt64,
        recipientShieldedAddress: Data
    ) async throws -> String {
        // 1. Select input notes (need 2 for transfer circuit)
        let inputNotes = try noteManager.selectNotes(amount: amount, minNotes: 1)

        var inputs = inputNotes
        // Pad to 2 inputs if needed
        while inputs.count < 2 {
            inputs.append(ShieldedPoolCore.Note(
                value: 0, token: tokenMintData, owner: Data(count: 32),
                blinding: Data(count: 32), commitment: Data(count: 32),
                leafIndex: 0, epoch: currentEpoch,
                nullifier: Data(count: 32), randomness: Data(count: 32)
            ))
        }

        let inputSum = inputNotes.reduce(0 as UInt64) { $0 + $1.value }
        let change = inputSum - amount

        // 2. Create output notes
        let outRand1 = ShieldedPoolCore.Crypto.randomBytes(32)
        let outCommitment1 = try ShieldedPoolCore.Crypto.computeCommitment(
            value: amount, owner: recipientShieldedAddress, randomness: outRand1)

        let outRand2 = ShieldedPoolCore.Crypto.randomBytes(32)
        let outCommitment2 = try ShieldedPoolCore.Crypto.computeCommitment(
            value: change, owner: keyManager.shieldedAddress, randomness: outRand2)

        // 3. Compute nullifiers for both inputs
        let keys = keyManager.exportKeys()
        let nullifier1 = try ShieldedPoolCore.Crypto.computeNullifier(
            commitment: inputs[0].commitment, nullifierKey: keys.nullifierKey,
            epoch: inputs[0].epoch ?? 0, leafIndex: inputs[0].leafIndex ?? 0)
        let nullifier2 = try ShieldedPoolCore.Crypto.computeNullifier(
            commitment: inputs[1].commitment, nullifierKey: keys.nullifierKey,
            epoch: inputs[1].epoch ?? 0, leafIndex: inputs[1].leafIndex ?? 0)

        // 4. Encrypt output notes
        let encNote1 = try encryptOutputNote(
            value: amount, owner: recipientShieldedAddress, randomness: outRand1,
            viewingKey: recipientShieldedAddress)
        let encNote2 = try encryptOutputNote(
            value: change, owner: keyManager.shieldedAddress, randomness: outRand2,
            viewingKey: keyManager.viewingKey)

        // 5. Derive PDAs
        let spendEpoch = inputs[0].epoch ?? 0
        let (spendTreePDA, _) = try ShieldedPoolPDAs.epochTree(
            poolConfig: poolConfigPDA, epoch: spendEpoch, programId: programId)
        let (depositTreePDA, _) = try ShieldedPoolPDAs.epochTree(
            poolConfig: poolConfigPDA, epoch: currentEpoch, programId: programId)
        let (nfMarker1, _) = try ShieldedPoolPDAs.nullifierMarker(
            poolConfig: poolConfigPDA, nullifier: nullifier1, programId: programId)
        let (nfMarker2, _) = try ShieldedPoolPDAs.nullifierMarker(
            poolConfig: poolConfigPDA, nullifier: nullifier2, programId: programId)
        let (leafChunkPDA, _) = try ShieldedPoolPDAs.leafChunk(
            poolConfig: poolConfigPDA, epoch: currentEpoch, chunkIndex: 0, programId: programId)
        let (verifierPDA, _) = try ShieldedPoolPDAs.verifierConfig(
            poolConfig: poolConfigPDA, circuitName: "transfer", programId: programId)

        let spendTree = getOrCreateTree(epoch: spendEpoch)
        let merkleRoot = spendTree.getRoot()

        // 6. Build instruction
        let publicInputs = ShieldedPoolInstructions.TransferPublicInputs(
            root: merkleRoot,
            nullifier1: nullifier1,
            nullifier2: nullifier2,
            outputCommitment1: outCommitment1,
            outputCommitment2: outCommitment2,
            outputEpoch: currentEpoch,
            txAnchor: Data(count: 32),
            poolId: poolConfigPDA.data
        )

        let ix = ShieldedPoolInstructions.transferV2(
            proofBytes: ShieldedPoolInstructions.mockProofBytes(),
            publicInputs: publicInputs,
            encryptedNotes: [encNote1, encNote2],
            accounts: ShieldedPoolInstructions.TransferV2Accounts(
                poolConfig: poolConfigPDA,
                spendEpochTree: spendTreePDA,
                depositEpochTree: depositTreePDA,
                nullifierMarker1: nfMarker1,
                nullifierMarker2: nfMarker2,
                depositLeafChunk: leafChunkPDA,
                verifierConfig: verifierPDA,
                payer: solanaKeyPair.publicKey
            ),
            programId: programId
        )

        // 7. Send
        let preparedTx = try await blockchainClient.prepareTransaction(
            instructions: [ix],
            signers: [solanaKeyPair],
            feePayer: solanaKeyPair.publicKey,
            feeCalculator: nil
        )

        let txId = try await blockchainClient.sendTransaction(preparedTransaction: preparedTx)

        // 8. Update local state
        for note in inputNotes {
            noteManager.markSpent(commitment: note.commitment)
        }

        return txId
    }

    // MARK: - Pool Initialization (for testing)

    /// Initialize a V2 shielded pool. Used for localnet/devnet setup.
    public func initializePool(
        epochDurationSlots: UInt64 = 100,
        expirySlots: UInt64 = 300,
        finalizationDelaySlots: UInt64 = 10
    ) async throws -> String {
        let (epochTreePDA, _) = try ShieldedPoolPDAs.epochTree(
            poolConfig: poolConfigPDA, epoch: 0, programId: programId)

        let ix = ShieldedPoolInstructions.initializePoolV2(
            epochDurationSlots: epochDurationSlots,
            expirySlots: expirySlots,
            finalizationDelaySlots: finalizationDelaySlots,
            accounts: ShieldedPoolInstructions.InitializePoolV2Accounts(
                poolConfig: poolConfigPDA,
                epochTree: epochTreePDA,
                vaultAuthority: vaultAuthorityPDA,
                vault: vaultPDA,
                mint: mint,
                authority: solanaKeyPair.publicKey,
                payer: solanaKeyPair.publicKey
            ),
            programId: programId
        )

        let preparedTx = try await blockchainClient.prepareTransaction(
            instructions: [ix],
            signers: [solanaKeyPair],
            feePayer: solanaKeyPair.publicKey,
            feeCalculator: nil
        )

        return try await blockchainClient.sendTransaction(preparedTransaction: preparedTx)
    }

    /// Initialize a leaf chunk for the current epoch.
    public func initializeLeafChunk(
        epoch: UInt64? = nil,
        chunkIndex: UInt32 = 0
    ) async throws -> String {
        let ep = epoch ?? currentEpoch
        let (leafChunkPDA, _) = try ShieldedPoolPDAs.leafChunk(
            poolConfig: poolConfigPDA, epoch: ep, chunkIndex: chunkIndex, programId: programId)

        let ix = ShieldedPoolInstructions.initializeEpochLeafChunk(
            epoch: ep,
            chunkIndex: chunkIndex,
            poolConfig: poolConfigPDA,
            leafChunk: leafChunkPDA,
            payer: solanaKeyPair.publicKey,
            programId: programId
        )

        let preparedTx = try await blockchainClient.prepareTransaction(
            instructions: [ix],
            signers: [solanaKeyPair],
            feePayer: solanaKeyPair.publicKey,
            feeCalculator: nil
        )

        return try await blockchainClient.sendTransaction(preparedTransaction: preparedTx)
    }

    // MARK: - State Access

    public func getBalance() -> ShieldedPoolCore.BalanceInfo {
        noteManager.calculateBalanceInfo()
    }

    public func getNotes() -> [ShieldedPoolCore.Note] {
        noteManager.getNotes()
    }

    public func getShieldedAddress() -> String {
        ShieldedPoolCore.Base58.encode(keyManager.shieldedAddress)
    }

    /// Process raw event data from on-chain logs
    public func processEventData(_ data: Data) {
        scanner.processEventData(data)
    }

    /// Process transaction logs
    public func processTransactionLogs(_ logs: [String]) {
        scanner.processTransactionLogs(logs)
    }

    // MARK: - Private Helpers

    private func encryptOutputNote(
        value: UInt64, owner: Data, randomness: Data, viewingKey: Data
    ) throws -> Data {
        let serialized = ShieldedPoolCore.Crypto.serializeNote(
            value: value, token: tokenMintData, owner: owner, blinding: randomness)
        let (encrypted, nonce) = try ShieldedPoolCore.Crypto.encryptNote(
            noteData: serialized, viewingKey: viewingKey)
        return nonce + encrypted
    }
}

import Foundation
import SolanaSwift
import ShieldedPoolCore

/// Builds raw Solana `TransactionInstruction` objects for the shielded pool program.
/// Each method Borsh-serializes the args with the correct Anchor discriminator
/// and assembles the account list matching the on-chain IDL.
public enum ShieldedPoolInstructions {

    // MARK: - Anchor Discriminators (SHA256("global:<instruction_name>")[0..8])

    private static let DISC_INITIALIZE_POOL_V2: [UInt8]           = [0xcf, 0x2d, 0x57, 0xf2, 0x1b, 0x3f, 0xcc, 0x43]
    private static let DISC_INITIALIZE_EPOCH_LEAF_CHUNK: [UInt8]  = [0x80, 0xb5, 0xe0, 0xa7, 0xbd, 0xc3, 0xa1, 0xd3]
    private static let DISC_DEPOSIT_V2: [UInt8]                   = [0x6d, 0x4b, 0x45, 0x99, 0xac, 0xda, 0x92, 0x13]
    private static let DISC_WITHDRAW_V2: [UInt8]                  = [0xf2, 0x50, 0xa3, 0x00, 0xc4, 0xdd, 0xc2, 0xc2]
    private static let DISC_TRANSFER_V2: [UInt8]                  = [0x77, 0x28, 0x06, 0xeb, 0xea, 0xdd, 0xf8, 0x31]
    private static let DISC_RENEW_NOTE: [UInt8]                   = [0xcf, 0xfe, 0x07, 0x63, 0xcc, 0x44, 0xa3, 0xab]
    private static let DISC_ROLLOVER_EPOCH: [UInt8]               = [0xb2, 0x0c, 0x6a, 0xe9, 0x7d, 0x37, 0x3a, 0x6f]
    private static let DISC_FINALIZE_EPOCH: [UInt8]               = [0x9f, 0x5d, 0x75, 0xd9, 0x3f, 0x2c, 0xf9, 0x4c]

    // MARK: - Account Structs

    public struct InitializePoolV2Accounts {
        public let poolConfig: PublicKey
        public let epochTree: PublicKey
        public let vaultAuthority: PublicKey
        public let vault: PublicKey
        public let mint: PublicKey
        public let authority: PublicKey
        public let payer: PublicKey

        public init(poolConfig: PublicKey, epochTree: PublicKey, vaultAuthority: PublicKey,
                    vault: PublicKey, mint: PublicKey, authority: PublicKey, payer: PublicKey) {
            self.poolConfig = poolConfig; self.epochTree = epochTree
            self.vaultAuthority = vaultAuthority; self.vault = vault
            self.mint = mint; self.authority = authority; self.payer = payer
        }
    }

    public struct DepositV2Accounts {
        public let poolConfig: PublicKey
        public let epochTree: PublicKey
        public let leafChunk: PublicKey
        public let vault: PublicKey
        public let depositorTokenAccount: PublicKey
        public let mint: PublicKey
        public let depositor: PublicKey

        public init(poolConfig: PublicKey, epochTree: PublicKey, leafChunk: PublicKey,
                    vault: PublicKey, depositorTokenAccount: PublicKey, mint: PublicKey,
                    depositor: PublicKey) {
            self.poolConfig = poolConfig; self.epochTree = epochTree
            self.leafChunk = leafChunk; self.vault = vault
            self.depositorTokenAccount = depositorTokenAccount
            self.mint = mint; self.depositor = depositor
        }
    }

    public struct WithdrawV2Accounts {
        public let poolConfig: PublicKey
        public let epochTree: PublicKey
        public let nullifierMarker: PublicKey
        public let verifierConfig: PublicKey
        public let vaultAuthority: PublicKey
        public let vault: PublicKey
        public let recipientTokenAccount: PublicKey
        public let mint: PublicKey
        public let payer: PublicKey

        public init(poolConfig: PublicKey, epochTree: PublicKey, nullifierMarker: PublicKey,
                    verifierConfig: PublicKey, vaultAuthority: PublicKey, vault: PublicKey,
                    recipientTokenAccount: PublicKey, mint: PublicKey, payer: PublicKey) {
            self.poolConfig = poolConfig; self.epochTree = epochTree
            self.nullifierMarker = nullifierMarker; self.verifierConfig = verifierConfig
            self.vaultAuthority = vaultAuthority; self.vault = vault
            self.recipientTokenAccount = recipientTokenAccount
            self.mint = mint; self.payer = payer
        }
    }

    public struct TransferV2Accounts {
        public let poolConfig: PublicKey
        public let spendEpochTree: PublicKey
        public let depositEpochTree: PublicKey
        public let nullifierMarker1: PublicKey
        public let nullifierMarker2: PublicKey
        public let depositLeafChunk: PublicKey
        public let verifierConfig: PublicKey
        public let payer: PublicKey

        public init(poolConfig: PublicKey, spendEpochTree: PublicKey, depositEpochTree: PublicKey,
                    nullifierMarker1: PublicKey, nullifierMarker2: PublicKey,
                    depositLeafChunk: PublicKey, verifierConfig: PublicKey, payer: PublicKey) {
            self.poolConfig = poolConfig; self.spendEpochTree = spendEpochTree
            self.depositEpochTree = depositEpochTree
            self.nullifierMarker1 = nullifierMarker1; self.nullifierMarker2 = nullifierMarker2
            self.depositLeafChunk = depositLeafChunk; self.verifierConfig = verifierConfig
            self.payer = payer
        }
    }

    public struct RenewNoteAccounts {
        public let poolConfig: PublicKey
        public let oldEpochTree: PublicKey
        public let newEpochTree: PublicKey
        public let nullifierMarker: PublicKey
        public let newLeafChunk: PublicKey
        public let verifierConfig: PublicKey
        public let payer: PublicKey

        public init(poolConfig: PublicKey, oldEpochTree: PublicKey, newEpochTree: PublicKey,
                    nullifierMarker: PublicKey, newLeafChunk: PublicKey,
                    verifierConfig: PublicKey, payer: PublicKey) {
            self.poolConfig = poolConfig; self.oldEpochTree = oldEpochTree
            self.newEpochTree = newEpochTree; self.nullifierMarker = nullifierMarker
            self.newLeafChunk = newLeafChunk; self.verifierConfig = verifierConfig
            self.payer = payer
        }
    }

    // MARK: - Public Input Structs

    /// On-chain WithdrawPublicInputs layout
    public struct WithdrawPublicInputs {
        public let root: Data            // [u8; 32]
        public let nullifier: Data       // [u8; 32]
        public let amount: UInt64
        public let recipient: PublicKey
        public let epoch: UInt64
        public let txAnchor: Data        // [u8; 32] — recent blockhash or zeros
        public let poolId: Data          // [u8; 32]

        public init(root: Data, nullifier: Data, amount: UInt64, recipient: PublicKey,
                    epoch: UInt64, txAnchor: Data, poolId: Data) {
            self.root = root; self.nullifier = nullifier; self.amount = amount
            self.recipient = recipient; self.epoch = epoch
            self.txAnchor = txAnchor; self.poolId = poolId
        }

        func serialize() -> Data {
            var enc = BorshEncoder()
            enc.writeBytes32(root)
            enc.writeBytes32(nullifier)
            enc.writeU64(amount)
            enc.writePubkey(recipient.data)
            enc.writeU64(epoch)
            enc.writeBytes32(txAnchor)
            enc.writeBytes32(poolId)
            return enc.encode()
        }
    }

    /// On-chain TransferPublicInputs layout
    public struct TransferPublicInputs {
        public let root: Data
        public let nullifier1: Data
        public let nullifier2: Data
        public let outputCommitment1: Data
        public let outputCommitment2: Data
        public let outputEpoch: UInt64
        public let txAnchor: Data
        public let poolId: Data

        public init(root: Data, nullifier1: Data, nullifier2: Data,
                    outputCommitment1: Data, outputCommitment2: Data,
                    outputEpoch: UInt64, txAnchor: Data, poolId: Data) {
            self.root = root; self.nullifier1 = nullifier1; self.nullifier2 = nullifier2
            self.outputCommitment1 = outputCommitment1; self.outputCommitment2 = outputCommitment2
            self.outputEpoch = outputEpoch; self.txAnchor = txAnchor; self.poolId = poolId
        }

        func serialize() -> Data {
            var enc = BorshEncoder()
            enc.writeBytes32(root)
            enc.writeBytes32(nullifier1)
            enc.writeBytes32(nullifier2)
            enc.writeBytes32(outputCommitment1)
            enc.writeBytes32(outputCommitment2)
            enc.writeU64(outputEpoch)
            enc.writeBytes32(txAnchor)
            enc.writeBytes32(poolId)
            return enc.encode()
        }
    }

    /// On-chain RenewPublicInputs layout
    public struct RenewPublicInputs {
        public let oldRoot: Data
        public let nullifier: Data
        public let newCommitment: Data
        public let oldEpoch: UInt64
        public let newEpoch: UInt64
        public let txAnchor: Data
        public let poolId: Data

        public init(oldRoot: Data, nullifier: Data, newCommitment: Data,
                    oldEpoch: UInt64, newEpoch: UInt64, txAnchor: Data, poolId: Data) {
            self.oldRoot = oldRoot; self.nullifier = nullifier; self.newCommitment = newCommitment
            self.oldEpoch = oldEpoch; self.newEpoch = newEpoch
            self.txAnchor = txAnchor; self.poolId = poolId
        }

        func serialize() -> Data {
            var enc = BorshEncoder()
            enc.writeBytes32(oldRoot)
            enc.writeBytes32(nullifier)
            enc.writeBytes32(newCommitment)
            enc.writeU64(oldEpoch)
            enc.writeU64(newEpoch)
            enc.writeBytes32(txAnchor)
            enc.writeBytes32(poolId)
            return enc.encode()
        }
    }

    // MARK: - Well-known Program IDs

    // nonisolated(unsafe) to suppress Swift 6 concurrency warnings for PublicKey (which is
    // effectively immutable but doesn't conform to Sendable in SolanaSwift v5)
    nonisolated(unsafe) public static let TOKEN_PROGRAM_ID: PublicKey = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    nonisolated(unsafe) public static let SYSTEM_PROGRAM_ID: PublicKey = "11111111111111111111111111111111"

    // MARK: - Instruction Builders

    /// Initialize a V2 epoch-based shielded pool.
    public static func initializePoolV2(
        epochDurationSlots: UInt64,
        expirySlots: UInt64,
        finalizationDelaySlots: UInt64,
        accounts: InitializePoolV2Accounts,
        programId: PublicKey
    ) -> TransactionInstruction {
        var enc = BorshEncoder()
        enc.writeFixedBytes(DISC_INITIALIZE_POOL_V2)
        enc.writeU64(epochDurationSlots)
        enc.writeU64(expirySlots)
        enc.writeU64(finalizationDelaySlots)

        return TransactionInstruction(
            keys: [
                .writable(publicKey: accounts.poolConfig, isSigner: false),
                .writable(publicKey: accounts.epochTree, isSigner: false),
                .readonly(publicKey: accounts.vaultAuthority, isSigner: false),
                .writable(publicKey: accounts.vault, isSigner: false),
                .readonly(publicKey: accounts.mint, isSigner: false),
                .readonly(publicKey: accounts.authority, isSigner: true),
                .writable(publicKey: accounts.payer, isSigner: true),
                .readonly(publicKey: SYSTEM_PROGRAM_ID, isSigner: false),
                .readonly(publicKey: TOKEN_PROGRAM_ID, isSigner: false),
            ],
            programId: programId,
            data: [enc.encode() as BytesEncodable]
        )
    }

    /// Initialize a leaf chunk PDA for a given epoch.
    public static func initializeEpochLeafChunk(
        epoch: UInt64,
        chunkIndex: UInt32,
        poolConfig: PublicKey,
        leafChunk: PublicKey,
        payer: PublicKey,
        programId: PublicKey
    ) -> TransactionInstruction {
        var enc = BorshEncoder()
        enc.writeFixedBytes(DISC_INITIALIZE_EPOCH_LEAF_CHUNK)
        enc.writeU64(epoch)
        enc.writeU32(chunkIndex)

        return TransactionInstruction(
            keys: [
                .readonly(publicKey: poolConfig, isSigner: false),
                .writable(publicKey: leafChunk, isSigner: false),
                .writable(publicKey: payer, isSigner: true),
                .readonly(publicKey: SYSTEM_PROGRAM_ID, isSigner: false),
            ],
            programId: programId,
            data: [enc.encode() as BytesEncodable]
        )
    }

    /// Deposit tokens into the shielded pool (V2 epoch-based).
    public static func depositV2(
        commitment: Data,
        amount: UInt64,
        encryptedNote: Data,
        accounts: DepositV2Accounts,
        programId: PublicKey
    ) -> TransactionInstruction {
        var enc = BorshEncoder()
        enc.writeFixedBytes(DISC_DEPOSIT_V2)
        enc.writeBytes32(commitment)     // [u8; 32]
        enc.writeU64(amount)             // u64
        enc.writeBytes(encryptedNote)    // bytes (Vec<u8>)

        return TransactionInstruction(
            keys: [
                .writable(publicKey: accounts.poolConfig, isSigner: false),
                .writable(publicKey: accounts.epochTree, isSigner: false),
                .writable(publicKey: accounts.leafChunk, isSigner: false),
                .writable(publicKey: accounts.vault, isSigner: false),
                .writable(publicKey: accounts.depositorTokenAccount, isSigner: false),
                .readonly(publicKey: accounts.mint, isSigner: false),
                .readonly(publicKey: accounts.depositor, isSigner: true),
                .readonly(publicKey: TOKEN_PROGRAM_ID, isSigner: false),
            ],
            programId: programId,
            data: [enc.encode() as BytesEncodable]
        )
    }

    /// Withdraw from the shielded pool (V2 epoch-based).
    public static func withdrawV2(
        proofBytes: Data,
        publicInputs: WithdrawPublicInputs,
        accounts: WithdrawV2Accounts,
        programId: PublicKey
    ) -> TransactionInstruction {
        var enc = BorshEncoder()
        enc.writeFixedBytes(DISC_WITHDRAW_V2)
        enc.writeBytes(proofBytes)                  // bytes (proof)
        enc.writeFixedBytes(publicInputs.serialize()) // struct (inline)

        return TransactionInstruction(
            keys: [
                .writable(publicKey: accounts.poolConfig, isSigner: false),
                .writable(publicKey: accounts.epochTree, isSigner: false),
                .writable(publicKey: accounts.nullifierMarker, isSigner: false),
                .readonly(publicKey: accounts.verifierConfig, isSigner: false),
                .readonly(publicKey: accounts.vaultAuthority, isSigner: false),
                .writable(publicKey: accounts.vault, isSigner: false),
                .writable(publicKey: accounts.recipientTokenAccount, isSigner: false),
                .readonly(publicKey: accounts.mint, isSigner: false),
                .writable(publicKey: accounts.payer, isSigner: true),
                .readonly(publicKey: TOKEN_PROGRAM_ID, isSigner: false),
                .readonly(publicKey: SYSTEM_PROGRAM_ID, isSigner: false),
            ],
            programId: programId,
            data: [enc.encode() as BytesEncodable]
        )
    }

    /// Shielded transfer (V2 epoch-based, 2-in-2-out).
    public static func transferV2(
        proofBytes: Data,
        publicInputs: TransferPublicInputs,
        encryptedNotes: [Data],
        accounts: TransferV2Accounts,
        programId: PublicKey
    ) -> TransactionInstruction {
        var enc = BorshEncoder()
        enc.writeFixedBytes(DISC_TRANSFER_V2)
        enc.writeBytes(proofBytes)                     // bytes (proof)
        enc.writeFixedBytes(publicInputs.serialize())  // struct (inline)
        enc.writeVecBytes(encryptedNotes)              // Vec<bytes>

        return TransactionInstruction(
            keys: [
                .writable(publicKey: accounts.poolConfig, isSigner: false),
                .writable(publicKey: accounts.spendEpochTree, isSigner: false),
                .writable(publicKey: accounts.depositEpochTree, isSigner: false),
                .writable(publicKey: accounts.nullifierMarker1, isSigner: false),
                .writable(publicKey: accounts.nullifierMarker2, isSigner: false),
                .writable(publicKey: accounts.depositLeafChunk, isSigner: false),
                .readonly(publicKey: accounts.verifierConfig, isSigner: false),
                .writable(publicKey: accounts.payer, isSigner: true),
                .readonly(publicKey: SYSTEM_PROGRAM_ID, isSigner: false),
            ],
            programId: programId,
            data: [enc.encode() as BytesEncodable]
        )
    }

    /// Renew a note from an old epoch to the current epoch.
    public static func renewNote(
        proofBytes: Data,
        publicInputs: RenewPublicInputs,
        encryptedNote: Data,
        accounts: RenewNoteAccounts,
        programId: PublicKey
    ) -> TransactionInstruction {
        var enc = BorshEncoder()
        enc.writeFixedBytes(DISC_RENEW_NOTE)
        enc.writeBytes(proofBytes)                     // bytes (proof)
        enc.writeFixedBytes(publicInputs.serialize())  // struct (inline)
        enc.writeBytes(encryptedNote)                  // bytes

        return TransactionInstruction(
            keys: [
                .writable(publicKey: accounts.poolConfig, isSigner: false),
                .writable(publicKey: accounts.oldEpochTree, isSigner: false),
                .writable(publicKey: accounts.newEpochTree, isSigner: false),
                .writable(publicKey: accounts.nullifierMarker, isSigner: false),
                .writable(publicKey: accounts.newLeafChunk, isSigner: false),
                .readonly(publicKey: accounts.verifierConfig, isSigner: false),
                .writable(publicKey: accounts.payer, isSigner: true),
                .readonly(publicKey: SYSTEM_PROGRAM_ID, isSigner: false),
            ],
            programId: programId,
            data: [enc.encode() as BytesEncodable]
        )
    }

    /// Trigger epoch rollover (advances current epoch).
    public static func rolloverEpoch(
        poolConfig: PublicKey,
        currentEpochTree: PublicKey,
        newEpochTree: PublicKey,
        payer: PublicKey,
        programId: PublicKey
    ) -> TransactionInstruction {
        var enc = BorshEncoder()
        enc.writeFixedBytes(DISC_ROLLOVER_EPOCH)

        return TransactionInstruction(
            keys: [
                .writable(publicKey: poolConfig, isSigner: false),
                .writable(publicKey: currentEpochTree, isSigner: false),
                .writable(publicKey: newEpochTree, isSigner: false),
                .writable(publicKey: payer, isSigner: true),
                .readonly(publicKey: SYSTEM_PROGRAM_ID, isSigner: false),
            ],
            programId: programId,
            data: [enc.encode() as BytesEncodable]
        )
    }

    /// Finalize an epoch (commits its Merkle root).
    public static func finalizeEpoch(
        epoch: UInt64,
        poolConfig: PublicKey,
        epochTree: PublicKey,
        programId: PublicKey
    ) -> TransactionInstruction {
        var enc = BorshEncoder()
        enc.writeFixedBytes(DISC_FINALIZE_EPOCH)
        enc.writeU64(epoch)

        return TransactionInstruction(
            keys: [
                .readonly(publicKey: poolConfig, isSigner: false),
                .writable(publicKey: epochTree, isSigner: false),
            ],
            programId: programId,
            data: [enc.encode() as BytesEncodable]
        )
    }

    // MARK: - Mock Proof Helper

    /// Create an all-zero mock proof for testing with mock-verifier enabled programs.
    /// The mock-verifier accepts proofs where pi_a, pi_b, and pi_c are all zeros.
    /// Proof layout: pi_a (64 bytes) || pi_b (128 bytes) || pi_c (64 bytes) = 256 bytes
    public static func mockProofBytes() -> Data {
        Data(repeating: 0, count: 256)
    }
}

import Foundation
import SolanaSwift

/// PDA (Program Derived Address) derivation for the shielded pool program.
/// All seeds match the on-chain Anchor program's `#[account]` constraints.
public enum ShieldedPoolPDAs {

    // MARK: - Pool Config

    /// Derive the pool config PDA.
    /// Seeds: `["pool_config", mint]`
    public static func poolConfig(
        mint: PublicKey,
        programId: PublicKey
    ) throws -> (PublicKey, UInt8) {
        try PublicKey.findProgramAddress(
            seeds: [Data("pool_config".utf8), mint.data],
            programId: programId
        )
    }

    // MARK: - Epoch Tree

    /// Derive the epoch tree PDA.
    /// Seeds: `["epoch_tree", pool_config, epoch(u64 LE)]`
    public static func epochTree(
        poolConfig: PublicKey,
        epoch: UInt64,
        programId: PublicKey
    ) throws -> (PublicKey, UInt8) {
        var epochBytes = Data(count: 8)
        var e = epoch.littleEndian
        epochBytes = Data(bytes: &e, count: 8)
        return try PublicKey.findProgramAddress(
            seeds: [Data("epoch_tree".utf8), poolConfig.data, epochBytes],
            programId: programId
        )
    }

    // MARK: - Leaf Chunk

    /// Derive the leaf chunk PDA for a given epoch and chunk index.
    /// Seeds: `["leaves", pool_config, epoch(u64 LE), chunk_index(u32 LE)]`
    public static func leafChunk(
        poolConfig: PublicKey,
        epoch: UInt64,
        chunkIndex: UInt32,
        programId: PublicKey
    ) throws -> (PublicKey, UInt8) {
        var epochBytes = Data(count: 8)
        var e = epoch.littleEndian
        epochBytes = Data(bytes: &e, count: 8)

        var chunkBytes = Data(count: 4)
        var c = chunkIndex.littleEndian
        chunkBytes = Data(bytes: &c, count: 4)

        return try PublicKey.findProgramAddress(
            seeds: [Data("leaves".utf8), poolConfig.data, epochBytes, chunkBytes],
            programId: programId
        )
    }

    // MARK: - Vault Authority

    /// Derive the vault authority PDA (token account signer).
    /// Seeds: `["vault_authority", pool_config]`
    public static func vaultAuthority(
        poolConfig: PublicKey,
        programId: PublicKey
    ) throws -> (PublicKey, UInt8) {
        try PublicKey.findProgramAddress(
            seeds: [Data("vault_authority".utf8), poolConfig.data],
            programId: programId
        )
    }

    // MARK: - Vault

    /// Derive the vault PDA (token account holding shielded funds).
    /// Seeds: `["vault", pool_config]`
    public static func vault(
        poolConfig: PublicKey,
        programId: PublicKey
    ) throws -> (PublicKey, UInt8) {
        try PublicKey.findProgramAddress(
            seeds: [Data("vault".utf8), poolConfig.data],
            programId: programId
        )
    }

    // MARK: - Nullifier Marker

    /// Derive the nullifier marker PDA (prevents double-spending).
    /// Seeds: `["nullifier", pool_config, nullifier_bytes]`
    public static func nullifierMarker(
        poolConfig: PublicKey,
        nullifier: Data,
        programId: PublicKey
    ) throws -> (PublicKey, UInt8) {
        try PublicKey.findProgramAddress(
            seeds: [Data("nullifier".utf8), poolConfig.data, nullifier],
            programId: programId
        )
    }

    // MARK: - Verifier Config

    /// Derive the verifier config PDA for a circuit type.
    /// Seeds: `["verifier", pool_config, circuit_name]`
    public static func verifierConfig(
        poolConfig: PublicKey,
        circuitName: String,
        programId: PublicKey
    ) throws -> (PublicKey, UInt8) {
        try PublicKey.findProgramAddress(
            seeds: [Data("verifier".utf8), poolConfig.data, Data(circuitName.utf8)],
            programId: programId
        )
    }

    // MARK: - Convenience

    /// Compute the leaf chunk index for a given leaf index.
    /// Each chunk holds 256 leaves.
    public static func chunkIndex(forLeafIndex leafIndex: UInt32) -> UInt32 {
        leafIndex / 256
    }
}

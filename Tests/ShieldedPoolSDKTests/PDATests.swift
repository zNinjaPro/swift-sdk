import XCTest
import SolanaSwift
@testable import ShieldedPoolSDK

/// Tests for ShieldedPoolPDAs — verify PDA derivation matches on-chain program
final class PDATests: XCTestCase {

    let programId: PublicKey = "C58iVei3DXTL9BSKe5ZpQuJehqLJL1fQjejdnCAdWzV7"

    // MARK: - Pool Config PDA

    func testPoolConfigPDA() throws {
        let mint: PublicKey = "8AnBxM3s9VUSvGtUigaP5WhLBuGtW4wnKw6wMzjREi4k"
        let (pda, bump) = try ShieldedPoolPDAs.poolConfig(mint: mint, programId: programId)

        // PDA should be a valid public key
        XCTAssertEqual(pda.data.count, 32)
        XCTAssertTrue(bump <= 255)

        // Same inputs should produce same PDA (deterministic)
        let (pda2, bump2) = try ShieldedPoolPDAs.poolConfig(mint: mint, programId: programId)
        XCTAssertEqual(pda, pda2)
        XCTAssertEqual(bump, bump2)
    }

    func testPoolConfigDifferentMints() throws {
        let mint1: PublicKey = "8AnBxM3s9VUSvGtUigaP5WhLBuGtW4wnKw6wMzjREi4k"
        let mint2: PublicKey = "So11111111111111111111111111111111111111112"

        let (pda1, _) = try ShieldedPoolPDAs.poolConfig(mint: mint1, programId: programId)
        let (pda2, _) = try ShieldedPoolPDAs.poolConfig(mint: mint2, programId: programId)

        XCTAssertNotEqual(pda1, pda2, "Different mints should produce different PDAs")
    }

    // MARK: - Epoch Tree PDA

    func testEpochTreePDA() throws {
        let mint: PublicKey = "8AnBxM3s9VUSvGtUigaP5WhLBuGtW4wnKw6wMzjREi4k"
        let (poolConfig, _) = try ShieldedPoolPDAs.poolConfig(mint: mint, programId: programId)

        let (tree0, _) = try ShieldedPoolPDAs.epochTree(
            poolConfig: poolConfig, epoch: 0, programId: programId)
        let (tree1, _) = try ShieldedPoolPDAs.epochTree(
            poolConfig: poolConfig, epoch: 1, programId: programId)

        XCTAssertNotEqual(tree0, tree1, "Different epochs should produce different tree PDAs")
        XCTAssertEqual(tree0.data.count, 32)
    }

    func testEpochTreeDeterministic() throws {
        let poolConfig = try PublicKey(data: Data(repeating: 0x42, count: 32))

        let (pda1, b1) = try ShieldedPoolPDAs.epochTree(
            poolConfig: poolConfig, epoch: 5, programId: programId)
        let (pda2, b2) = try ShieldedPoolPDAs.epochTree(
            poolConfig: poolConfig, epoch: 5, programId: programId)

        XCTAssertEqual(pda1, pda2)
        XCTAssertEqual(b1, b2)
    }

    // MARK: - Leaf Chunk PDA

    func testLeafChunkPDA() throws {
        let poolConfig = try PublicKey(data: Data(repeating: 0x42, count: 32))

        let (chunk0, _) = try ShieldedPoolPDAs.leafChunk(
            poolConfig: poolConfig, epoch: 0, chunkIndex: 0, programId: programId)
        let (chunk1, _) = try ShieldedPoolPDAs.leafChunk(
            poolConfig: poolConfig, epoch: 0, chunkIndex: 1, programId: programId)

        XCTAssertNotEqual(chunk0, chunk1, "Different chunks should produce different PDAs")
    }

    func testLeafChunkDifferentEpochs() throws {
        let poolConfig = try PublicKey(data: Data(repeating: 0x42, count: 32))

        let (chunk_e0, _) = try ShieldedPoolPDAs.leafChunk(
            poolConfig: poolConfig, epoch: 0, chunkIndex: 0, programId: programId)
        let (chunk_e1, _) = try ShieldedPoolPDAs.leafChunk(
            poolConfig: poolConfig, epoch: 1, chunkIndex: 0, programId: programId)

        XCTAssertNotEqual(chunk_e0, chunk_e1)
    }

    // MARK: - Vault Authority & Vault

    func testVaultAuthorityPDA() throws {
        let poolConfig = try PublicKey(data: Data(repeating: 0x42, count: 32))
        let (va, _) = try ShieldedPoolPDAs.vaultAuthority(
            poolConfig: poolConfig, programId: programId)

        XCTAssertEqual(va.data.count, 32)
    }

    func testVaultPDA() throws {
        let poolConfig = try PublicKey(data: Data(repeating: 0x42, count: 32))
        let (vault, _) = try ShieldedPoolPDAs.vault(
            poolConfig: poolConfig, programId: programId)

        XCTAssertEqual(vault.data.count, 32)

        // Vault and vault authority should be different
        let (va, _) = try ShieldedPoolPDAs.vaultAuthority(
            poolConfig: poolConfig, programId: programId)
        XCTAssertNotEqual(vault, va)
    }

    // MARK: - Nullifier Marker

    func testNullifierMarkerPDA() throws {
        let poolConfig = try PublicKey(data: Data(repeating: 0x42, count: 32))
        let nullifier1 = Data(repeating: 0xAA, count: 32)
        let nullifier2 = Data(repeating: 0xBB, count: 32)

        let (marker1, _) = try ShieldedPoolPDAs.nullifierMarker(
            poolConfig: poolConfig, nullifier: nullifier1, programId: programId)
        let (marker2, _) = try ShieldedPoolPDAs.nullifierMarker(
            poolConfig: poolConfig, nullifier: nullifier2, programId: programId)

        XCTAssertNotEqual(marker1, marker2, "Different nullifiers should produce different markers")
    }

    // MARK: - Verifier Config

    func testVerifierConfigPDA() throws {
        let poolConfig = try PublicKey(data: Data(repeating: 0x42, count: 32))

        let (withdrawVC, _) = try ShieldedPoolPDAs.verifierConfig(
            poolConfig: poolConfig, circuitName: "withdraw", programId: programId)
        let (transferVC, _) = try ShieldedPoolPDAs.verifierConfig(
            poolConfig: poolConfig, circuitName: "transfer", programId: programId)

        XCTAssertNotEqual(withdrawVC, transferVC, "Different circuits should have different verifier configs")
    }

    // MARK: - Chunk Index Helper

    func testChunkIndexCalculation() {
        XCTAssertEqual(ShieldedPoolPDAs.chunkIndex(forLeafIndex: 0), 0)
        XCTAssertEqual(ShieldedPoolPDAs.chunkIndex(forLeafIndex: 255), 0)
        XCTAssertEqual(ShieldedPoolPDAs.chunkIndex(forLeafIndex: 256), 1)
        XCTAssertEqual(ShieldedPoolPDAs.chunkIndex(forLeafIndex: 4095), 15)
    }
}

import XCTest
import SolanaSwift
@testable import ShieldedPoolSDK
@testable import ShieldedPoolCore

/// On-chain integration tests — cross-validate PDA derivation with TS SDK,
/// test instruction building, and verify data formats against the deployed program.
/// These tests use the localnet program at C58iVei3DXTL9BSKe5ZpQuJehqLJL1fQjejdnCAdWzV7.
final class OnChainTests: XCTestCase {

    let programId: PublicKey = "C58iVei3DXTL9BSKe5ZpQuJehqLJL1fQjejdnCAdWzV7"
    let testMint: PublicKey = "sxZCUPCTteXJm58xg31jiKQVn9pxyteDvakRAESYwuL"

    // MARK: - PDA Cross-Validation vs TypeScript SDK

    func testPoolConfigPDACrossValidation() throws {
        let (pda, _) = try ShieldedPoolPDAs.poolConfig(mint: testMint, programId: programId)
        // Cross-validated against TS SDK: PublicKey.findProgramAddressSync(["pool_config", mint], programId)
        XCTAssertEqual(pda.base58EncodedString, "2pygj3tnm4AKhJGCT5QDeaiLFYZtxU3NtLyTtYHxRbp7",
                       "Pool config PDA must match TS SDK derivation")
    }

    func testEpochTree0PDACrossValidation() throws {
        let (poolConfig, _) = try ShieldedPoolPDAs.poolConfig(mint: testMint, programId: programId)
        let (tree0, _) = try ShieldedPoolPDAs.epochTree(poolConfig: poolConfig, epoch: 0, programId: programId)
        // Cross-validated against TS SDK
        XCTAssertEqual(tree0.base58EncodedString, "Fo8Dx98DLSChBofcTbc65y16P4mcnkq9ra1mXGDQzrDN",
                       "Epoch tree 0 PDA must match TS SDK derivation")
    }

    func testVaultAuthorityPDACrossValidation() throws {
        let (poolConfig, _) = try ShieldedPoolPDAs.poolConfig(mint: testMint, programId: programId)
        let (va, _) = try ShieldedPoolPDAs.vaultAuthority(poolConfig: poolConfig, programId: programId)
        XCTAssertEqual(va.base58EncodedString, "Gj2LLNWhMSoMA4wgQJctAJUciXfqWaUKYXXqiKiR2AU3",
                       "Vault authority PDA must match TS SDK derivation")
    }

    func testVaultPDACrossValidation() throws {
        let (poolConfig, _) = try ShieldedPoolPDAs.poolConfig(mint: testMint, programId: programId)
        let (vault, _) = try ShieldedPoolPDAs.vault(poolConfig: poolConfig, programId: programId)
        XCTAssertEqual(vault.base58EncodedString, "2VSBvAWDZze3UzN4QeNMCAuJkd49sGaQ8YhZbL8Qw4iu",
                       "Vault PDA must match TS SDK derivation")
    }

    // MARK: - Full PDA Chain

    func testFullPDADerivationChain() throws {
        let (poolConfig, _) = try ShieldedPoolPDAs.poolConfig(mint: testMint, programId: programId)
        let (epochTree, _) = try ShieldedPoolPDAs.epochTree(poolConfig: poolConfig, epoch: 0, programId: programId)
        let (leafChunk, _) = try ShieldedPoolPDAs.leafChunk(poolConfig: poolConfig, epoch: 0, chunkIndex: 0, programId: programId)
        let (va, _) = try ShieldedPoolPDAs.vaultAuthority(poolConfig: poolConfig, programId: programId)
        let (vault, _) = try ShieldedPoolPDAs.vault(poolConfig: poolConfig, programId: programId)

        // All should be distinct
        let pdas = [poolConfig, epochTree, leafChunk, va, vault]
        let unique = Set(pdas.map { $0.base58EncodedString })
        XCTAssertEqual(unique.count, 5, "All PDAs should be distinct")
    }

    // MARK: - Deposit Instruction for On-Chain

    func testBuildDepositInstructionForLocalnet() throws {
        // Build a complete deposit instruction that would work on localnet
        let (poolConfig, _) = try ShieldedPoolPDAs.poolConfig(mint: testMint, programId: programId)
        let (epochTree, _) = try ShieldedPoolPDAs.epochTree(poolConfig: poolConfig, epoch: 0, programId: programId)
        let (leafChunk, _) = try ShieldedPoolPDAs.leafChunk(poolConfig: poolConfig, epoch: 0, chunkIndex: 0, programId: programId)
        let (vault, _) = try ShieldedPoolPDAs.vault(poolConfig: poolConfig, programId: programId)

        let depositor: PublicKey = "56SDxK3tK7TbaERxqkUggYocJYCav3WPdMCbQH9AD5kD"
        let depositorTokenAccount: PublicKey = "6Tcz6tVQr8NJSwuZxr8wBRbx19RfF1fwo3SaTc9UduHA"

        // Use TxBuilder to prepare deposit data
        let km = ShieldedPoolCore.KeyManager.fromSeed(Data(0..<32))
        let seed = Data(0..<32)
        let proverConfig = ShieldedPoolCore.ProverConfig(zkeyPath: "/mock", circuitType: .withdraw)
        let prover = ShieldedPoolCore.ZKProver(config: proverConfig)
        let txb = ShieldedPoolCore.TxBuilder(prover: prover, poolId: poolConfig.data, tokenMint: testMint.data)

        let deposit = try txb.prepareDeposit(
            amount: 1_000_000_000, // 1 token (9 decimals)
            recipientAddress: km.shieldedAddress,
            viewingKey: km.viewingKey
        )

        // Build the instruction
        let ix = ShieldedPoolInstructions.depositV2(
            commitment: deposit.commitment,
            amount: 1_000_000_000,
            encryptedNote: deposit.encryptedNote,
            accounts: ShieldedPoolInstructions.DepositV2Accounts(
                poolConfig: poolConfig,
                epochTree: epochTree,
                leafChunk: leafChunk,
                vault: vault,
                depositorTokenAccount: depositorTokenAccount,
                mint: testMint,
                depositor: depositor
            ),
            programId: programId
        )

        // Verify instruction is well-formed
        XCTAssertEqual(ix.programId, programId)
        XCTAssertEqual(ix.keys.count, 8)

        // Verify accounts match expected PDAs
        XCTAssertEqual(ix.keys[0].publicKey, poolConfig)
        XCTAssertEqual(ix.keys[1].publicKey, epochTree)
        XCTAssertEqual(ix.keys[2].publicKey, leafChunk)
        XCTAssertEqual(ix.keys[3].publicKey, vault)
        XCTAssertEqual(ix.keys[4].publicKey, depositorTokenAccount)
        XCTAssertEqual(ix.keys[5].publicKey, testMint)
        XCTAssertEqual(ix.keys[6].publicKey, depositor)
        XCTAssertEqual(ix.keys[7].publicKey, ShieldedPoolInstructions.TOKEN_PROGRAM_ID)

        // Verify discriminator
        let disc = Array(ix.data.prefix(8))
        XCTAssertEqual(disc, [0x6d, 0x4b, 0x45, 0x99, 0xac, 0xda, 0x92, 0x13])

        // Verify commitment in data (bytes 8-40)
        XCTAssertEqual(Data(ix.data[8..<40]), deposit.commitment)
    }

    // MARK: - Withdraw Instruction with Mock Proof

    func testBuildWithdrawInstructionWithMockProof() throws {
        let (poolConfig, _) = try ShieldedPoolPDAs.poolConfig(mint: testMint, programId: programId)
        let (epochTree, _) = try ShieldedPoolPDAs.epochTree(poolConfig: poolConfig, epoch: 0, programId: programId)
        let (va, _) = try ShieldedPoolPDAs.vaultAuthority(poolConfig: poolConfig, programId: programId)
        let (vault, _) = try ShieldedPoolPDAs.vault(poolConfig: poolConfig, programId: programId)

        let nullifier = Data(repeating: 0xAA, count: 32)
        let (nfMarker, _) = try ShieldedPoolPDAs.nullifierMarker(
            poolConfig: poolConfig, nullifier: nullifier, programId: programId)
        let (verifier, _) = try ShieldedPoolPDAs.verifierConfig(
            poolConfig: poolConfig, circuitName: "withdraw", programId: programId)

        let recipient: PublicKey = "56SDxK3tK7TbaERxqkUggYocJYCav3WPdMCbQH9AD5kD"
        let recipientTA: PublicKey = "6Tcz6tVQr8NJSwuZxr8wBRbx19RfF1fwo3SaTc9UduHA"

        let inputs = ShieldedPoolInstructions.WithdrawPublicInputs(
            root: Data(repeating: 0xBB, count: 32),
            nullifier: nullifier,
            amount: 500_000_000,
            recipient: recipient,
            epoch: 0,
            txAnchor: Data(count: 32),
            poolId: poolConfig.data
        )

        let ix = ShieldedPoolInstructions.withdrawV2(
            proofBytes: ShieldedPoolInstructions.mockProofBytes(),
            publicInputs: inputs,
            accounts: ShieldedPoolInstructions.WithdrawV2Accounts(
                poolConfig: poolConfig,
                epochTree: epochTree,
                nullifierMarker: nfMarker,
                verifierConfig: verifier,
                vaultAuthority: va,
                vault: vault,
                recipientTokenAccount: recipientTA,
                mint: testMint,
                payer: recipient
            ),
            programId: programId
        )

        XCTAssertEqual(ix.programId, programId)
        XCTAssertEqual(ix.keys.count, 11)

        // Mock proof should be 256 zero bytes
        // Located at: disc(8) + u32_len(4) + proof(256)
        let proofStart = 12 // 8 disc + 4 length
        let proofEnd = proofStart + 256
        let proofInData = Data(ix.data[proofStart..<proofEnd])
        XCTAssertTrue(proofInData.allSatisfy { $0 == 0 }, "Mock proof must be all zeros in serialized data")
    }
}

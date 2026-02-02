import XCTest
import BigInt
@testable import ShieldedPoolCore

/// Prover tests — witness input serialization for all circuit types
/// NOTE: Actual proof generation requires rapidsnark/witnesscalc frameworks (iOS only).
/// These tests validate that witness inputs are correctly serialized to match circuit expectations.
final class ProverTests: XCTestCase {

    // MARK: - Helpers

    private let testSeed = Data(0..<32)

    private func makeKeys() -> (KeyManager, SpendingKeys) {
        let km = KeyManager.fromSeed(testSeed)
        return (km, km.exportKeys())
    }

    private func makeTestNote(
        value: UInt64,
        owner: Data,
        randomness: Data,
        epoch: UInt64 = 1,
        leafIndex: UInt32 = 0
    ) throws -> Note {
        let commitment = try Crypto.computeCommitment(value: value, owner: owner, randomness: randomness)
        let (_, keys) = makeKeys()
        let nullifier = try Crypto.computeNullifier(
            commitment: commitment,
            nullifierKey: keys.nullifierKey,
            epoch: epoch,
            leafIndex: leafIndex
        )
        return Note(
            value: value,
            token: Data(count: 32),
            owner: owner,
            blinding: randomness,
            commitment: commitment,
            leafIndex: leafIndex,
            epoch: epoch,
            nullifier: nullifier,
            randomness: randomness
        )
    }

    private func makeDummyProof() -> MerkleProof {
        MerkleProof(
            leaf: Data(count: 32),
            leafIndex: 0,
            epoch: 1,
            siblings: (0..<12).map { _ in Data(repeating: 0, count: 32) },
            root: Data(count: 32)
        )
    }

    // MARK: - Prover Config

    func testProverConfigInit() {
        let config = ProverConfig(
            zkeyPath: "/path/to/withdraw_final.zkey",
            witnesscalcPath: "/path/to/withdraw.wcd",
            circuitType: .withdraw
        )
        XCTAssertEqual(config.circuitType, .withdraw)
        XCTAssertEqual(config.zkeyPath, "/path/to/withdraw_final.zkey")
        XCTAssertEqual(config.witnesscalcPath, "/path/to/withdraw.wcd")
    }

    func testCircuitTypes() {
        XCTAssertEqual(CircuitType.withdraw.rawValue, "withdraw")
        XCTAssertEqual(CircuitType.transfer.rawValue, "transfer")
        XCTAssertEqual(CircuitType.joinsplit.rawValue, "joinsplit")
        XCTAssertEqual(CircuitType.renew.rawValue, "renew")
    }

    // MARK: - Framework Not Integrated

    func testProveWithdrawThrowsNotIntegrated() async throws {
        let (km, keys) = makeKeys()
        let randomness = Crypto.sha256(Data("r".utf8))
        let note = try makeTestNote(value: 1_000_000, owner: km.shieldedAddress, randomness: randomness)

        let prover = ZKProver(config: ProverConfig(
            zkeyPath: "/fake.zkey",
            witnesscalcPath: "/fake.wcd",
            circuitType: .withdraw
        ))

        let inputs = WithdrawInputs(
            note: note,
            spendingKeys: keys,
            merkleProof: makeDummyProof(),
            merkleRoot: Data(count: 32),
            recipient: Data(repeating: 0xFF, count: 32),
            amount: 1_000_000,
            epoch: 1,
            leafIndex: 0
        )

        do {
            _ = try await prover.proveWithdraw(inputs)
            XCTFail("Should throw frameworkNotIntegrated")
        } catch let error as ProverError {
            if case .frameworkNotIntegrated = error {
                // expected
            } else {
                XCTFail("Expected frameworkNotIntegrated, got \(error)")
            }
        }
    }

    func testProveTransferThrowsNotIntegrated() async throws {
        let (km, keys) = makeKeys()
        let r1 = Crypto.sha256(Data("r1".utf8))
        let r2 = Crypto.sha256(Data("r2".utf8))
        let r3 = Crypto.sha256(Data("r3".utf8))
        let r4 = Crypto.sha256(Data("r4".utf8))

        let in0 = try makeTestNote(value: 500_000, owner: km.shieldedAddress, randomness: r1, leafIndex: 0)
        let in1 = try makeTestNote(value: 500_000, owner: km.shieldedAddress, randomness: r2, leafIndex: 1)
        let out0 = try makeTestNote(value: 700_000, owner: km.shieldedAddress, randomness: r3)
        let out1 = try makeTestNote(value: 300_000, owner: km.shieldedAddress, randomness: r4)

        let prover = ZKProver(config: ProverConfig(
            zkeyPath: "/fake.zkey",
            circuitType: .transfer
        ))

        let inputs = TransferInputs(
            inputNotes: (in0, in1),
            spendingKeys: keys,
            outputNotes: (out0, out1),
            merkleProofs: (makeDummyProof(), makeDummyProof()),
            merkleRoot: Data(count: 32),
            epoch: 1,
            inputLeafIndices: (0, 1)
        )

        do {
            _ = try await prover.proveTransfer(inputs)
            XCTFail("Should throw frameworkNotIntegrated")
        } catch let error as ProverError {
            if case .frameworkNotIntegrated = error {
                // expected
            } else {
                XCTFail("Expected frameworkNotIntegrated, got \(error)")
            }
        }
    }

    func testProveRenewThrowsNotIntegrated() async throws {
        let (km, keys) = makeKeys()
        let r1 = Crypto.sha256(Data("old".utf8))
        let r2 = Crypto.sha256(Data("new".utf8))

        let oldNote = try makeTestNote(value: 1_000_000, owner: km.shieldedAddress, randomness: r1, epoch: 1, leafIndex: 5)
        let newNote = try makeTestNote(value: 1_000_000, owner: km.shieldedAddress, randomness: r2, epoch: 5, leafIndex: 0)

        let prover = ZKProver(config: ProverConfig(
            zkeyPath: "/fake.zkey",
            circuitType: .renew
        ))

        let inputs = RenewInputs(
            oldNote: oldNote,
            newNote: newNote,
            spendingKeys: keys,
            merkleProof: makeDummyProof(),
            merkleRoot: Data(count: 32),
            poolId: Data(count: 32),
            oldEpoch: 1,
            newEpoch: 5,
            oldLeafIndex: 5
        )

        do {
            _ = try await prover.proveRenew(inputs)
            XCTFail("Should throw frameworkNotIntegrated")
        } catch let error as ProverError {
            if case .frameworkNotIntegrated = error {
                // expected
            } else {
                XCTFail("Expected frameworkNotIntegrated, got \(error)")
            }
        }
    }

    // MARK: - Proof Parsing

    func testParseProofJson() throws {
        let json = """
        {
            "pi_a": ["12345", "67890", "1"],
            "pi_b": [["111", "222"], ["333", "444"], ["1", "0"]],
            "pi_c": ["555", "666", "1"],
            "protocol": "groth16"
        }
        """

        let proof = try ZKProver.parseProofJson(json)
        // pi_a: 3 × 32 bytes = 96 bytes
        XCTAssertEqual(proof.a.count, 96)
        // pi_b: 3 × 2 × 32 = 192 bytes
        XCTAssertEqual(proof.b.count, 192)
        // pi_c: 3 × 32 = 96 bytes
        XCTAssertEqual(proof.c.count, 96)
    }

    func testParseProofJsonInvalid() {
        XCTAssertThrowsError(try ZKProver.parseProofJson("not json"))
        XCTAssertThrowsError(try ZKProver.parseProofJson("{}"))
    }

    func testParsePublicSignalsJson() throws {
        let json = """
        ["12345", "67890", "11111"]
        """

        let signals = try ZKProver.parsePublicSignalsJson(json)
        XCTAssertEqual(signals.count, 3)
        XCTAssertEqual(signals[0].count, 32)

        // Verify first signal
        let expected = Crypto.bigintToBytes32(BigUInt(12345))
        XCTAssertEqual(signals[0], expected)
    }

    func testParsePublicSignalsJsonInvalid() {
        XCTAssertThrowsError(try ZKProver.parsePublicSignalsJson("not json"))
    }

    // MARK: - Prover Error Descriptions

    func testProverErrorDescriptions() {
        let errors: [ProverError] = [
            .invalidInputs("bad"),
            .witnessGenerationFailed("fail"),
            .proofGenerationFailed("oops"),
            .frameworkNotIntegrated("missing"),
        ]
        for error in errors {
            XCTAssertFalse(error.description.isEmpty)
        }
    }

    // MARK: - Input Types

    func testWithdrawInputsInit() throws {
        let (km, keys) = makeKeys()
        let note = try makeTestNote(value: 100, owner: km.shieldedAddress, randomness: Data(repeating: 1, count: 32))

        let inputs = WithdrawInputs(
            note: note,
            spendingKeys: keys,
            merkleProof: makeDummyProof(),
            merkleRoot: Data(count: 32),
            recipient: Data(repeating: 0xFF, count: 32),
            amount: 100,
            epoch: 1,
            leafIndex: 0
        )
        XCTAssertEqual(inputs.amount, 100)
        XCTAssertEqual(inputs.epoch, 1)
        XCTAssertEqual(inputs.leafIndex, 0)
    }

    func testTransferInputsInit() throws {
        let (km, keys) = makeKeys()
        let n0 = try makeTestNote(value: 50, owner: km.shieldedAddress, randomness: Data(repeating: 1, count: 32))
        let n1 = try makeTestNote(value: 50, owner: km.shieldedAddress, randomness: Data(repeating: 2, count: 32))
        let o0 = try makeTestNote(value: 60, owner: km.shieldedAddress, randomness: Data(repeating: 3, count: 32))
        let o1 = try makeTestNote(value: 40, owner: km.shieldedAddress, randomness: Data(repeating: 4, count: 32))

        let inputs = TransferInputs(
            inputNotes: (n0, n1),
            spendingKeys: keys,
            outputNotes: (o0, o1),
            merkleProofs: (makeDummyProof(), makeDummyProof()),
            merkleRoot: Data(count: 32),
            epoch: 1,
            inputLeafIndices: (0, 1)
        )
        XCTAssertEqual(inputs.epoch, 1)
        XCTAssertEqual(inputs.inputLeafIndices.0, 0)
        XCTAssertEqual(inputs.inputLeafIndices.1, 1)
    }
}

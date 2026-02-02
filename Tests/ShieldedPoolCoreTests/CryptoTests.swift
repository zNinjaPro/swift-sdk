import XCTest
import BigInt
@testable import ShieldedPoolCore

/// Crypto module tests — commitment, nullifier, note serialization, encryption
final class CryptoTests: XCTestCase {

    // MARK: - Commitment

    func testComputeCommitmentDeterministic() throws {
        let owner = Data(repeating: 0xAA, count: 32)
        let randomness = Data(repeating: 0xBB, count: 32)

        let c1 = try Crypto.computeCommitment(value: 1_000_000, owner: owner, randomness: randomness)
        let c2 = try Crypto.computeCommitment(value: 1_000_000, owner: owner, randomness: randomness)

        XCTAssertEqual(c1, c2, "Commitment must be deterministic")
        XCTAssertEqual(c1.count, 32)
    }

    func testComputeCommitmentSensitivity() throws {
        let owner = Data(repeating: 0xAA, count: 32)
        let randomness = Data(repeating: 0xBB, count: 32)

        let base = try Crypto.computeCommitment(value: 1_000_000, owner: owner, randomness: randomness)
        let diffValue = try Crypto.computeCommitment(value: 1_000_001, owner: owner, randomness: randomness)
        let diffOwner = try Crypto.computeCommitment(value: 1_000_000, owner: Data(repeating: 0xCC, count: 32), randomness: randomness)
        let diffRand = try Crypto.computeCommitment(value: 1_000_000, owner: owner, randomness: Data(repeating: 0xDD, count: 32))

        XCTAssertNotEqual(base, diffValue)
        XCTAssertNotEqual(base, diffOwner)
        XCTAssertNotEqual(base, diffRand)
    }

    // MARK: - Nullifier

    func testComputeNullifierDeterministic() throws {
        let commitment = Data(repeating: 0x11, count: 32)
        let nullifierKey = Data(repeating: 0x22, count: 32)

        let n1 = try Crypto.computeNullifier(commitment: commitment, nullifierKey: nullifierKey, epoch: 1, leafIndex: 0)
        let n2 = try Crypto.computeNullifier(commitment: commitment, nullifierKey: nullifierKey, epoch: 1, leafIndex: 0)

        XCTAssertEqual(n1, n2, "Nullifier must be deterministic")
        XCTAssertEqual(n1.count, 32)
    }

    func testComputeNullifierSensitivity() throws {
        let commitment = Data(repeating: 0x11, count: 32)
        let nullifierKey = Data(repeating: 0x22, count: 32)

        let base = try Crypto.computeNullifier(commitment: commitment, nullifierKey: nullifierKey, epoch: 1, leafIndex: 0)
        let diffEpoch = try Crypto.computeNullifier(commitment: commitment, nullifierKey: nullifierKey, epoch: 2, leafIndex: 0)
        let diffIndex = try Crypto.computeNullifier(commitment: commitment, nullifierKey: nullifierKey, epoch: 1, leafIndex: 1)
        let diffKey = try Crypto.computeNullifier(commitment: commitment, nullifierKey: Data(repeating: 0x33, count: 32), epoch: 1, leafIndex: 0)

        XCTAssertNotEqual(base, diffEpoch, "Different epoch → different nullifier")
        XCTAssertNotEqual(base, diffIndex, "Different leafIndex → different nullifier")
        XCTAssertNotEqual(base, diffKey, "Different nullifierKey → different nullifier")
    }

    func testNullifierEpochEncoding() throws {
        // Epoch is little-endian encoded matching TS SDK
        let commitment = Data(repeating: 0x11, count: 32)
        let nullifierKey = Data(repeating: 0x22, count: 32)

        // epoch=256 should produce different result than epoch=1
        let n1 = try Crypto.computeNullifier(commitment: commitment, nullifierKey: nullifierKey, epoch: 1, leafIndex: 0)
        let n256 = try Crypto.computeNullifier(commitment: commitment, nullifierKey: nullifierKey, epoch: 256, leafIndex: 0)
        XCTAssertNotEqual(n1, n256)
    }

    // MARK: - Note Serialization

    func testNoteSerializationRoundtrip() throws {
        let value: UInt64 = 1_000_000
        let token = Data(repeating: 0xAA, count: 32)
        let owner = Data(repeating: 0xBB, count: 32)
        let blinding = Data(repeating: 0xCC, count: 32)
        let memo = "hello"

        let serialized = Crypto.serializeNote(value: value, token: token, owner: owner, blinding: blinding, memo: memo)
        let deserialized = try Crypto.deserializeNote(serialized)

        XCTAssertEqual(deserialized.value, value)
        XCTAssertEqual(deserialized.token, token)
        XCTAssertEqual(deserialized.owner, owner)
        XCTAssertEqual(deserialized.blinding, blinding)
        XCTAssertEqual(deserialized.memo, memo)
    }

    func testNoteSerializationCrossValidation() throws {
        // Cross-validated against TS SDK: serializeNote(1000000, 0xAA*32, 0xBB*32, 0xCC*32, "hello")
        let serialized = Crypto.serializeNote(
            value: 1_000_000,
            token: Data(repeating: 0xAA, count: 32),
            owner: Data(repeating: 0xBB, count: 32),
            blinding: Data(repeating: 0xCC, count: 32),
            memo: "hello"
        )
        let expected = "00000000000000000000000000000000000000000000000000000000000f4240aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc050068656c6c6f"
        XCTAssertEqual(serialized.hexString, expected, "Serialized note must match TS SDK")
        XCTAssertEqual(serialized.count, 135)
    }

    func testNoteSerializationNoMemo() throws {
        let serialized = Crypto.serializeNote(
            value: 42,
            token: Data(repeating: 0, count: 32),
            owner: Data(repeating: 0, count: 32),
            blinding: Data(repeating: 0, count: 32)
        )
        // 32*4 + 2 (memo length) = 130
        XCTAssertEqual(serialized.count, 130)

        let deserialized = try Crypto.deserializeNote(serialized)
        XCTAssertEqual(deserialized.value, 42)
        XCTAssertNil(deserialized.memo)
    }

    func testDeserializeInvalidLength() {
        let shortData = Data(repeating: 0, count: 10)
        XCTAssertThrowsError(try Crypto.deserializeNote(shortData))
    }

    // MARK: - Note Encryption/Decryption

    func testEncryptDecryptRoundtrip() throws {
        let plaintext = Data("secret note data for testing encryption".utf8)
        let viewingKey = Crypto.sha256(Data("test-viewing-key".utf8))

        let (encrypted, nonce) = try Crypto.encryptNote(noteData: plaintext, viewingKey: viewingKey)

        let decrypted = Crypto.decryptNote(encryptedData: encrypted, nonce: nonce, viewingKey: viewingKey)
        XCTAssertNotNil(decrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testEncryptDifferentNonce() throws {
        let plaintext = Data("same plaintext".utf8)
        let viewingKey = Crypto.sha256(Data("test-key".utf8))

        let (enc1, nonce1) = try Crypto.encryptNote(noteData: plaintext, viewingKey: viewingKey)
        let (enc2, nonce2) = try Crypto.encryptNote(noteData: plaintext, viewingKey: viewingKey)

        // Random nonces should differ, so ciphertexts should differ
        XCTAssertNotEqual(nonce1, nonce2, "Nonces should be random")
        XCTAssertNotEqual(enc1, enc2, "Ciphertexts with different nonces should differ")

        // But both should decrypt to same plaintext
        XCTAssertEqual(Crypto.decryptNote(encryptedData: enc1, nonce: nonce1, viewingKey: viewingKey), plaintext)
        XCTAssertEqual(Crypto.decryptNote(encryptedData: enc2, nonce: nonce2, viewingKey: viewingKey), plaintext)
    }

    func testDecryptWithWrongKey() throws {
        let plaintext = Data("secret".utf8)
        let correctKey = Crypto.sha256(Data("correct".utf8))
        let wrongKey = Crypto.sha256(Data("wrong".utf8))

        let (encrypted, nonce) = try Crypto.encryptNote(noteData: plaintext, viewingKey: correctKey)

        let result = Crypto.decryptNote(encryptedData: encrypted, nonce: nonce, viewingKey: wrongKey)
        XCTAssertNil(result, "Decryption with wrong key should fail")
    }

    func testDecryptWithWrongNonce() throws {
        let plaintext = Data("secret".utf8)
        let key = Crypto.sha256(Data("key".utf8))

        let (encrypted, _) = try Crypto.encryptNote(noteData: plaintext, viewingKey: key)
        let wrongNonce = Crypto.randomBytes(12)

        let result = Crypto.decryptNote(encryptedData: encrypted, nonce: wrongNonce, viewingKey: key)
        XCTAssertNil(result, "Decryption with wrong nonce should fail")
    }

    // MARK: - BigInt Conversion

    func testBigintToBytes32() {
        let value = BigUInt(1_000_000)
        let bytes = Crypto.bigintToBytes32(value)
        XCTAssertEqual(bytes.count, 32)
        // 1000000 = 0x0F4240
        XCTAssertEqual(bytes[29], 0x0F)
        XCTAssertEqual(bytes[30], 0x42)
        XCTAssertEqual(bytes[31], 0x40)
    }

    func testBytes32ToBigUInt() {
        var data = Data(repeating: 0, count: 32)
        data[31] = 42
        let value = Crypto.bytes32ToBigUInt(data)
        XCTAssertEqual(value, 42)
    }

    func testBigintRoundtrip() {
        let original = BigUInt("21888242871839275222246405745257275088548364400416034343698204186575808495616")
        let bytes = Crypto.bigintToBytes32(original)
        let recovered = Crypto.bytes32ToBigUInt(bytes)
        XCTAssertEqual(recovered, original)
    }

    func testIsInField() {
        XCTAssertTrue(Crypto.isInField(BigUInt(0)))
        XCTAssertTrue(Crypto.isInField(BigUInt(42)))

        let primeMinusOne = BigUInt("21888242871839275222246405745257275088548364400416034343698204186575808495616")
        XCTAssertTrue(Crypto.isInField(primeMinusOne))

        let prime = BigUInt("21888242871839275222246405745257275088548364400416034343698204186575808495617")
        XCTAssertFalse(Crypto.isInField(prime))
    }

    // MARK: - Full Flow: Commitment → Nullifier

    func testFullCommitmentNullifierFlow() throws {
        let km = KeyManager.fromSeed(Data(0..<32))
        let randomness = Crypto.sha256(Data("test-randomness".utf8))

        // Create commitment
        let commitment = try Crypto.computeCommitment(
            value: 500_000,
            owner: km.shieldedAddress,
            randomness: randomness
        )
        XCTAssertEqual(commitment.count, 32)

        // Compute nullifier
        let nullifier = try Crypto.computeNullifier(
            commitment: commitment,
            nullifierKey: km.nullifierKey,
            epoch: 1,
            leafIndex: 0
        )
        XCTAssertEqual(nullifier.count, 32)
        XCTAssertNotEqual(nullifier, commitment, "Nullifier should differ from commitment")
    }
}

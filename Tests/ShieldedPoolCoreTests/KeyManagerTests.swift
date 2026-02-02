import XCTest
@testable import ShieldedPoolCore

/// KeyManager tests — cross-validated against TS SDK key derivation
final class KeyManagerTests: XCTestCase {

    // Known seed: bytes 0x00..0x1f
    let testSeed = Data(0..<32)

    func testKeyDerivationFromSeed() throws {
        let km = KeyManager.fromSeed(testSeed)

        // Cross-validated against TS SDK: SHA256("spending" + seed), etc.
        XCTAssertEqual(km.spendingKey.hexString,
                       "3ee92c5801db4f2837a4bde76093da160891c42f61ab4a4502341401f9f71088")
        XCTAssertEqual(km.viewingKey.hexString,
                       "665a8176f53d0716143ed42d630b58358cb63bef4c70f6353b0814cc99f9af06")
        XCTAssertEqual(km.nullifierKey.hexString,
                       "bb21aa1f9d086cae980b5bfa0ddfeb527499dad03526d3682224b35205633e84")
        XCTAssertEqual(km.shieldedAddress.hexString,
                       "308449e3fb08dd1f9893f8a7df2202ee06436afe6cb554cc478d6531d021946e")
    }

    func testKeyDerivationDeterministic() throws {
        let km1 = KeyManager.fromSeed(testSeed)
        let km2 = KeyManager.fromSeed(testSeed)

        XCTAssertEqual(km1.spendingKey, km2.spendingKey)
        XCTAssertEqual(km1.viewingKey, km2.viewingKey)
        XCTAssertEqual(km1.nullifierKey, km2.nullifierKey)
        XCTAssertEqual(km1.shieldedAddress, km2.shieldedAddress)
    }

    func testDifferentSeedsDifferentKeys() throws {
        let km1 = KeyManager.fromSeed(Data(repeating: 0, count: 32))
        let km2 = KeyManager.fromSeed(Data(repeating: 1, count: 32))

        XCTAssertNotEqual(km1.spendingKey, km2.spendingKey)
        XCTAssertNotEqual(km1.viewingKey, km2.viewingKey)
        XCTAssertNotEqual(km1.nullifierKey, km2.nullifierKey)
        XCTAssertNotEqual(km1.shieldedAddress, km2.shieldedAddress)
    }

    func testAllKeysAre32Bytes() throws {
        let km = KeyManager.fromSeed(testSeed)
        XCTAssertEqual(km.spendingKey.count, 32)
        XCTAssertEqual(km.viewingKey.count, 32)
        XCTAssertEqual(km.nullifierKey.count, 32)
        XCTAssertEqual(km.shieldedAddress.count, 32)
    }

    func testExportKeys() throws {
        let km = KeyManager.fromSeed(testSeed)
        let exported = km.exportKeys()
        XCTAssertEqual(exported.seed, testSeed)
        XCTAssertEqual(exported.spendingKey, km.spendingKey)
        XCTAssertEqual(exported.viewingKey, km.viewingKey)
    }

    func testShieldedAddressBase58() throws {
        let km = KeyManager.fromSeed(testSeed)
        let base58 = km.shieldedAddressString
        // Should be non-empty and decodable
        XCTAssertFalse(base58.isEmpty)
        XCTAssertTrue(KeyManager.validateShieldedAddress(base58))

        // Roundtrip
        let decoded = try KeyManager.decodeShieldedAddress(base58)
        XCTAssertEqual(decoded, km.shieldedAddress)
    }

    func testInvalidShieldedAddress() {
        // Characters not in Base58 alphabet should fail decode
        XCTAssertNil(Base58.decode("0OIl"), "0, O, I, l are not in Base58")

        // TODO: Base58.decode("") and short strings return 32-byte zero-padded data
        // which passes validateShieldedAddress. Fix Base58.decode to reject short inputs.
    }
}

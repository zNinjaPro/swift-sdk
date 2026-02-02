import XCTest
@testable import ShieldedPoolSDK

/// BorshEncoder tests — verify Borsh binary encoding matches expected layouts
final class BorshSerializeTests: XCTestCase {

    func testWriteU8() {
        var enc = BorshEncoder()
        enc.writeU8(42)
        XCTAssertEqual(enc.encode(), Data([42]))
    }

    func testWriteU32LittleEndian() {
        var enc = BorshEncoder()
        enc.writeU32(256) // 0x00000100 LE = [0x00, 0x01, 0x00, 0x00]
        XCTAssertEqual(enc.encode(), Data([0x00, 0x01, 0x00, 0x00]))
    }

    func testWriteU64LittleEndian() {
        var enc = BorshEncoder()
        enc.writeU64(1_000_000) // 0xF4240 LE
        let expected = Data([0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00])
        XCTAssertEqual(enc.encode(), expected)
    }

    func testWriteBytes32() {
        var enc = BorshEncoder()
        let data = Data(repeating: 0xAA, count: 32)
        enc.writeBytes32(data)
        XCTAssertEqual(enc.encode().count, 32)
        XCTAssertEqual(enc.encode(), data)
    }

    func testWriteBytesWithLengthPrefix() {
        var enc = BorshEncoder()
        let payload = Data([0x01, 0x02, 0x03])
        enc.writeBytes(payload)
        // u32 length (3) + 3 bytes
        let expected = Data([0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03])
        XCTAssertEqual(enc.encode(), expected)
    }

    func testWriteEmptyBytes() {
        var enc = BorshEncoder()
        enc.writeBytes(Data())
        // u32 length (0)
        XCTAssertEqual(enc.encode(), Data([0x00, 0x00, 0x00, 0x00]))
    }

    func testWriteString() {
        var enc = BorshEncoder()
        enc.writeString("hello")
        // u32 length (5) + "hello" UTF-8
        let expected = Data([0x05, 0x00, 0x00, 0x00]) + Data("hello".utf8)
        XCTAssertEqual(enc.encode(), expected)
    }

    func testWriteBool() {
        var enc = BorshEncoder()
        enc.writeBool(true)
        enc.writeBool(false)
        XCTAssertEqual(enc.encode(), Data([0x01, 0x00]))
    }

    func testWriteVecBytes32() {
        var enc = BorshEncoder()
        let items = [Data(repeating: 0x11, count: 32), Data(repeating: 0x22, count: 32)]
        enc.writeVecBytes32(items)
        // u32 count (2) + 2 × 32 bytes = 68 bytes
        XCTAssertEqual(enc.encode().count, 4 + 64)
        // First 4 bytes = count = 2
        XCTAssertEqual(Array(enc.encode().prefix(4)), [0x02, 0x00, 0x00, 0x00])
    }

    func testWriteVecU64() {
        var enc = BorshEncoder()
        enc.writeVecU64([100, 200])
        // u32 count (2) + 2 × 8 bytes = 20 bytes
        XCTAssertEqual(enc.encode().count, 4 + 16)
    }

    func testWriteVecBytes() {
        var enc = BorshEncoder()
        enc.writeVecBytes([Data([0x01, 0x02]), Data([0x03])])
        // u32 outer count (2) + (u32 len(2) + 2 bytes) + (u32 len(1) + 1 byte) = 4+6+5 = 15
        XCTAssertEqual(enc.encode().count, 15)
    }

    func testCombinedEncoding() {
        // Simulate deposit_v2 args: discriminator(8) + commitment(32) + amount(8) + encrypted_note(4+N)
        var enc = BorshEncoder()
        enc.writeFixedBytes([0x6d, 0x4b, 0x45, 0x99, 0xac, 0xda, 0x92, 0x13]) // discriminator
        enc.writeBytes32(Data(repeating: 0xAB, count: 32)) // commitment
        enc.writeU64(1_000_000_000) // amount (1 SOL)
        enc.writeBytes(Data(repeating: 0xCC, count: 10)) // encrypted note

        let result = enc.encode()
        XCTAssertEqual(result.count, 8 + 32 + 8 + 4 + 10) // 62 bytes

        // Verify discriminator
        XCTAssertEqual(Array(result.prefix(8)), [0x6d, 0x4b, 0x45, 0x99, 0xac, 0xda, 0x92, 0x13])

        // Verify amount at offset 40 (8+32)
        let amountBytes = result[40..<48]
        let amount = amountBytes.withUnsafeBytes { $0.load(as: UInt64.self) }
        XCTAssertEqual(UInt64(littleEndian: amount), 1_000_000_000)
    }
}

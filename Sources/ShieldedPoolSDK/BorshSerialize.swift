import Foundation

/// Borsh binary serialization for Anchor instruction encoding.
/// Borsh uses little-endian for integers and u32-prefixed lengths for dynamic types.
public struct BorshEncoder {
    private(set) var data = Data()

    public init() {}

    /// Write raw bytes (no length prefix)
    public mutating func writeFixedBytes(_ bytes: Data) {
        data.append(bytes)
    }

    /// Write raw bytes (no length prefix)
    public mutating func writeFixedBytes(_ bytes: [UInt8]) {
        data.append(contentsOf: bytes)
    }

    /// Write u8
    public mutating func writeU8(_ value: UInt8) {
        data.append(value)
    }

    /// Write u32 (little-endian)
    public mutating func writeU32(_ value: UInt32) {
        var v = value.littleEndian
        data.append(Data(bytes: &v, count: 4))
    }

    /// Write u64 (little-endian)
    public mutating func writeU64(_ value: UInt64) {
        var v = value.littleEndian
        data.append(Data(bytes: &v, count: 8))
    }

    /// Write i64 (little-endian)
    public mutating func writeI64(_ value: Int64) {
        var v = value.littleEndian
        data.append(Data(bytes: &v, count: 8))
    }

    /// Write bool (1 byte: 0 or 1)
    public mutating func writeBool(_ value: Bool) {
        data.append(value ? 1 : 0)
    }

    /// Write Borsh bytes/Vec<u8> (u32 length prefix + raw bytes)
    public mutating func writeBytes(_ bytes: Data) {
        writeU32(UInt32(bytes.count))
        data.append(bytes)
    }

    /// Write Borsh string (u32 length prefix + UTF-8 bytes)
    public mutating func writeString(_ string: String) {
        let utf8 = Data(string.utf8)
        writeU32(UInt32(utf8.count))
        data.append(utf8)
    }

    /// Write a fixed-size byte array [u8; N] (no length prefix)
    public mutating func writeBytes32(_ bytes: Data) {
        precondition(bytes.count == 32, "Expected 32 bytes, got \(bytes.count)")
        data.append(bytes)
    }

    /// Write Pubkey (32 raw bytes, no prefix)
    public mutating func writePubkey(_ bytes: Data) {
        writeBytes32(bytes)
    }

    /// Write Option<T> — 0 byte for None, 1 byte + value for Some
    public mutating func writeOptionalU64(_ value: UInt64?) {
        if let v = value {
            writeU8(1)
            writeU64(v)
        } else {
            writeU8(0)
        }
    }

    /// Write Vec<[u8; 32]> — u32 count + N×32 bytes
    public mutating func writeVecBytes32(_ items: [Data]) {
        writeU32(UInt32(items.count))
        for item in items {
            writeBytes32(item)
        }
    }

    /// Write Vec<u64> — u32 count + N×8 bytes
    public mutating func writeVecU64(_ items: [UInt64]) {
        writeU32(UInt32(items.count))
        for item in items {
            writeU64(item)
        }
    }

    /// Write Vec<Vec<u8>> — u32 count + N×(u32 len + bytes)
    public mutating func writeVecBytes(_ items: [Data]) {
        writeU32(UInt32(items.count))
        for item in items {
            writeBytes(item)
        }
    }

    /// Finalize and return encoded data
    public func encode() -> Data {
        return data
    }
}

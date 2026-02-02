import XCTest
@testable import ShieldedPoolCore

final class PoseidonTests: XCTestCase {
    
    // Test vectors extracted from TypeScript SDK
    // These must match exactly to ensure compatibility
    
    func testSingleInputZeros() throws {
        // Input: 32 bytes of 0x00
        let input = Data(count: 32)
        let result = try Poseidon.hash([input])
        
        let expected = Data(hexString: "2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c")!
        XCTAssertEqual(result, expected, "Single input (zeros) hash mismatch")
    }
    
    func testSingleInput0x01() throws {
        // Input: 32 bytes of 0x01
        let input = Data(repeating: 0x01, count: 32)
        let result = try Poseidon.hash([input])
        
        let expected = Data(hexString: "05bface581ee6177cc19c6c56363a68882f11e8407ac639db991e0d27f1b75e6")!
        XCTAssertEqual(result, expected, "Single input (0x01) hash mismatch")
    }
    
    func testTwoInputs() throws {
        let input1 = Data(repeating: 0x01, count: 32)
        let input2 = Data(repeating: 0x02, count: 32)
        let result = try Poseidon.hash([input1, input2])
        
        let expected = Data(hexString: "0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990")!
        XCTAssertEqual(result, expected, "Two input hash mismatch")
    }
    
    func testCommitmentStyleThreeInputs() throws {
        // Simulates commitment: Hash(value, owner, randomness)
        let value = Data(hexString: "0000000000000000000000000000000000000000000000000000000000000064")! // 100
        let owner = Data(repeating: 0xAB, count: 32)
        let randomness = Data(repeating: 0xCD, count: 32)
        
        let result = try Poseidon.hash([value, owner, randomness])
        
        let expected = Data(hexString: "0b93b96be23efa39695e7bc94460808d928d601013535d10a166517dc35d7757")!
        XCTAssertEqual(result, expected, "Three input (commitment-style) hash mismatch")
    }
    
    func testHash2Convenience() throws {
        let left = Data(repeating: 0x01, count: 32)
        let right = Data(repeating: 0x02, count: 32)
        
        let result = try Poseidon.hash2(left, right)
        let expected = try Poseidon.hash([left, right])
        
        XCTAssertEqual(result, expected, "hash2 should equal hash with two inputs")
    }
    
    func testDeterminism() throws {
        let input = Data(repeating: 0x42, count: 32)
        
        let result1 = try Poseidon.hash([input])
        let result2 = try Poseidon.hash([input])
        
        XCTAssertEqual(result1, result2, "Poseidon should be deterministic")
    }
    
    func testInputSensitivity() throws {
        let input1 = Data(repeating: 0x01, count: 32)
        var input2 = input1
        input2[0] = 0x02 // Change one byte
        
        let result1 = try Poseidon.hash([input1])
        let result2 = try Poseidon.hash([input2])
        
        XCTAssertNotEqual(result1, result2, "Different inputs should produce different outputs")
    }
    
    func testOutputLength() throws {
        let input = Data(repeating: 0x01, count: 32)
        let result = try Poseidon.hash([input])
        
        XCTAssertEqual(result.count, 32, "Output should be 32 bytes")
    }
    
    func testInvalidInputCount() {
        // Zero inputs
        XCTAssertThrowsError(try Poseidon.hash([])) { error in
            guard case Poseidon.PoseidonError.invalidInputCount = error else {
                XCTFail("Expected invalidInputCount error")
                return
            }
        }
        
        // Five inputs (too many — max is 4)
        let inputs = (0..<5).map { _ in Data(count: 32) }
        XCTAssertThrowsError(try Poseidon.hash(inputs)) { error in
            guard case Poseidon.PoseidonError.invalidInputCount = error else {
                XCTFail("Expected invalidInputCount error")
                return
            }
        }
    }
    
    func testFieldArithmetic() {
        // Test modular arithmetic stays within field
        let largeValue = Poseidon.BN254_PRIME - 1
        let result = Poseidon.modPrime(largeValue + 1)
        XCTAssertEqual(result, .zero, "Prime should wrap to zero")
        
        let result2 = Poseidon.modPrime(largeValue + 2)
        XCTAssertEqual(result2, 1, "Prime + 1 should wrap to 1")
    }
    
    func testBytesToFieldConversion() {
        // Zero bytes
        let zeros = Data(count: 32)
        let fieldZero = Poseidon.bytesToField(zeros)
        XCTAssertEqual(fieldZero, .zero)
        
        // One in last byte (big-endian)
        var one = Data(count: 32)
        one[31] = 1
        let fieldOne = Poseidon.bytesToField(one)
        XCTAssertEqual(fieldOne, 1)
    }
    
    func testFieldToBytesConversion() {
        let value = Poseidon.FieldElement(12345)
        let bytes = Poseidon.fieldToBytes(value)
        
        XCTAssertEqual(bytes.count, 32, "Should be 32 bytes")
        
        // Convert back
        let recovered = Poseidon.bytesToField(bytes)
        XCTAssertEqual(recovered, value, "Round-trip should preserve value")
    }
}

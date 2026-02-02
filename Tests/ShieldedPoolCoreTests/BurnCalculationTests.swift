import XCTest
@testable import ShieldedPoolCore

/// Burn Calculation Tests
///
/// Tests for the burn mechanism (0.1% default) applied on deposits and withdrawals.
/// Per TESTING_STRATEGY.md - these are critical paths requiring 100% coverage.
final class BurnCalculationTests: XCTestCase {

    // MARK: - calculateBurnAmount Tests

    func testCalculateBurnAmountNormal() {
        // 1,000,000,000 lamports at 10 bps = 1,000,000 burn
        let burn = calculateBurnAmount(1_000_000_000, burnRateBps: 10)
        XCTAssertEqual(burn, 1_000_000)
    }

    func testDefaultBurnRateBps() {
        XCTAssertEqual(Constants.defaultBurnRateBps, 10)
    }

    func testCalculateBurnAmountZero() {
        let burn = calculateBurnAmount(0, burnRateBps: 10)
        XCTAssertEqual(burn, 0)
    }

    func testCalculateBurnAmountDust() {
        // 999 lamports at 10 bps = 0 burn (rounds down)
        let burn = calculateBurnAmount(999, burnRateBps: 10)
        XCTAssertEqual(burn, 0)
    }

    func testCalculateBurnAmountRoundsDown() {
        // 10001 at 10 bps = 10001 * 10 / 10000 = 100010 / 10000 = 10.001 → 10
        let burn = calculateBurnAmount(10001, burnRateBps: 10)
        XCTAssertEqual(burn, 10)
    }

    func testCalculateBurnAmountAtThreshold() {
        // 1000 lamports at 10 bps = 1 burn (exactly at threshold)
        let burn = calculateBurnAmount(1000, burnRateBps: 10)
        XCTAssertEqual(burn, 1)
    }

    func testCalculateBurnAmountMaxRate() {
        // Maximum allowed burn rate (1000 bps = 10%)
        let burn = calculateBurnAmount(1_000_000_000, burnRateBps: 1000)
        XCTAssertEqual(burn, 100_000_000)
    }

    func testCalculateBurnAmountZeroRate() {
        // Zero burn rate = no burn
        let burn = calculateBurnAmount(1_000_000_000, burnRateBps: 0)
        XCTAssertEqual(burn, 0)
    }

    func testCalculateBurnAmountOneBps() {
        // 1 bps = 0.01%
        let burn = calculateBurnAmount(1_000_000, burnRateBps: 1)
        XCTAssertEqual(burn, 100)
    }

    func testCalculateBurnAmountHundredBps() {
        // 100 bps = 1%
        let burn = calculateBurnAmount(1_000_000_000, burnRateBps: 100)
        XCTAssertEqual(burn, 10_000_000)
    }

    func testCalculateBurnAmountLargeValue() {
        // 10 billion tokens (large but within UInt64)
        let largeAmount: UInt64 = 10_000_000_000_000_000
        let burn = calculateBurnAmount(largeAmount, burnRateBps: 10)
        XCTAssertEqual(burn, 10_000_000_000_000)
    }

    // MARK: - calculateAmountAfterBurn Tests

    func testCalculateAmountAfterBurnNormal() {
        let net = calculateAmountAfterBurn(1_000_000_000, burnRateBps: 10)
        XCTAssertEqual(net, 999_000_000)
    }

    func testCalculateAmountAfterBurnZero() {
        let net = calculateAmountAfterBurn(0, burnRateBps: 10)
        XCTAssertEqual(net, 0)
    }

    func testCalculateAmountAfterBurnDust() {
        // 999 at 10 bps → burn = 0, net = 999
        let net = calculateAmountAfterBurn(999, burnRateBps: 10)
        XCTAssertEqual(net, 999)
    }

    func testCalculateAmountAfterBurnZeroRate() {
        let net = calculateAmountAfterBurn(1_000_000_000, burnRateBps: 0)
        XCTAssertEqual(net, 1_000_000_000)
    }

    func testCalculateAmountAfterBurnMaxRate() {
        // 10% burn → 90% remaining
        let net = calculateAmountAfterBurn(1_000_000_000, burnRateBps: 1000)
        XCTAssertEqual(net, 900_000_000)
    }

    func testAmountInvariant() {
        // amount = afterBurn + burnAmount
        let amount: UInt64 = 1_234_567_890
        let rate: UInt16 = 10
        let burnAmount = calculateBurnAmount(amount, burnRateBps: rate)
        let afterBurn = calculateAmountAfterBurn(amount, burnRateBps: rate)
        XCTAssertEqual(burnAmount + afterBurn, amount)
    }

    // MARK: - calculateGrossAmount Tests

    func testCalculateGrossAmountBasic() {
        let net: UInt64 = 1_000_000_000
        let gross = calculateGrossAmount(net, burnRateBps: 10)
        // gross should be slightly more than net
        XCTAssertGreaterThan(gross, net)
    }

    func testCalculateGrossAmountProducesTargetNet() {
        let targetNet: UInt64 = 1_000_000_000
        let gross = calculateGrossAmount(targetNet, burnRateBps: 10)
        let actualNet = calculateAmountAfterBurn(gross, burnRateBps: 10)
        XCTAssertGreaterThanOrEqual(actualNet, targetNet)
    }

    func testCalculateGrossAmountZero() {
        let gross = calculateGrossAmount(0, burnRateBps: 10)
        XCTAssertEqual(gross, 0)
    }

    func testCalculateGrossAmountZeroRate() {
        let gross = calculateGrossAmount(1_000_000_000, burnRateBps: 0)
        XCTAssertEqual(gross, 1_000_000_000)
    }

    func testCalculateGrossAmountMaxRate() {
        let net: UInt64 = 900_000_000
        let gross = calculateGrossAmount(net, burnRateBps: 1000)
        XCTAssertEqual(gross, 1_000_000_000)
    }

    func testCalculateGrossAmountInverse() {
        // Should be approximately inverse of calculateAmountAfterBurn
        let original: UInt64 = 1_000_000_000
        let rate: UInt16 = 10
        let afterBurn = calculateAmountAfterBurn(original, burnRateBps: rate)
        let reconstructed = calculateGrossAmount(afterBurn, burnRateBps: rate)
        // Due to rounding, reconstructed should be close to original
        XCTAssertGreaterThanOrEqual(reconstructed, original - 1)
        XCTAssertLessThanOrEqual(reconstructed, original + 1)
    }

    func testCalculateGrossAmountVariousRates() {
        let testCases: [(net: UInt64, rate: UInt16)] = [
            (1_000_000, 1),
            (1_000_000, 5),
            (1_000_000, 10),
            (1_000_000, 50),
            (1_000_000, 100),
            (1_000_000, 500),
        ]

        for (net, rate) in testCases {
            let gross = calculateGrossAmount(net, burnRateBps: rate)
            let actualNet = calculateAmountAfterBurn(gross, burnRateBps: rate)
            XCTAssertGreaterThanOrEqual(actualNet, net, "Failed for rate=\(rate)")
        }
    }

    // MARK: - Edge Cases

    func testMinimumNonZeroBurn() {
        // Find minimum amount that produces 1 lamport burn at 10 bps
        XCTAssertEqual(calculateBurnAmount(1000, burnRateBps: 10), 1)
        XCTAssertEqual(calculateBurnAmount(999, burnRateBps: 10), 0)
    }

    func testConsistencyAcrossFunctions() {
        let amounts: [UInt64] = [1, 100, 1000, 10000, 1_000_000, 1_000_000_000]
        let rates: [UInt16] = [0, 1, 5, 10, 50, 100, 500, 1000]

        for amount in amounts {
            for rate in rates {
                let burn = calculateBurnAmount(amount, burnRateBps: rate)
                let afterBurn = calculateAmountAfterBurn(amount, burnRateBps: rate)

                // Invariant: burn + afterBurn = amount
                XCTAssertEqual(burn + afterBurn, amount, "Invariant violated for amount=\(amount), rate=\(rate)")

                // Invariant: afterBurn <= amount
                XCTAssertLessThanOrEqual(afterBurn, amount)
            }
        }
    }

    // MARK: - Real-world Scenarios

    func testOneSOLDeposit() {
        let oneSOL: UInt64 = 1_000_000_000 // 1 SOL = 10^9 lamports
        let burn = calculateBurnAmount(oneSOL, burnRateBps: Constants.defaultBurnRateBps)
        let credited = calculateAmountAfterBurn(oneSOL, burnRateBps: Constants.defaultBurnRateBps)

        XCTAssertEqual(burn, 1_000_000) // 0.001 SOL burned
        XCTAssertEqual(credited, 999_000_000) // 0.999 SOL credited
    }

    func testHundredSOLDeposit() {
        let hundredSOL: UInt64 = 100_000_000_000
        let burn = calculateBurnAmount(hundredSOL, burnRateBps: Constants.defaultBurnRateBps)
        let credited = calculateAmountAfterBurn(hundredSOL, burnRateBps: Constants.defaultBurnRateBps)

        XCTAssertEqual(burn, 100_000_000) // 0.1 SOL burned
        XCTAssertEqual(credited, 99_900_000_000) // 99.9 SOL credited
    }

    func testGrossAmountForDesiredNet() {
        let desiredNet: UInt64 = 1_000_000_000
        let grossNeeded = calculateGrossAmount(desiredNet, burnRateBps: Constants.defaultBurnRateBps)
        let actualNet = calculateAmountAfterBurn(grossNeeded, burnRateBps: Constants.defaultBurnRateBps)

        // User needs to deposit grossNeeded to receive at least desiredNet
        XCTAssertGreaterThanOrEqual(actualNet, desiredNet)
        // Gross should be approximately 1.001001... SOL
        XCTAssertEqual(grossNeeded, 1_001_001_001)
    }

    // MARK: - Cross-validation with TypeScript SDK

    func testCrossValidationWithTypeScriptSDK() {
        // These values should match exactly with the TypeScript SDK tests
        
        // Test case 1: Normal calculation
        XCTAssertEqual(calculateBurnAmount(1_000_000_000, burnRateBps: 10), 1_000_000)
        
        // Test case 2: Dust amount
        XCTAssertEqual(calculateBurnAmount(999, burnRateBps: 10), 0)
        
        // Test case 3: Max rate
        XCTAssertEqual(calculateBurnAmount(1_000_000_000, burnRateBps: 1000), 100_000_000)
        
        // Test case 4: Amount after burn
        XCTAssertEqual(calculateAmountAfterBurn(1_000_000_000, burnRateBps: 10), 999_000_000)
        
        // Test case 5: Gross amount
        XCTAssertEqual(calculateGrossAmount(1_000_000_000, burnRateBps: 10), 1_001_001_001)
    }
}

import Foundation
import BigInt

/// Poseidon parameters loader
/// Loads round constants and MDS matrix from bundled JSON
enum PoseidonParams {
    
    typealias FieldElement = BigUInt
    
    /// Cached parameter tables by width
    /// Using nonisolated(unsafe) since this is initialized once at startup and read-only thereafter
    nonisolated(unsafe) static var table: [Int: Poseidon.Parameters] = {
        loadParameters()
    }()
    
    /// Load parameters from bundled JSON
    private static func loadParameters() -> [Int: Poseidon.Parameters] {
        var result: [Int: Poseidon.Parameters] = [:]
        
        // Load from bundle
        guard let url = Bundle.module.url(forResource: "solana_poseidon_params", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let json = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            // Fallback: return empty (will fail at runtime with clear error)
            assertionFailure("Failed to load Poseidon parameters from bundle")
            return result
        }
        
        for entry in json {
            guard let width = entry["width"] as? Int,
                  let fullRounds = entry["full_rounds"] as? Int,
                  let partialRounds = entry["partial_rounds"] as? Int,
                  let alpha = entry["alpha"] as? Int,
                  let arkHex = entry["ark"] as? [String],
                  let mdsHex = entry["mds"] as? [[String]] else {
                continue
            }
            
            let ark = arkHex.map { hexToField($0) }
            let mds = mdsHex.map { row in row.map { hexToField($0) } }
            
            result[width] = Poseidon.Parameters(
                width: width,
                fullRounds: fullRounds,
                partialRounds: partialRounds,
                alpha: alpha,
                ark: ark,
                mds: mds
            )
        }
        
        return result
    }
    
    /// Convert hex string to field element
    private static func hexToField(_ hex: String) -> FieldElement {
        FieldElement(hex, radix: 16) ?? .zero
    }
}

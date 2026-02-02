import Foundation

// MARK: - Circuit Artifact Configuration

/// Available circuit types
public enum CircuitArtifact: String, CaseIterable, Sendable {
    case withdraw = "withdraw"
    case transfer = "transfer"
    case joinsplit = "joinsplit"
    case renew = "renew"
    
    /// Approximate size in bytes for download progress
    public var estimatedSize: Int64 {
        switch self {
        case .withdraw: return 4_500_000   // ~4.5MB
        case .transfer: return 9_200_000   // ~9.2MB
        case .joinsplit: return 18_000_000 // ~18MB
        case .renew: return 4_700_000      // ~4.7MB
        }
    }
    
    /// Required files for this circuit
    public var requiredFiles: [ArtifactFile] {
        return [
            ArtifactFile(name: "\(rawValue)_final.zkey", type: .zkey),
            ArtifactFile(name: "\(rawValue).wcd", type: .witnessGraph),
        ]
    }
}

/// Artifact file types
public enum ArtifactFileType: String, Sendable {
    case zkey = "zkey"           // Proving key for rapidsnark
    case witnessGraph = "wcd"    // Witness calculation graph for witnesscalc
    case wasm = "wasm"           // WASM for fallback witness generation
    case verificationKey = "json" // Verification key (bundled, small)
}

/// Individual artifact file info
public struct ArtifactFile: Sendable {
    public let name: String
    public let type: ArtifactFileType
}

/// Download progress delegate
public protocol ArtifactDownloadDelegate: AnyObject {
    func downloadProgress(circuit: CircuitArtifact, progress: Double, bytesDownloaded: Int64, totalBytes: Int64)
    func downloadCompleted(circuit: CircuitArtifact)
    func downloadFailed(circuit: CircuitArtifact, error: Error)
}

// MARK: - Circuit Artifact Manager

/// Manages on-demand downloading and caching of circuit artifacts
/// Artifacts are stored in App Group container for sharing across app extensions
public final class CircuitArtifactManager: @unchecked Sendable {
    
    /// Shared instance
    public static let shared = CircuitArtifactManager()
    
    /// Base URL for artifact downloads
    private var baseURL: URL?
    
    /// App Group identifier for shared storage
    private var appGroupIdentifier: String?
    
    /// Download delegate
    public weak var delegate: ArtifactDownloadDelegate?
    
    /// Active downloads
    private var activeDownloads: [CircuitArtifact: URLSessionDownloadTask] = [:]
    
    /// Lock for thread-safe access
    private let lock = NSLock()
    
    /// URLSession for downloads
    private lazy var downloadSession: URLSession = {
        let config = URLSessionConfiguration.default
        config.allowsCellularAccess = true
        config.waitsForConnectivity = true
        return URLSession(configuration: config, delegate: nil, delegateQueue: .main)
    }()
    
    private init() {}
    
    // MARK: - Configuration
    
    /// Configure the artifact manager
    /// - Parameters:
    ///   - baseURL: Base URL for downloading artifacts
    ///   - appGroupIdentifier: Optional App Group ID for shared storage
    public func configure(baseURL: URL, appGroupIdentifier: String? = nil) {
        self.baseURL = baseURL
        self.appGroupIdentifier = appGroupIdentifier
    }
    
    // MARK: - Directory Management
    
    /// Get the artifacts directory
    public var artifactsDirectory: URL {
        let baseDir: URL
        
        if let groupId = appGroupIdentifier,
           let groupURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupId) {
            baseDir = groupURL
        } else {
            baseDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        }
        
        let artifactsDir = baseDir.appendingPathComponent("ShieldedPoolCircuits", isDirectory: true)
        
        // Create directory if needed
        try? FileManager.default.createDirectory(at: artifactsDir, withIntermediateDirectories: true)
        
        return artifactsDir
    }
    
    /// Get path for a specific artifact file
    public func artifactPath(circuit: CircuitArtifact, fileType: ArtifactFileType) -> URL {
        let fileName: String
        switch fileType {
        case .zkey:
            fileName = "\(circuit.rawValue)_final.zkey"
        case .witnessGraph:
            fileName = "\(circuit.rawValue).wcd"
        case .wasm:
            fileName = "\(circuit.rawValue).wasm"
        case .verificationKey:
            fileName = "\(circuit.rawValue)_verification_key.json"
        }
        return artifactsDirectory.appendingPathComponent(fileName)
    }
    
    // MARK: - Availability Checks
    
    /// Check if a circuit's artifacts are downloaded and ready
    public func isCircuitReady(_ circuit: CircuitArtifact) -> Bool {
        let zkeyPath = artifactPath(circuit: circuit, fileType: .zkey)
        let wcdPath = artifactPath(circuit: circuit, fileType: .witnessGraph)
        
        return FileManager.default.fileExists(atPath: zkeyPath.path) &&
               FileManager.default.fileExists(atPath: wcdPath.path)
    }
    
    /// Check if WASM fallback is available for a circuit
    public func isWASMFallbackAvailable(_ circuit: CircuitArtifact) -> Bool {
        let wasmPath = artifactPath(circuit: circuit, fileType: .wasm)
        return FileManager.default.fileExists(atPath: wasmPath.path)
    }
    
    /// Get download status for all circuits
    public func getCircuitStatus() -> [CircuitArtifact: CircuitStatus] {
        var status: [CircuitArtifact: CircuitStatus] = [:]
        
        for circuit in CircuitArtifact.allCases {
            if isCircuitReady(circuit) {
                status[circuit] = .ready
            } else if activeDownloads[circuit] != nil {
                status[circuit] = .downloading
            } else {
                status[circuit] = .notDownloaded
            }
        }
        
        return status
    }
    
    /// Circuit availability status
    public enum CircuitStatus: Sendable {
        case notDownloaded
        case downloading
        case ready
    }
    
    // MARK: - Download Management
    
    /// Download circuit artifacts
    /// - Parameter circuit: Circuit to download
    public func downloadCircuit(_ circuit: CircuitArtifact) async throws {
        guard let baseURL = baseURL else {
            throw ArtifactError.notConfigured
        }
        
        guard activeDownloads[circuit] == nil else {
            throw ArtifactError.alreadyDownloading
        }
        
        // Download zkey
        let zkeyURL = baseURL.appendingPathComponent("\(circuit.rawValue)_final.zkey")
        let zkeyDestination = artifactPath(circuit: circuit, fileType: .zkey)
        try await downloadFile(from: zkeyURL, to: zkeyDestination, circuit: circuit)
        
        // Download witness graph
        let wcdURL = baseURL.appendingPathComponent("\(circuit.rawValue).wcd")
        let wcdDestination = artifactPath(circuit: circuit, fileType: .witnessGraph)
        try await downloadFile(from: wcdURL, to: wcdDestination, circuit: circuit)
        
        delegate?.downloadCompleted(circuit: circuit)
    }
    
    /// Download a single file
    private func downloadFile(from url: URL, to destination: URL, circuit: CircuitArtifact) async throws {
        let (tempURL, response) = try await downloadSession.download(from: url)
        
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw ArtifactError.downloadFailed("HTTP error")
        }
        
        // Move to destination
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.moveItem(at: tempURL, to: destination)
    }
    
    /// Cancel an active download
    public func cancelDownload(_ circuit: CircuitArtifact) {
        activeDownloads[circuit]?.cancel()
        activeDownloads.removeValue(forKey: circuit)
    }
    
    // MARK: - Bundle Fallback
    
    /// Copy bundled artifacts if available (for apps that include artifacts in bundle)
    public func copyBundledArtifacts(bundle: Bundle = .main) throws {
        for circuit in CircuitArtifact.allCases {
            // Try to copy zkey from bundle
            if let zkeyBundlePath = bundle.path(forResource: "\(circuit.rawValue)_final", ofType: "zkey") {
                let destination = artifactPath(circuit: circuit, fileType: .zkey)
                if !FileManager.default.fileExists(atPath: destination.path) {
                    try FileManager.default.copyItem(atPath: zkeyBundlePath, toPath: destination.path)
                }
            }
            
            // Try to copy wcd from bundle
            if let wcdBundlePath = bundle.path(forResource: circuit.rawValue, ofType: "wcd") {
                let destination = artifactPath(circuit: circuit, fileType: .witnessGraph)
                if !FileManager.default.fileExists(atPath: destination.path) {
                    try FileManager.default.copyItem(atPath: wcdBundlePath, toPath: destination.path)
                }
            }
            
            // Try to copy wasm fallback from bundle
            if let wasmBundlePath = bundle.path(forResource: circuit.rawValue, ofType: "wasm") {
                let destination = artifactPath(circuit: circuit, fileType: .wasm)
                if !FileManager.default.fileExists(atPath: destination.path) {
                    try FileManager.default.copyItem(atPath: wasmBundlePath, toPath: destination.path)
                }
            }
        }
    }
    
    // MARK: - Storage Management
    
    /// Get total size of downloaded artifacts
    public func totalDownloadedSize() -> Int64 {
        var totalSize: Int64 = 0
        
        let fileManager = FileManager.default
        if let enumerator = fileManager.enumerator(at: artifactsDirectory, includingPropertiesForKeys: [.fileSizeKey]) {
            while let url = enumerator.nextObject() as? URL {
                if let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize {
                    totalSize += Int64(size)
                }
            }
        }
        
        return totalSize
    }
    
    /// Delete all downloaded artifacts
    public func clearCache() throws {
        try FileManager.default.removeItem(at: artifactsDirectory)
        try FileManager.default.createDirectory(at: artifactsDirectory, withIntermediateDirectories: true)
    }
    
    /// Delete artifacts for a specific circuit
    public func clearCircuit(_ circuit: CircuitArtifact) throws {
        for file in circuit.requiredFiles {
            let path = artifactsDirectory.appendingPathComponent(file.name)
            try? FileManager.default.removeItem(at: path)
        }
        
        // Also remove WASM fallback if present
        let wasmPath = artifactPath(circuit: circuit, fileType: .wasm)
        try? FileManager.default.removeItem(at: wasmPath)
    }
}

// MARK: - Errors

public enum ArtifactError: Error, CustomStringConvertible {
    case notConfigured
    case alreadyDownloading
    case downloadFailed(String)
    case artifactNotFound(CircuitArtifact)
    case invalidArtifact(String)
    
    public var description: String {
        switch self {
        case .notConfigured:
            return "CircuitArtifactManager not configured. Call configure() first."
        case .alreadyDownloading:
            return "Download already in progress for this circuit"
        case .downloadFailed(let reason):
            return "Download failed: \(reason)"
        case .artifactNotFound(let circuit):
            return "Artifacts not found for circuit: \(circuit.rawValue). Download required."
        case .invalidArtifact(let reason):
            return "Invalid artifact: \(reason)"
        }
    }
}

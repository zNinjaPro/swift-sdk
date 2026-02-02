# Shielded Pool Swift SDK

Native Swift SDK for privacy-preserving token transfers on Solana using zero-knowledge proofs.

## Overview

This SDK provides a native Swift implementation of the zNinja Shielded Pool protocol, optimized for iOS with:

- **Native ZK proving** via rapidsnark (10-50x faster than JavaScript)
- **Pure Swift Poseidon hash** using BN254 field arithmetic
- **Solana integration** via SolanaSwift
- **Offline-capable** with bundled circuit artifacts
- **Epoch-based architecture** with automatic note renewal

## Requirements

- iOS 15.0+ / macOS 12.0+
- Swift 6.0+
- Xcode 26.0+

## Installation

### Swift Package Manager

Add the following to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/zNinjaPro/swift-sdk.git", from: "0.1.0")
]
```

Or in Xcode: File → Add Package Dependencies → Enter repository URL.

### Modules

| Module | Description | Dependencies |
|--------|-------------|--------------|
| `ShieldedPoolCore` | Crypto primitives, types, prover, scanner | BigInt, rapidsnark (iOS), witnesscalc (iOS) |
| `ShieldedPoolSDK` | Full Solana client | ShieldedPoolCore, SolanaSwift |

Use `ShieldedPoolCore` alone if you only need crypto operations (Poseidon, Merkle, key derivation) without Solana RPC.

## Quick Start

```swift
import ShieldedPoolSDK

// Configure for devnet
let config = ShieldedPoolConfig.devnet(
    programId: "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS",
    poolConfig: "<pool-config-address>",
    tokenMint: "8AnBxM3s9VUSvGtUigaP5WhLBuGtW4wnKw6wMzjREi4k",
    zkeyBasePath: Bundle.main.resourcePath!
)

// Create client from mnemonic
let client = try ShieldedPoolClient(
    config: config,
    mnemonic: "your twelve word mnemonic phrase here ..."
)

// Check balance
let balance = client.getBalance()
print("Spendable: \(balance.spendable) lamports")
print("Pending: \(balance.pending) lamports")
print("Expiring: \(balance.expiring) lamports")

// Prepare a deposit
let deposit = try client.prepareDeposit(amount: 1_000_000)

// Prepare a withdrawal
let withdraw = try await client.prepareWithdraw(
    amount: 500_000,
    recipient: "RecipientPublicKeyBase58..."
)

// Shielded transfer to another user
let transfer = try await client.prepareTransfer(
    amount: 250_000,
    recipient: "RecipientShieldedAddressBase58..."
)
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              ShieldedPoolClient                      │
│  (config, deposit, withdraw, transfer, renew, sync) │
├──────────────┬──────────────┬───────────────────────┤
│ KeyManager   │ NoteManager  │ TxBuilder             │
│ (BIP39, HD)  │ (UTXO state) │ (proof + tx assembly) │
├──────────────┴──────────────┴───────────────────────┤
│   ZKProver / NativeProver                           │
│   (rapidsnark + witnesscalc, WASM fallback)         │
├─────────────────────┬───────────────────────────────┤
│ Poseidon (BN254)    │ EpochMerkleTree (depth=12)    │
├─────────────────────┴───────────────────────────────┤
│   SolanaSwift (RPC, signing, transactions)          │
└─────────────────────────────────────────────────────┘
```

## Module Reference

### ShieldedPoolCore

#### Poseidon Hash

BN254-field Poseidon hash, compatible with Solana's `light_poseidon` and the zNinja TS SDK.

```swift
import ShieldedPoolCore

// Hash 1-3 inputs (each 32 bytes), returns 32 bytes
let hash = try Poseidon.hash([input1, input2])

// Convenience for Merkle node hashing
let node = try Poseidon.hash2(left, right)

// Get result as a field element (BigUInt)
let field = try Poseidon.hashToField([input1])
```

**Supported widths:** 2 (1 input), 3 (2 inputs), 4 (3 inputs).
Parameters are loaded from bundled `solana_poseidon_params.json`.

#### Key Management

```swift
// From BIP39 mnemonic
let keyManager = try KeyManager.fromMnemonic("word1 word2 ... word12")

// From raw seed bytes
let keyManager = KeyManager.fromSeed(seedData)

// Export keys
let keys: SpendingKeys = keyManager.exportKeys()
// keys.spendingKey  — signs transactions
// keys.viewingKey   — decrypts notes (read-only access)
// keys.nullifierKey — generates nullifiers (spend detection)
// keys.shieldedAddress — public receiving address

// Get shielded address for receiving
let address: Data = keyManager.shieldedAddress
```

#### Note Management

```swift
let noteManager = NoteManager(spendingKeys: keys)

// Add notes (usually via scanner)
noteManager.addNote(note)

// Select notes for a spend
let selected = try noteManager.selectNotes(amount: 1_000_000)

// Get balance breakdown
let balance: BalanceInfo = noteManager.calculateBalanceInfo()
// .total     — all unspent (excludes expired)
// .spendable — in finalized epochs
// .pending   — in active epoch (awaiting finalization)
// .expiring  — approaching epoch expiry
// .expired   — in expired epochs (needs renewal)

// Track epoch state
noteManager.setCurrentEpoch(epoch)
```

#### Merkle Tree

```swift
let tree = EpochMerkleTree(epoch: 0)

// Insert a commitment
try tree.insert(commitmentData)

// Generate inclusion proof
let proof: MerkleProof = try tree.generateProof(leafIndex: 0)
// proof.siblings — sibling hashes (12 levels)
// proof.root     — computed root
// proof.epoch    — epoch number
```

Depth is fixed at 12 (4,096 deposits per epoch).

#### ZK Proving

Two prover implementations:

```swift
// Standard prover (requires circuit artifacts)
let config = ProverConfig(
    zkeyPath: "/path/to/withdraw_final.zkey",
    witnesscalcPath: "/path/to/withdraw.wcd",
    circuitType: .withdraw
)
let prover = ZKProver(config: config)
let output = try await prover.proveWithdraw(inputs)

// Native prover with WASM fallback (iOS)
let nativeProver = NativeProver(circuitType: .withdraw)
nativeProver.isNativeAvailable  // true if rapidsnark + artifacts present
nativeProver.isWASMAvailable    // true if WASM fallback available
let output = try await nativeProver.proveWithdraw(inputs)
```

**Circuit types:** `.withdraw`, `.transfer`, `.joinsplit`

> ⚠️ Native proving (rapidsnark/witnesscalc) is iOS-only.
> On macOS, proof generation requires circuit artifacts but uses a placeholder verifier for testing.

#### Event Scanner

```swift
let scanner = UTXOScanner(
    viewingKey: keyManager.viewingKey,
    tokenMint: tokenMintData,
    poolId: poolConfigData,
    noteManager: noteManager
)

// Set delegate for event callbacks
scanner.delegate = self

// Process Solana transaction logs
scanner.processTransactionLogs(logStrings)

// Or process raw event data directly
scanner.processEventData(eventData)
```

Supported events (V2 epoch-aware):
- `DepositV2` — new shielded deposit
- `WithdrawV2` — withdrawal from pool
- `TransferV2` — shielded transfer
- `RenewV2` — note renewal across epochs
- `EpochRollover` — new epoch started
- `EpochFinalized` — epoch Merkle root committed

Legacy V1 events are also supported for historical data.

#### Circuit Artifact Manager

```swift
let manager = CircuitArtifactManager.shared

// Configure for remote downloads
manager.configure(
    baseURL: URL(string: "https://artifacts.zninja.io/v1/")!,
    appGroupIdentifier: "group.com.zninja.pool"  // optional, for app extensions
)

// Check availability
manager.isCircuitReady(.withdraw)  // true if zkey + wcd present

// Download on demand
try await manager.downloadCircuit(.withdraw)

// Or copy from app bundle
try manager.copyBundledArtifacts()

// Storage management
let size = manager.totalDownloadedSize()  // bytes
try manager.clearCircuit(.withdraw)
try manager.clearCache()  // delete all
```

#### Crypto Utilities

```swift
// Compute commitment: H(value, token, owner, randomness)
let commitment = try Crypto.computeCommitment(
    value: amount, token: tokenMint, owner: address, randomness: blinding
)

// Compute nullifier: H(commitment, nullifierKey, epoch, leafIndex)
let nullifier = try Crypto.computeNullifier(
    commitment: commitment, nullifierKey: nfKey, epoch: epoch, leafIndex: idx
)

// Note encryption/decryption (AES-256-GCM)
let encrypted = try Crypto.encryptNote(note: note, viewingKey: viewKey)
let decrypted = NoteManager.decryptNote(
    encryptedData: encrypted, viewingKey: viewKey, token: mint,
    leafIndex: idx, epoch: epoch
)
```

### ShieldedPoolSDK

#### Client Configuration

```swift
// Manual configuration
let config = ShieldedPoolConfig(
    rpcURL: "https://api.devnet.solana.com",
    wsURL: "wss://api.devnet.solana.com",
    programId: "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS",
    poolConfig: "<pool-config-pubkey>",
    tokenMint: "8AnBxM3s9VUSvGtUigaP5WhLBuGtW4wnKw6wMzjREi4k",
    withdrawZkeyPath: "/path/to/withdraw.zkey",
    transferZkeyPath: "/path/to/transfer.zkey",
    cluster: .devnet
)

// Convenience constructors
let devnet = ShieldedPoolConfig.devnet(
    programId: "...", poolConfig: "...",
    tokenMint: "...", zkeyBasePath: "/path/to/keys"
)
let localnet = ShieldedPoolConfig.localnet(
    programId: "...", poolConfig: "...",
    tokenMint: "...", zkeyBasePath: "/path/to/keys"
)
```

#### Full Client API

```swift
let client = try ShieldedPoolClient(config: config, mnemonic: mnemonic)

// — Identity —
client.getShieldedAddress()   // Base58 shielded address
client.getViewingKey()        // For read-only wallets
client.getSpendingKeys()      // Full key export

// — Balance —
client.getBalance()           // BalanceInfo
client.getNotes()             // All unspent notes
client.getExpiringNotes()     // Notes needing renewal

// — Epoch —
try await client.syncEpoch()  // Sync with on-chain state
client.getCurrentEpoch()      // Current epoch number

// — Deposit —
let dep = try client.prepareDeposit(amount: 1_000_000)
let depTo = try client.prepareDepositTo(amount: 1_000_000, recipient: "Base58...")

// — Withdraw —
let wd = try await client.prepareWithdraw(amount: 500_000, recipient: "PublicKey...")

// — Transfer —
let tx = try await client.prepareTransfer(amount: 250_000, recipient: "ShieldedAddr...")

// — Renew —
let renewals = try await client.prepareRenewals()  // All expiring notes

// — Event Processing —
client.processTransactionLogs(logs)
client.processEventData(data)

// — State —
client.clearState()  // Reset all cached state
```

## Circuit Artifacts

The SDK requires circuit artifacts for ZK proof generation. These are **not** included in the Swift package due to size (~100MB total).

### Required Files

| File | Size (approx) | Purpose |
|------|---------------|---------|
| `withdraw_final.zkey` | ~25MB | Withdraw proving key |
| `transfer_final.zkey` | ~45MB | Transfer proving key |
| `withdraw.wcd` | ~5MB | Withdraw witness graph (iOS native) |
| `transfer.wcd` | ~5MB | Transfer witness graph (iOS native) |

### Delivery Options

1. **Bundle with app** — add to Xcode project as resources (~100MB added to app size)
2. **Download on demand** — use `CircuitArtifactManager` for lazy download
3. **App Group sharing** — share artifacts across app + extensions

### Generating Artifacts

From the `circuits/` directory:

```bash
# Compile circuits
circom withdraw.circom --r1cs --wasm --sym

# Trusted setup (Phase 2)
snarkjs groth16 setup withdraw.r1cs pot_final.ptau withdraw_0000.zkey
snarkjs zkey contribute withdraw_0000.zkey withdraw_final.zkey

# Generate witness graph for iOS native proving
circom-witnesscalc withdraw.circom -o withdraw.wcd

# Export verification key
snarkjs zkey export verificationkey withdraw_final.zkey withdraw_vk.json
```

## Epoch Model

The shielded pool uses an **epoch-based** design for scalability:

- **Active epoch** — accepting deposits (current)
- **Frozen epoch** — no more deposits, awaiting finalization
- **Finalized epoch** — Merkle root committed, notes are spendable
- **Expired epoch** — past expiry slot, notes must be renewed

```
Epoch 0          Epoch 1          Epoch 2
[deposits...]    [deposits...]    [deposits...]
     ↓                ↓                ↓
  finalized       finalized         active
     ↓
  expiring → renew to Epoch 2
```

**Default timing (configurable):**
- Epoch duration: ~2 weeks (3,024,000 slots)
- Finalization delay: ~1 day (216,000 slots)
- Expiry grace: ~6 months (38,880,000 slots)

Notes in expiring epochs should be renewed using `prepareRenewals()`.

## Types Reference

### Core Types

| Type | Description |
|------|-------------|
| `Note` | UTXO in the pool (value, owner, commitment, nullifier, epoch, etc.) |
| `SpendingKeys` | Master seed + spending/viewing/nullifier keys + shielded address |
| `MerkleProof` | Inclusion proof (leaf, index, siblings, root, epoch) |
| `BalanceInfo` | Balance breakdown (total, spendable, pending, expiring, expired) |
| `Groth16Proof` | ZK proof (pi_a, pi_b, pi_c as Data) |
| `ProverOutput` | Proof + public inputs |
| `EpochState` | `.active`, `.frozen`, `.finalized` |
| `EpochInfo` | Full epoch metadata |

### Transaction Types

| Type | Description |
|------|-------------|
| `PreparedDeposit` | Ready-to-sign deposit (commitment, encrypted note, instruction data) |
| `PreparedWithdraw` | Ready-to-sign withdrawal (proof, nullifiers, instruction data) |
| `PreparedTransfer` | Ready-to-sign transfer (proof, nullifiers, output commitments) |
| `PreparedRenew` | Ready-to-sign renewal (old nullifier, new commitment, proof) |

### Error Types

| Error | Description |
|-------|-------------|
| `ShieldedPoolError` | SDK-level errors (invalid address, insufficient balance, etc.) |
| `ProverError` | Proof generation errors (framework not integrated, witness failed) |
| `ArtifactError` | Circuit artifact errors (not configured, download failed) |
| `ScannerError` | Event scanning errors (invalid data, decryption failed) |
| `Poseidon.PoseidonError` | Hash errors (invalid input count, missing params) |

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| [BigInt](https://github.com/attaswift/BigInt) | 5.4+ | BN254 field arithmetic for Poseidon |
| [SolanaSwift](https://github.com/p2p-org/solana-swift) | 5.0+ | Solana RPC, transactions, key management |
| [ios-rapidsnark](https://github.com/iden3/ios-rapidsnark) | 0.0.1-beta.4 | Native Groth16 prover (iOS only) |
| [circom-witnesscalc-swift](https://github.com/iden3/circom-witnesscalc-swift) | 0.0.1-alpha.3 | Native witness generation (iOS only) |

> ⚠️ rapidsnark and circom-witnesscalc are pre-release. They compile conditionally on iOS only.

## Testing

```bash
# Run all tests (requires Xcode)
swift test

# Run specific test suite
swift test --filter PoseidonTests
```

### Test Coverage

**156 tests passing** across 11 test files (zero warnings, zero failures):

| Suite | Tests | Coverage |
|-------|-------|----------|
| PoseidonTests | 12 | Hash widths 2-5, edge cases, field overflow |
| CrossValidationTests | 14 | All crypto cross-validated vs TS SDK |
| CryptoTests | 18 | Commitment, nullifier, serialization, encryption |
| KeyManagerTests | 7 | Key derivation, Base58, export |
| NoteManagerTests | 24 | Note lifecycle, balance, selection, epoch expiry |
| EventParserTests | 16 | All V2 event types, discriminators |
| ProverTests | 12 | Config, proof parsing, input types |
| IntegrationTests | 18 | Full lifecycle, event scanner, cross-epoch flows |
| BorshSerializeTests | 15 | Borsh encoding (u8/u32/u64, bytes, Vec, strings) |
| InstructionTests | 12 | Discriminators, data layouts, account counts |
| PDATests | 11 | PDA derivation, determinism, uniqueness |

All Poseidon, commitment, nullifier, and Merkle tree outputs are cross-validated against the TypeScript SDK.

## Development Status

### Completed
- ✅ Build verification (Swift 6.0, Xcode 26.2, zero warnings)
- ✅ Poseidon hash (BN254, widths 2-5) with cross-validated test vectors
- ✅ Merkle tree (epoch-based, depth 12)
- ✅ Key derivation (BIP39 mnemonic + raw seed, cross-validated vs TS SDK)
- ✅ Note management (UTXO tracking, selection, balance)
- ✅ Note encryption/decryption (ChaChaPoly)
- ✅ ZK prover interface (rapidsnark + WASM fallback)
- ✅ Transaction builder (deposit, withdraw, transfer, renew)
- ✅ Event scanner (V1 + V2 events, note decryption)
- ✅ Circuit artifact manager (download, cache, bundle)
- ✅ Full SDK client (ShieldedPoolClient)
- ✅ Circuit artifact pipeline (all 3 circuits compiled + proof-verified)
- ✅ Anchor instruction serializer (Borsh encoding, all 8 instructions)
- ✅ PDA derivation (all program accounts via SolanaSwift)
- ✅ Transaction submission client (`ShieldedPoolTransactor`)
- ✅ Comprehensive test suite (156 tests — unit, cross-validation, integration, serialization)

### TODO
- [ ] Live on-chain test against solana-test-validator
- [ ] iOS device testing + native ZK proving performance
- [ ] State persistence (save/restore NoteManager)
- [ ] Keychain integration for secure key storage
- [ ] WebSocket subscription for real-time scanning

## License

MIT License — see [LICENSE](LICENSE) for details.

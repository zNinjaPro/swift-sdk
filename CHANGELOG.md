# Changelog

All notable changes to the Shielded Pool Swift SDK will be documented in this file.

## [Unreleased]

### Added
- Initial SDK implementation
- `ShieldedPoolCore` module: Poseidon hash, Merkle tree, key management, note management, ZK prover, event scanner, circuit artifact manager
- `ShieldedPoolSDK` module: Full Solana client with deposit/withdraw/transfer/renew
- Poseidon hash implementation (BN254) with 12 cross-validated test vectors from the TypeScript SDK
- Native ZK proving via rapidsnark + circom-witnesscalc (iOS only)
- WASM fallback prover via JavaScriptCore
- Epoch-based UTXO architecture with note renewal
- V1 and V2 event parsing for backwards compatibility
- Circuit artifact manager with on-demand download support
- `CircuitType.renew` and `CircuitArtifact.renew` for renewal proof support
- Bundled circuit artifacts for testing: withdraw, transfer, renew (zkey, wasm, wcd, verification key, test inputs)

### Fixed
- **Critical: Poseidon width-5 support** — nullifier computation requires `Poseidon(commitment, nullifierKey, epoch, leafIndex)` (4 inputs = width 5). Constants were missing for width 5 across all codebases (circuits, TS SDK, Swift SDK). Generated correct constants from `light-poseidon` Rust crate.
- Poseidon input limit bumped from 3 to 4 (width 2-5)
- Unused variable warnings in V1 legacy event handlers (Scanner.swift)
- Updated `testInvalidInputCount` to reflect new 4-input max

### Circuit Artifacts
- All 3 circuits compiled: withdraw (3,508 constraints), transfer (7,539), renew (3,772)
- Groth16 trusted setup with snarkjs v0.7.5 (development ceremony)
- `.wcd` witness graph files generated via circom-witnesscalc build-circuit v0.1.1
- End-to-end proof generation & verification verified for all circuits

### Testing (Phase 3)
- **100/100 tests passing** across 7 test files (zero warnings, zero failures)
- `PoseidonTests` (12): Hash widths 2-5, edge cases, field overflow, invalid inputs
- `CrossValidationTests` (14): All crypto outputs cross-validated against TS SDK — Poseidon, commitment, nullifier, zero hash chain, Merkle roots, proof verification
- `CryptoTests` (18): Commitment/nullifier computation, note serialization roundtrip, encryption/decryption, BigInt conversion, field validation
- `KeyManagerTests` (7): Key derivation cross-validated vs TS SDK, export, Base58 roundtrip
- `NoteManagerTests` (24): Note lifecycle, deduplication, spending, balance calculation, epoch expiry, note selection, encrypt/decrypt roundtrip
- `EventParserTests` (16): Binary parsing for all V2 event types (deposit, withdraw, transfer, renew, epoch rollover, epoch finalized), discriminator uniqueness, edge cases
- `ProverTests` (12): Prover config, circuit types, proof/signal JSON parsing, framework-not-integrated errors, input type construction
- **Bugs fixed**: Stale Merkle zero hashes replaced with TS SDK cross-validated values
- **Known issue**: `Base58.decode("")` returns 32 zero bytes instead of nil (minor)

### Integration Testing (Phase 4)
- **118/118 tests passing** (added 18 integration tests, zero failures)
- `IntegrationTests` (18): Full lifecycle flows, event scanner pipeline, cross-epoch management
  - Deposit preparation + encrypt/decrypt roundtrip
  - Full deposit → Merkle insert → nullifier → spend lifecycle
  - Multi-deposit with note selection
  - Event scanner: deposit event processing, withdraw event (nullifier marking), epoch rollover
  - Cross-epoch note management and renewal selection
  - Value conservation validation
  - Merkle root history across sequential deposits
  - Epoch tree finalization and state transitions
  - Balance info lifecycle (spendable, pending, spent)
  - PDA seed and Merkle config constants verification
  - Prepared transaction data format validation (field membership)
  - Concurrent deposits to same tree (10 leaves, all proofs verify)
- **Note:** On-chain transaction submission requires either:
  - Anchor instruction serialization in Swift (not yet implemented), or
  - TS SDK bridge for submitting mock-proof transactions
  - The ZK prover (rapidsnark/witnesscalc) is iOS-only; macOS uses mock paths

### SDK Completion: Anchor Instruction Serializer + PDA Derivation
- **`BorshSerialize.swift`** — full Borsh binary encoder (u8/u32/u64, fixed bytes, Vec, Option, strings)
- **`ShieldedPoolInstructions.swift`** — builds raw `TransactionInstruction` objects for all 8 on-chain instructions:
  - `initializePoolV2`, `initializeEpochLeafChunk`, `depositV2`, `withdrawV2`, `transferV2`, `renewNote`, `rolloverEpoch`, `finalizeEpoch`
  - Pre-computed Anchor discriminators (SHA256 of "global:<name>")
  - Borsh-serialized public input structs (`WithdrawPublicInputs`, `TransferPublicInputs`, `RenewPublicInputs`)
  - Account structs with proper signer/writable flags matching IDL
  - `mockProofBytes()` helper for testing with mock-verifier programs
- **`ShieldedPoolPDAs.swift`** — PDA derivation for all program accounts:
  - `poolConfig`, `epochTree`, `leafChunk`, `vaultAuthority`, `vault`, `nullifierMarker`, `verifierConfig`
  - Uses SolanaSwift's `PublicKey.findProgramAddress` with correct seed layouts
- **`ShieldedPoolTransactor.swift`** — high-level transaction submission client
  - `deposit(amount:depositorTokenAccount:)` → builds + signs + submits deposit tx
  - `withdrawWithMockProof(amount:recipientTokenAccount:recipient:)` → full withdraw with mock proofs
  - `transferWithMockProof(amount:recipientShieldedAddress:)` → shielded transfer with mock proofs
  - `initializePool()` / `initializeLeafChunk()` — for localnet/devnet setup
  - Automatic PDA derivation, note state tracking, event processing
  - Uses SolanaSwift's `BlockchainClient` for signing + RPC submission
- **156/156 tests passing** (38 new tests for serialization, instructions, PDAs)

### Development
- Verified build on Swift 6.0 / Xcode 26.2 (zero warnings)
- Tools: circom v2.2.3, snarkjs v0.7.5, build-circuit v0.1.1

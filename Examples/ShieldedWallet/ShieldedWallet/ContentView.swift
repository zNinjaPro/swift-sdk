import SwiftUI
import ShieldedPoolCore

struct ContentView: View {
    @EnvironmentObject var walletManager: WalletManager
    
    var body: some View {
        NavigationStack {
            if walletManager.isInitialized {
                WalletView()
            } else {
                OnboardingView()
            }
        }
    }
}

// MARK: - Onboarding View

struct OnboardingView: View {
    @EnvironmentObject var walletManager: WalletManager
    @State private var mnemonic = ""
    @State private var showImport = false
    @State private var showMnemonic: String?
    
    var body: some View {
        VStack(spacing: 32) {
            Spacer()
            
            // Logo/Title
            VStack(spacing: 16) {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 80))
                    .foregroundStyle(.blue.gradient)
                
                Text("Shielded Wallet")
                    .font(.largeTitle.bold())
                
                Text("Private transactions on Solana")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            // Circuit Status
            CircuitStatusView()
                .padding(.horizontal)
            
            // Actions
            VStack(spacing: 16) {
                Button {
                    Task {
                        do {
                            let mnemonic = try await walletManager.createWallet()
                            showMnemonic = mnemonic
                        } catch {
                            // Error handled by wallet manager
                        }
                    }
                } label: {
                    Text("Create New Wallet")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
                
                Button {
                    showImport = true
                } label: {
                    Text("Import Existing Wallet")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(.secondary.opacity(0.2))
                        .foregroundColor(.primary)
                        .cornerRadius(12)
                }
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 32)
        }
        .sheet(isPresented: $showImport) {
            ImportWalletSheet(mnemonic: $mnemonic)
        }
        .sheet(item: $showMnemonic) { mnemonic in
            MnemonicBackupSheet(mnemonic: mnemonic)
        }
        .overlay {
            if walletManager.isLoading {
                LoadingOverlay()
            }
        }
    }
}

extension String: Identifiable {
    public var id: String { self }
}

// MARK: - Circuit Status View

struct CircuitStatusView: View {
    @EnvironmentObject var walletManager: WalletManager
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Required Circuits")
                .font(.headline)
            
            ForEach([CircuitArtifact.withdraw, .transfer], id: \.rawValue) { circuit in
                HStack {
                    Text(circuit.rawValue.capitalized)
                    
                    Spacer()
                    
                    switch walletManager.circuitStatus[circuit] {
                    case .ready:
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                    case .downloading:
                        ProgressView()
                            .scaleEffect(0.8)
                    case .notDownloaded, .none:
                        Button("Download") {
                            Task {
                                try? await walletManager.downloadCircuit(circuit)
                            }
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .padding()
        .background(.ultraThinMaterial)
        .cornerRadius(12)
    }
}

// MARK: - Wallet View

struct WalletView: View {
    @EnvironmentObject var walletManager: WalletManager
    @State private var showReceive = false
    @State private var showSend = false
    @State private var showWithdraw = false
    
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Balance Card
                BalanceCard()
                
                // Action Buttons
                HStack(spacing: 16) {
                    ActionButton(title: "Receive", icon: "arrow.down.circle.fill", color: .green) {
                        showReceive = true
                    }
                    
                    ActionButton(title: "Send", icon: "arrow.up.circle.fill", color: .blue) {
                        showSend = true
                    }
                    
                    ActionButton(title: "Withdraw", icon: "banknote.fill", color: .orange) {
                        showWithdraw = true
                    }
                }
                .padding(.horizontal)
                
                // Notes List
                NotesListView()
            }
            .padding(.top)
        }
        .navigationTitle("Wallet")
        .refreshable {
            walletManager.refreshBalance()
        }
        .sheet(isPresented: $showReceive) {
            ReceiveSheet()
        }
        .sheet(isPresented: $showSend) {
            SendSheet()
        }
        .sheet(isPresented: $showWithdraw) {
            WithdrawSheet()
        }
    }
}

// MARK: - Balance Card

struct BalanceCard: View {
    @EnvironmentObject var walletManager: WalletManager
    
    var body: some View {
        VStack(spacing: 16) {
            Text("Shielded Balance")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            
            if let balance = walletManager.balance {
                Text(formatLamports(balance.spendable))
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                
                HStack(spacing: 24) {
                    BalanceItem(title: "Pending", value: balance.pending, color: .yellow)
                    BalanceItem(title: "Expiring", value: balance.expiring, color: .orange)
                }
            } else {
                Text("--")
                    .font(.system(size: 40, weight: .bold, design: .rounded))
            }
        }
        .frame(maxWidth: .infinity)
        .padding(24)
        .background(
            LinearGradient(
                colors: [.blue.opacity(0.1), .purple.opacity(0.1)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
        .cornerRadius(20)
        .padding(.horizontal)
    }
    
    private func formatLamports(_ lamports: UInt64) -> String {
        let sol = Double(lamports) / 1_000_000_000
        return String(format: "%.4f SOL", sol)
    }
}

struct BalanceItem: View {
    let title: String
    let value: UInt64
    let color: Color
    
    var body: some View {
        VStack(spacing: 4) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(formatLamports(value))
                .font(.subheadline.bold())
                .foregroundColor(color)
        }
    }
    
    private func formatLamports(_ lamports: UInt64) -> String {
        let sol = Double(lamports) / 1_000_000_000
        return String(format: "%.4f", sol)
    }
}

// MARK: - Action Button

struct ActionButton: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title)
                    .foregroundColor(color)
                Text(title)
                    .font(.caption.bold())
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(.ultraThinMaterial)
            .cornerRadius(12)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Notes List

struct NotesListView: View {
    @EnvironmentObject var walletManager: WalletManager
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Shielded Notes")
                .font(.headline)
                .padding(.horizontal)
            
            if walletManager.notes.isEmpty {
                Text("No notes yet. Deposit funds to get started.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .padding()
            } else {
                ForEach(walletManager.notes, id: \.commitment) { note in
                    NoteRow(note: note)
                }
            }
        }
    }
}

struct NoteRow: View {
    let note: Note
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(formatLamports(note.value))
                    .font(.headline)
                Text("Epoch \(note.epoch ?? 0)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            if note.expired {
                Text("Expired")
                    .font(.caption.bold())
                    .foregroundColor(.red)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(.red.opacity(0.1))
                    .cornerRadius(4)
            }
        }
        .padding()
        .background(.ultraThinMaterial)
        .cornerRadius(12)
        .padding(.horizontal)
    }
    
    private func formatLamports(_ lamports: UInt64) -> String {
        let sol = Double(lamports) / 1_000_000_000
        return String(format: "%.4f SOL", sol)
    }
}

// MARK: - Sheet Views (Stubs)

struct ImportWalletSheet: View {
    @Binding var mnemonic: String
    @Environment(\.dismiss) var dismiss
    @EnvironmentObject var walletManager: WalletManager
    
    var body: some View {
        NavigationStack {
            Form {
                Section("Recovery Phrase") {
                    TextEditor(text: $mnemonic)
                        .frame(height: 100)
                }
            }
            .navigationTitle("Import Wallet")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Import") {
                        Task {
                            try? await walletManager.importWallet(mnemonic: mnemonic)
                            dismiss()
                        }
                    }
                    .disabled(mnemonic.isEmpty)
                }
            }
        }
    }
}

struct MnemonicBackupSheet: View {
    let mnemonic: String
    @Environment(\.dismiss) var dismiss
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.largeTitle)
                    .foregroundColor(.yellow)
                
                Text("Back up your recovery phrase")
                    .font(.headline)
                
                Text("Write down these words in order and store them securely. Anyone with this phrase can access your funds.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                
                Text(mnemonic)
                    .font(.system(.body, design: .monospaced))
                    .padding()
                    .background(.secondary.opacity(0.1))
                    .cornerRadius(12)
                
                Spacer()
                
                Button("I've backed it up") {
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()
            .navigationTitle("Recovery Phrase")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

struct ReceiveSheet: View {
    @EnvironmentObject var walletManager: WalletManager
    @Environment(\.dismiss) var dismiss
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Text("Your Shielded Address")
                    .font(.headline)
                
                // QR Code placeholder
                RoundedRectangle(cornerRadius: 12)
                    .fill(.secondary.opacity(0.1))
                    .frame(width: 200, height: 200)
                    .overlay {
                        Image(systemName: "qrcode")
                            .font(.system(size: 60))
                            .foregroundStyle(.secondary)
                    }
                
                Text(walletManager.shieldedAddress)
                    .font(.system(.caption, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .padding()
                    .background(.secondary.opacity(0.1))
                    .cornerRadius(8)
                
                Button {
                    UIPasteboard.general.string = walletManager.shieldedAddress
                } label: {
                    Label("Copy Address", systemImage: "doc.on.doc")
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()
            .navigationTitle("Receive")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

struct SendSheet: View {
    @State private var recipient = ""
    @State private var amount = ""
    @Environment(\.dismiss) var dismiss
    @EnvironmentObject var walletManager: WalletManager
    
    var body: some View {
        NavigationStack {
            Form {
                Section("Recipient") {
                    TextField("Shielded Address", text: $recipient)
                        .font(.system(.body, design: .monospaced))
                }
                
                Section("Amount") {
                    TextField("0.0", text: $amount)
                        .keyboardType(.decimalPad)
                }
            }
            .navigationTitle("Shielded Send")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Send") {
                        // TODO: Implement send
                    }
                    .disabled(recipient.isEmpty || amount.isEmpty)
                }
            }
        }
    }
}

struct WithdrawSheet: View {
    @State private var recipient = ""
    @State private var amount = ""
    @Environment(\.dismiss) var dismiss
    
    var body: some View {
        NavigationStack {
            Form {
                Section("Solana Address") {
                    TextField("Public Key", text: $recipient)
                        .font(.system(.body, design: .monospaced))
                }
                
                Section("Amount") {
                    TextField("0.0", text: $amount)
                        .keyboardType(.decimalPad)
                }
            }
            .navigationTitle("Withdraw")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Withdraw") {
                        // TODO: Implement withdraw
                    }
                    .disabled(recipient.isEmpty || amount.isEmpty)
                }
            }
        }
    }
}

// MARK: - Loading Overlay

struct LoadingOverlay: View {
    var body: some View {
        ZStack {
            Color.black.opacity(0.3)
                .ignoresSafeArea()
            
            VStack(spacing: 16) {
                ProgressView()
                    .scaleEffect(1.5)
                Text("Generating proof...")
                    .font(.subheadline)
            }
            .padding(32)
            .background(.ultraThickMaterial)
            .cornerRadius(16)
        }
    }
}

#Preview {
    ContentView()
        .environmentObject(WalletManager())
}

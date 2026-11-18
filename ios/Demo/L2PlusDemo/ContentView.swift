import SwiftUI
import Security
import L2PlusSDK

/// Minimal integration example. In a real wallet the challenge comes from the PID Provider
/// and the JSON is sent back inside the `mrtd_validation_jwt`.
struct ContentView: View {
    private enum AccessType: String, CaseIterable, Identifiable {
        case can = "CAN"
        case mrz = "MRZ data"
        var id: String { rawValue }
    }

    @State private var accessType = AccessType.can
    @State private var can = ""
    @State private var documentNumber = ""
    @State private var birthDate = ""
    @State private var expiryDate = ""
    @State private var challenge = ContentView.randomChallenge()
    @State private var status = "Enter the access data and tap Read CIE."
    @State private var json: String?
    @State private var running = false

    @State private var sdk = L2PlusSdk(trust: L2PlusTrustConfig(mrtdTrustAnchors: L2PlusTrustConfig.bundledCscaCertificates()))

    var body: some View {
        NavigationView {
            Form {
                Section("Access") {
                    Picker("Access", selection: $accessType) {
                        ForEach(AccessType.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    if accessType == .can {
                        SecureField("CAN (6 digits)", text: $can)
                            .keyboardType(.numberPad)
                    } else {
                        TextField("Document number", text: $documentNumber)
                            .textInputAutocapitalization(.characters)
                            .disableAutocorrection(true)
                        TextField("Birth date (YYYY-MM-DD)", text: $birthDate)
                            .keyboardType(.numbersAndPunctuation)
                        TextField("Expiry date (YYYY-MM-DD)", text: $expiryDate)
                            .keyboardType(.numbersAndPunctuation)
                    }
                }

                Section {
                    Text(hex(challenge))
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                    Button("New challenge") { challenge = ContentView.randomChallenge() }
                } header: {
                    Text("Challenge")
                } footer: {
                    Text("Random here; provided by the backend in a real flow.")
                }

                Section {
                    Button("Read CIE", action: read).disabled(running)
                    if running {
                        Button("Cancel", role: .destructive) { sdk.cancel() }
                    }
                    Text(status).foregroundColor(.secondary)
                }

                if let json = json {
                    Section("Result") {
                        Text(json)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                        Button("Copy JSON") { UIPasteboard.general.string = json }
                    }
                }
            }
            .navigationTitle("L2+ Demo")
        }
        .navigationViewStyle(.stack)
    }

    private func read() {
        let access: L2PlusAccess = accessType == .can
            ? .can(can)
            : .mrz(documentNumber: documentNumber, birthDate: birthDate, expiryDate: expiryDate)
        running = true
        json = nil
        sdk.start(access: access, challenge: challenge, onStep: { status = describe($0) }) { result in
            running = false
            switch result {
            case .success(let r):
                status = "Read completed"
                json = r.toJson()
            case .failure(let e):
                status = "\(e.code.rawValue) (\(e.action.rawValue))\n\(e.message)"
            }
        }
    }

    private func describe(_ step: L2PlusStep) -> String {
        switch step {
        case .waitingForCard: return "Hold the CIE near the top of the phone"
        case .cardDetected, .pace: return "Card detected, keep it still"
        case .readingMrtd: return "Reading document data"
        case .readingIas, .signingChallenge: return "Checking the card"
        case .verifying: return "Verifying signatures"
        }
    }

    private func hex(_ data: Data) -> String { data.map { String(format: "%02X", $0) }.joined() }

    private static func randomChallenge() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }
}

import SwiftUI
import UIKit

@main
struct BridgeApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

struct ContentView: View {
    @StateObject private var vpn = VPNManager()

    @AppStorage("bridgeURL") private var url = ""
    @AppStorage("token") private var token = ""
    @AppStorage("relay") private var relay = false
    @AppStorage("coalesceMs") private var coalesceMs = 50

    @State private var pasteNote = ""

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Состояние")) {
                    HStack {
                        Circle().fill(color).frame(width: 12, height: 12)
                        Text(vpn.statusText)
                        Spacer()
                        Text(vpn.coreStatus).font(.caption).foregroundColor(.secondary)
                    }
                    Button(action: toggle) {
                        Text(vpn.isOn ? "Отключить" : "Подключить")
                            .frame(maxWidth: .infinity)
                    }
                    .disabled(url.isEmpty || token.isEmpty)
                    if !vpn.error.isEmpty {
                        Text(vpn.error).font(.caption).foregroundColor(.red)
                    }
                }

                Section(header: Text("Настройки")) {
                    TextField("Bridge URL (wss://…/helper)", text: $url)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                        .keyboardType(.URL)
                    SecureField("Auth token", text: $token)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                    Toggle("Relay (через облачную функцию)", isOn: $relay)
                    Stepper("Коалесинг: \(coalesceMs) мс", value: $coalesceMs, in: 0...200, step: 10)
                    Button("Вставить конфиг из буфера") { pasteConfig() }
                    if !pasteNote.isEmpty {
                        Text(pasteNote).font(.caption).foregroundColor(.secondary)
                    }
                }

                if !vpn.logs.isEmpty {
                    Section(header: Text("Лог")) {
                        ScrollView {
                            Text(vpn.logs)
                                .font(.system(size: 10, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(height: 220)
                    }
                }
            }
            .navigationTitle("BTF VPN")
        }
        .navigationViewStyle(.stack)
    }

    private var color: Color {
        switch vpn.status {
        case .connected: return .green
        case .connecting, .reasserting: return .orange
        default: return .gray
        }
    }

    private func toggle() {
        if vpn.isOn {
            vpn.disconnect()
        } else {
            vpn.connect(url: url.trimmingCharacters(in: .whitespacesAndNewlines),
                        token: token.trimmingCharacters(in: .whitespacesAndNewlines),
                        relay: relay, coalesceMs: coalesceMs)
        }
    }

    /// Accepts either `btf://<base64 json {"url":…,"token":…}>` or a plain `wss://` URL.
    private func pasteConfig() {
        guard let s = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines),
              !s.isEmpty else {
            pasteNote = "буфер пуст"
            return
        }
        if s.hasPrefix("btf://") {
            let b64 = String(s.dropFirst("btf://".count))
            if let data = Data(base64Encoded: b64),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let u = obj["url"] as? String, let t = obj["token"] as? String {
                url = u
                token = t
                pasteNote = "конфиг применён"
                return
            }
            pasteNote = "не удалось разобрать btf://"
        } else if s.hasPrefix("wss://") || s.hasPrefix("ws://") {
            url = s
            pasteNote = "URL вставлен (токен введи вручную)"
        } else {
            pasteNote = "в буфере не конфиг"
        }
    }
}

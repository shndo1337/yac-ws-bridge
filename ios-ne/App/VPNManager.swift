import Foundation
import NetworkExtension
import Combine

/// Owns the NETunnelProviderManager and exposes state to the UI.
final class VPNManager: ObservableObject {
    @Published var status: NEVPNStatus = .invalid
    @Published var coreStatus: String = ""
    @Published var logs: String = ""
    @Published var error: String = ""

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var pollTimer: Timer?

    private let providerBundleId = "com.btf.native.tunnel"

    init() {
        load()
    }

    deinit {
        if let o = statusObserver { NotificationCenter.default.removeObserver(o) }
        pollTimer?.invalidate()
    }

    var statusText: String {
        switch status {
        case .invalid: return "не настроен"
        case .disconnected: return "отключён"
        case .connecting: return "подключение…"
        case .connected: return "подключён"
        case .reasserting: return "переподключение…"
        case .disconnecting: return "отключение…"
        @unknown default: return "?"
        }
    }

    var isOn: Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    private func load() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self = self else { return }
            DispatchQueue.main.async {
                if let error = error { self.error = error.localizedDescription }
                let m = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.providerBundleId
                })
                if let m = m { self.attach(m) }
            }
        }
    }

    private func attach(_ m: NETunnelProviderManager) {
        manager = m
        status = m.connection.status
        if let o = statusObserver { NotificationCenter.default.removeObserver(o) }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: m.connection, queue: .main
        ) { [weak self] _ in
            self?.status = m.connection.status
        }
        pollTimer?.invalidate()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.poll()
        }
    }

    private func poll() {
        guard let session = manager?.connection as? NETunnelProviderSession,
              session.status == .connected || session.status == .connecting || session.status == .reasserting
        else {
            if status == .disconnected { coreStatus = "" }
            return
        }
        try? session.sendProviderMessage(Data([0])) { [weak self] data in
            guard let data = data, let text = String(data: data, encoding: .utf8) else { return }
            let parts = text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
            DispatchQueue.main.async {
                self?.coreStatus = parts.first.map(String.init) ?? ""
                self?.logs = parts.count > 1 ? String(parts[1]) : ""
            }
        }
    }

    /// Saves the configuration into the system VPN preferences and starts the tunnel.
    func connect(url: String, token: String, relay: Bool, coalesceMs: Int) {
        error = ""
        let m = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleId
        proto.serverAddress = "Bridge to Freedom"
        proto.providerConfiguration = [
            "bridgeURL": url,
            "token": token,
            "relay": relay,
            "coalesceMs": coalesceMs,
        ]
        m.protocolConfiguration = proto
        m.localizedDescription = "Bridge to Freedom"
        m.isEnabled = true

        m.saveToPreferences { [weak self] err in
            guard let self = self else { return }
            if let err = err {
                DispatchQueue.main.async { self.error = "save: \(err.localizedDescription)" }
                return
            }
            // Reload after saving (required before the first start).
            m.loadFromPreferences { err in
                DispatchQueue.main.async {
                    if let err = err { self.error = "load: \(err.localizedDescription)"; return }
                    self.attach(m)
                    do {
                        try m.connection.startVPNTunnel()
                    } catch {
                        self.error = "start: \(error.localizedDescription)"
                    }
                }
            }
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }
}

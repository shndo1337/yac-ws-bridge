import Foundation
import NetworkExtension
import Btfcore

/// Writes packets produced by the Go netstack back to the tunnel interface.
final class PacketOut: NSObject, BtfcorePacketWriterProtocol {
    private let flow: NEPacketTunnelFlow

    init(flow: NEPacketTunnelFlow) {
        self.flow = flow
    }

    func writePacket(_ b: Data?) {
        guard let b = b, !b.isEmpty else { return }
        let family: Int32 = (b[b.startIndex] >> 4) == 6 ? AF_INET6 : AF_INET
        flow.writePackets([b], withProtocols: [NSNumber(value: family)])
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var core: BtfcoreCore?
    private var out: PacketOut?
    private let mtu = 1400

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let cfg = proto.providerConfiguration,
              let url = cfg["bridgeURL"] as? String, !url.isEmpty,
              let token = cfg["token"] as? String, !token.isEmpty
        else {
            completionHandler(NSError(domain: "BTF", code: 1,
                                      userInfo: [NSLocalizedDescriptionKey: "Bridge URL / token not configured"]))
            return
        }
        let relay = (cfg["relay"] as? Bool) ?? false
        let coalesce = (cfg["coalesceMs"] as? Int) ?? 50

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.2")

        let v4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"])
        v4.includedRoutes = [NEIPv4Route.default()]
        // Keep local networks, multicast and link-local out of the tunnel.
        v4.excludedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "224.0.0.0", subnetMask: "240.0.0.0"),
            NEIPv4Route(destinationAddress: "100.64.0.0", subnetMask: "255.192.0.0"),
        ]
        settings.ipv4Settings = v4

        // IPv6 is captured and refused so apps fall back to IPv4 (no leaks).
        let v6 = NEIPv6Settings(addresses: ["fd00:18::1"], networkPrefixLengths: [64])
        v6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = v6

        let dns = NEDNSSettings(servers: ["198.18.0.2"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: mtu)

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                completionHandler(error)
                return
            }
            let out = PacketOut(flow: self.packetFlow)
            guard let core = BtfcoreNewCore(url, token, relay, coalesce, self.mtu, out, nil) else {
                completionHandler(NSError(domain: "BTF", code: 2,
                                          userInfo: [NSLocalizedDescriptionKey: "Core init failed"]))
                return
            }
            do {
                try core.start()
            } catch {
                completionHandler(error)
                return
            }
            self.out = out
            self.core = core
            self.readLoop()
            completionHandler(nil)
        }
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self, let core = self.core else { return }
            for p in packets {
                core.injectPacket(p)
            }
            self.readLoop()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        core?.stop()
        core = nil
        out = nil
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let status = core?.status() ?? "stopped"
        let logs = core?.logs() ?? ""
        completionHandler?((status + "\n" + logs).data(using: .utf8))
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {}
}

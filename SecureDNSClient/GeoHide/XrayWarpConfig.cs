using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace SecureDNSClient.GeoHide;

internal sealed record XrayWarpAccount(string PrivateKey, string PeerPublicKey, string IPv6, int[] Reserved)
{
    internal void Validate()
    {
        if (Convert.FromBase64String(PrivateKey).Length != 32 || Convert.FromBase64String(PeerPublicKey).Length != 32)
            throw new FormatException("WARP keys must be 32 bytes.");
        if (!IPAddress.TryParse(IPv6.Split('/')[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetworkV6 ||
            !IPv6.EndsWith("/128", StringComparison.Ordinal) || Reserved.Length != 3 || Reserved.Any(x => x < 0 || x > 255))
            throw new FormatException("Invalid WARP address or reserved bytes.");
    }
}

internal sealed record XrayWarpOptions(bool DoubleTunnel = true, bool Noise = true, int NoiseCount = 5,
    int NoiseMin = 50, int NoiseMax = 100, int DelayMin = 1, int DelayMax = 5)
{
    internal void Validate()
    {
        if (NoiseCount is < 1 or > 10 || NoiseMin < 1 || NoiseMax > 1280 || NoiseMin > NoiseMax ||
            DelayMin < 0 || DelayMax > 100 || DelayMin > DelayMax)
            throw new ArgumentException("Noise must use 1–10 packets, 1–1280 bytes, and 0–100 ms delays with ordered ranges.");
    }
}

/// <summary>Independent implementation of BPB's two-account WARP chain and configurable UDP noise.</summary>
internal static class XrayWarpConfig
{
    internal static readonly string[] DefaultEndpoints = {
        "162.159.192.1:2408", "162.159.192.1:500", "162.159.192.1:4500", "162.159.192.2:1701",
        "162.159.193.1:2408", "188.114.96.1:2408", "188.114.97.1:500", "162.159.192.2:4500"
    };

    internal static IPEndPoint ParseEndpoint(string endpoint)
    {
        if (!IPEndPoint.TryParse(endpoint, out var ep) || ep.Port == 0 ||
            IPAddress.IsLoopback(ep.Address) || ep.Address.Equals(IPAddress.Any) || ep.Address.Equals(IPAddress.IPv6Any))
            throw new FormatException("Use an IP:port endpoint; IPv6 must use [address]:port.");
        return ep;
    }

    private static string Json(object value) => JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true });

    internal static string Build(XrayWarpAccount[] accounts, string endpoint, int port, string user, string password, XrayWarpOptions options)
    {
        options.Validate();
        ParseEndpoint(endpoint);
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        if (accounts.Length < (options.DoubleTunnel ? 2 : 1)) throw new ArgumentException("Two profiles are required for WARP-on-WARP.");
        foreach (var account in accounts) account.Validate();
        object Outbound(XrayWarpAccount account, bool inner) => new {
            tag = inner ? "chain" : "warp", protocol = "wireguard",
            settings = new { secretKey = account.PrivateKey, address = new[] { "172.16.0.2/32", account.IPv6 }, mtu = 1280,
                reserved = account.Reserved, peers = new[] { new { publicKey = account.PeerPublicKey,
                    endpoint = inner ? "162.159.192.1:2408" : endpoint, keepAlive = 5 } } },
            streamSettings = inner ? (object)new { sockopt = new { dialerProxy = "warp" } } :
                options.Noise ? new { finalmask = new { udp = new[] { new { type = "noise", settings = new {
                    reset = "30-60", noise = Enumerable.Range(0, options.NoiseCount).Select(_ => new {
                        rand = $"{options.NoiseMin}-{options.NoiseMax}", randRange = "0-255", delay = $"{options.DelayMin}-{options.DelayMax}" }).ToArray()
                } } } } } : new { }
        };
        var outbounds = new List<object>();
        if (options.DoubleTunnel) outbounds.Add(Outbound(accounts[1], true));
        outbounds.Add(Outbound(accounts[0], false));
        return Json(new {
            log = new { loglevel = "none" },
            inbounds = new[] { new { tag = "local", listen = "127.0.0.1", port, protocol = "socks",
                settings = new { auth = "password", accounts = new[] { new { user, pass = password } }, udp = true, ip = "127.0.0.1" } } },
            outbounds, routing = new { domainStrategy = "AsIs", rules = new[] {
                new { type = "field", inboundTag = new[] { "local" }, outboundTag = options.DoubleTunnel ? "chain" : "warp" }
            } }
        });
    }

    internal static string BuildTun(string endpoint, int port, string user, string password)
    {
        var ep = ParseEndpoint(endpoint);
        string bypass = ep.Address + (ep.AddressFamily == AddressFamily.InterNetwork ? "/32" : "/128");
        return Json(new {
            log = new { level = "error", timestamp = true },
            dns = new { servers = new[] { new { type = "https", tag = "remote", server = "1.1.1.1", server_port = 443,
                path = "/dns-query", tls = new { enabled = true, server_name = "cloudflare-dns.com" }, detour = "xray" } },
                final = "remote", strategy = "prefer_ipv4" },
            inbounds = new[] { new { type = "tun", tag = "game-tun", interface_name = "DNSveil-Xray",
                address = new[] { "172.30.253.1/30", "fdfe:dcba:9876::1/126" }, mtu = 1280, auto_route = true,
                strict_route = true, stack = "mixed", dns_mode = "hijack", route_exclude_address = new[] { bypass } } },
            outbounds = new[] { new { type = "socks", tag = "xray", server = "127.0.0.1", server_port = port,
                version = "5", username = user, password } },
            route = new { auto_detect_interface = true, final = "xray", rules = new[] { new { port = 53, action = "hijack-dns" } } }
        });
    }
}

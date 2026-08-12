using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace SecureDNSClient.GeoHide;

/// <summary>
/// Thin wrapper around Cloudflare's official <c>warp-cli</c>, inspired by
/// https://github.com/saeedmasoudie/pywarp (endpoint set, protocol, connect).
/// Censorship mode draws on IRCF endpoints, patterniha CF scanning (TCP not ICMP),
/// and GFW-knocker-style TLS fragmentation via <see cref="WarpDpiAssist"/>.
/// </summary>
public static class WarpCli
{
    public static readonly string[] EngageHosts =
    {
        "engage.cloudflareclient.com",
        "162.159.192.1", "162.159.192.2", "162.159.193.1", "162.159.193.3",
        "162.159.195.1", "162.159.195.3", "162.159.198.0", "162.159.198.1",
        "162.159.198.2", "162.159.199.1", "162.159.199.2", "162.159.204.1",
        "188.114.96.1", "188.114.97.1", "188.114.98.1", "188.114.99.1",
        "188.114.100.1", "188.114.101.1",
    };

    /// <summary>Classic WG + IRCF / community alternate ports used under censorship.</summary>
    public static readonly int[] WireGuardPorts =
    {
        2408, 500, 1701, 4500, 443, 854, 878, 864, 890, 894, 903, 908,
        1002, 1070, 1387, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198,
        4233, 4443, 5279, 5956, 7103, 7152, 7281, 7559, 8095, 8319, 8742,
        8854, 8886,
    };

    public static readonly int[] MasquePorts = { 443, 8443, 4443, 8095 };

    /// <summary>WARP/MASQUE-relevant CF ranges (IRCF + Cloudflare engage anycast).</summary>
    public static readonly string[] WarpScanCidrs =
    {
        "162.159.192.0/24",
        "162.159.193.0/24",
        "162.159.195.0/24",
        "162.159.198.0/24",
        "162.159.199.0/24",
        "188.114.96.0/24",
        "188.114.97.0/24",
        "188.114.98.0/24",
        "188.114.99.0/24",
    };

    private static readonly string[] IrcfEndpointUrls =
    {
        "https://raw.githubusercontent.com/ircfspace/endpoint/main/v2.json",
        "https://ircfspace.github.io/endpoint/v2.json",
    };

    private static string? _cachedExe;
    private static DateTime _cachedExeAt = DateTime.MinValue;
    private static readonly HttpClient SharedHttp = CreateHttpClient();
    private static List<string>? _cachedIrcf;
    private static DateTime _cachedIrcfAt = DateTime.MinValue;

    private static HttpClient CreateHttpClient()
    {
        HttpClient c = new() { Timeout = TimeSpan.FromSeconds(12) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("DNSveil-GeoHide/3.5");
        return c;
    }

    public sealed class Result
    {
        public int ExitCode { get; init; }
        public string StdOut { get; init; } = "";
        public string StdErr { get; init; } = "";
        public bool Ok => ExitCode == 0;
        public string Combined => (StdOut + "\n" + StdErr).Trim();
        public string ErrorLine =>
            string.IsNullOrWhiteSpace(StdErr)
                ? StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? ""
                : StdErr.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "";
    }

    public sealed class CensorshipOptions
    {
        /// <summary>Scan CF CIDRs + IRCF lists; MASQUE-first; longer polls.</summary>
        public bool Enabled { get; init; } = true;
        /// <summary>Start GoodbyeDPI TLS fragment before connect (GFW-knocker style).</summary>
        public bool DpiAssist { get; init; } = true;
        /// <summary>
        /// After connect: stop DPI assist, prefer tunnel_only (DNSveil owns DNS),
        /// optional WireGuard upgrade, exclude domestic IR ranges from the tunnel.
        /// </summary>
        public bool LowLatency { get; init; } = true;
        /// <summary>When false, skip WireGuard upgrade (saves ~10–30s under DPI).</summary>
        public bool TryWireGuardUpgrade { get; init; } = false;
        /// <summary>When false, skip applying dozens of Iran exclude ranges (already private excludes exist).</summary>
        public bool ApplyIranExcludes { get; init; } = true;
        public int MaxCandidates { get; init; } = 48;
        public int MaxConnectAttempts { get; init; } = 8;
        public int ProbeTimeoutMs { get; init; } = 400;
        public int CidrSamplePerRange { get; init; } = 16;
    }

    public static string? FindExecutable(bool forceRefresh = false)
    {
        try
        {
            if (!forceRefresh && _cachedExe != null && (DateTime.UtcNow - _cachedExeAt).TotalMinutes < 5)
            {
                if (File.Exists(_cachedExe)) return _cachedExe;
            }

            string? which = FindOnPath("warp-cli.exe") ?? FindOnPath("warp-cli");
            if (!string.IsNullOrEmpty(which))
            {
                _cachedExe = which;
                _cachedExeAt = DateTime.UtcNow;
                return which;
            }

            string[] candidates =
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cloudflare", "Cloudflare WARP", "warp-cli.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Cloudflare", "Cloudflare WARP", "warp-cli.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cloudflare", "CloudflareOne", "warp-cli.exe"),
                @"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
            };
            foreach (string c in candidates)
            {
                if (File.Exists(c))
                {
                    _cachedExe = c;
                    _cachedExeAt = DateTime.UtcNow;
                    return c;
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("WarpCli.FindExecutable: " + ex.Message);
        }
        _cachedExe = null;
        return null;
    }

    public static bool IsInstalled() => !string.IsNullOrEmpty(FindExecutable());

    public static bool IsServiceRunning()
    {
        try
        {
            return Process.GetProcessesByName("warp-svc").Length > 0
                || Process.GetProcessesByName("Cloudflare WARP").Length > 0;
        }
        catch
        {
            return true;
        }
    }

    public static Result Run(params string[] args)
    {
        string? exe = FindExecutable();
        if (string.IsNullOrEmpty(exe))
            return new Result { ExitCode = -1, StdErr = "warp-cli not found. Install Cloudflare WARP first." };

        try
        {
            using Process p = new();
            p.StartInfo = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = string.Join(" ", args.Select(Quote)),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            p.Start();

            Task<string> outTask = p.StandardOutput.ReadToEndAsync();
            Task<string> errTask = p.StandardError.ReadToEndAsync();
            if (!Task.WaitAll(new Task[] { outTask, errTask }, 45_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return new Result { ExitCode = -1, StdErr = "warp-cli timed out" };
            }
            if (!p.WaitForExit(5_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return new Result { ExitCode = -1, StdErr = "warp-cli timed out" };
            }

            return new Result
            {
                ExitCode = p.ExitCode,
                StdOut = (outTask.Result ?? "").Trim(),
                StdErr = (errTask.Result ?? "").Trim()
            };
        }
        catch (Exception ex)
        {
            return new Result { ExitCode = -1, StdErr = ex.Message };
        }
    }

    public static Result AcceptTos() => Run("accept-tos");
    public static Result Register() => Run("registration", "new");
    public static Result Connect() => Run("connect");
    public static Result Disconnect() => Run("disconnect");
    public static Result Status() => Run("status");
    public static Result SetModeWarp() => Run("mode", "warp");
    /// <summary>Tunnel without WARP DNS proxy — lower overhead when DNSveil already handles DNS.</summary>
    public static Result SetModeTunnelOnly() => Run("mode", "tunnel_only");
    public static Result SetProtocol(string protocol) => Run("tunnel", "protocol", "set", protocol);
    public static Result SetMasqueOptions(string options) => Run("tunnel", "masque-options", "set", options);
    public static Result SetEndpoint(string endpoint) => Run("tunnel", "endpoint", "set", endpoint);
    public static Result ResetEndpoint() => Run("tunnel", "endpoint", "reset");

    public static bool HasRegistration()
    {
        Result show = Run("registration", "show");
        if (IsRegistrationPresent(show)) return true;
        Result showJson = Run("-j", "registration", "show");
        return IsRegistrationPresent(showJson);
    }

    public static bool EnsureRegistration(IProgress<string>? progress = null)
    {
        if (HasRegistration()) return true;
        progress?.Report("Creating WARP registration…");
        Result reg = Register();
        AcceptTos();
        if (HasRegistration()) return true;
        progress?.Report("Registration failed: " + reg.ErrorLine);
        return false;
    }

    private static bool IsRegistrationPresent(Result r)
    {
        string t = r.Combined;
        if (string.IsNullOrWhiteSpace(t)) return false;
        if (t.Contains("not registered", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("No registration", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("Missing registration", StringComparison.OrdinalIgnoreCase))
            return false;
        if (t.Contains("Account type", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("Device ID", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("License", StringComparison.OrdinalIgnoreCase))
            return true;
        if (t.Contains("account_type", StringComparison.OrdinalIgnoreCase) ||
            t.Contains("\"device_id\"", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    public static string ParseStatus(Result r)
    {
        string text = r.Combined;
        foreach (string line in text.Split('\n'))
        {
            string s = line.Trim();
            if (s.StartsWith("Status update:", StringComparison.OrdinalIgnoreCase) ||
                s.StartsWith("Status:", StringComparison.OrdinalIgnoreCase))
                return s;
        }
        foreach (string line in text.Split('\n'))
        {
            string s = line.Trim();
            if (s.Contains("Connected", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("Disconnected", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("Connecting", StringComparison.OrdinalIgnoreCase))
                return s;
        }
        return string.IsNullOrWhiteSpace(r.StdOut) ? (r.Ok ? "Unknown" : r.ErrorLine) : r.StdOut.Split('\n')[0].Trim();
    }

    public static bool IsConnected(Result status)
    {
        foreach (string line in status.Combined.Split('\n'))
        {
            string s = line.Trim();
            if (!s.StartsWith("Status", StringComparison.OrdinalIgnoreCase)) continue;

            int colon = s.IndexOf(':');
            string value = colon >= 0 ? s[(colon + 1)..].Trim() : s;
            if (value.Equals("Connected", StringComparison.OrdinalIgnoreCase))
                return true;
            return false;
        }
        return false;
    }

    public static IEnumerable<string> EnumerateEndpointCandidates(string protocol = "WireGuard", int maxCount = 24)
    {
        bool masque = protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase);
        int[] ports = masque ? MasquePorts : WireGuardPorts.Take(8).ToArray();

        var hosts = new List<string> { EngageHosts[0] };
        var ips = EngageHosts.Skip(1).ToList();
        Shuffle(ips);
        hosts.AddRange(ips);

        int n = 0;
        foreach (string host in hosts)
        {
            foreach (int port in ports)
            {
                yield return $"{host}:{port}";
                if (++n >= maxCount) yield break;
            }
        }
    }

    /// <summary>
    /// Build a large Iran/censorship-oriented candidate list:
    /// IRCF live endpoints + known engage hosts + random samples from WARP CF CIDRs.
    /// Prefer MASQUE :443 (looks like HTTPS; H2 TCP fallback works with TLS fragment).
    /// </summary>
    public static async Task<List<string>> BuildCensorshipCandidatesAsync(
        string preferredProtocol,
        CensorshipOptions opt,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool preferMasque = preferredProtocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase)
                            || opt.Enabled;

        // 1) Live IRCF community list (Iran-curated)
        progress?.Report("Fetching IRCF community endpoints…");
        foreach (string ep in await FetchIrcfEndpointsAsync(ct).ConfigureAwait(false))
            set.Add(ep);

        // 2) Hardcoded engage + IRCF-like seeds
        foreach (string host in EngageHosts.Skip(1))
        {
            set.Add($"{host}:443");
            set.Add($"{host}:8443");
            set.Add($"{host}:2408");
            set.Add($"{host}:500");
            set.Add($"{host}:4500");
            set.Add($"{host}:1701");
        }

        // 3) Random samples from WARP CF CIDRs × MASQUE ports (patterniha: TCP scan, not ICMP)
        progress?.Report("Sampling Cloudflare WARP CIDRs (TCP probe targets)…");
        int[] ports = preferMasque
            ? MasquePorts
            : new[] { 2408, 500, 4500, 1701, 878, 894, 903, 1002, 4177, 7281, 8886 };
        foreach (string cidr in WarpScanCidrs)
        {
            foreach (IPAddress ip in SampleCidr(cidr, opt.CidrSamplePerRange))
            {
                foreach (int port in ports.Take(preferMasque ? 2 : 4))
                    set.Add($"{ip}:{port}");
            }
        }

        List<string> list = set.ToList();
        Shuffle(list);

        // Put MASQUE :443 first when censorship mode is on
        if (preferMasque)
        {
            list = list
                .OrderBy(e => e.EndsWith(":443") ? 0 : e.EndsWith(":8443") ? 1 : 2)
                .ThenBy(_ => Random.Shared.Next())
                .ToList();
        }

        if (list.Count > opt.MaxCandidates)
            list = list.Take(opt.MaxCandidates).ToList();

        progress?.Report($"Built {list.Count} censorship-resistant candidates.");
        return list;
    }

    public static async Task<List<string>> FetchIrcfEndpointsAsync(CancellationToken ct)
    {
        if (_cachedIrcf != null && (DateTime.UtcNow - _cachedIrcfAt).TotalMinutes < 30)
            return _cachedIrcf;

        var found = new List<string>();
        foreach (string url in IrcfEndpointUrls)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(8000);
                string json = await SharedHttp.GetStringAsync(url, cts.Token).ConfigureAwait(false);
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement root = doc.RootElement;

                void AddArr(JsonElement arr)
                {
                    if (arr.ValueKind != JsonValueKind.Array) return;
                    foreach (JsonElement el in arr.EnumerateArray())
                    {
                        string? s = el.GetString();
                        if (!string.IsNullOrWhiteSpace(s) && s.Contains(':') && !s.Contains('['))
                            found.Add(s.Trim());
                    }
                }

                if (root.TryGetProperty("masque", out JsonElement masque))
                {
                    if (masque.TryGetProperty("ipv4", out JsonElement m4)) AddArr(m4);
                }
                if (root.TryGetProperty("warp", out JsonElement warp))
                {
                    if (warp.TryGetProperty("ipv4", out JsonElement w4)) AddArr(w4);
                }
                // legacy ip.json shape
                if (root.TryGetProperty("ipv4", out JsonElement legacy)) AddArr(legacy);

                if (found.Count > 0) break;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("FetchIrcfEndpointsAsync: " + ex.Message);
            }
        }

        // Static IRCF v2 fallback seeds if network fetch failed
        if (found.Count == 0)
        {
            found.AddRange(new[]
            {
                "162.159.198.0:443", "162.159.198.1:443", "162.159.198.2:443",
                "162.159.192.1:2408", "162.159.192.1:500", "162.159.192.1:4500",
                "162.159.192.2:878", "162.159.192.64:894", "162.159.192.8:903",
                "162.159.195.1:4177", "162.159.195.3:878", "188.114.96.24:1002",
                "188.114.97.6:7281", "8.6.112.224:8886",
            });
        }

        _cachedIrcf = found.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        _cachedIrcfAt = DateTime.UtcNow;
        return _cachedIrcf;
    }

    public static async Task<(bool Ok, string Message, string? Endpoint, string Protocol)> TryConnectWithFallbackAsync(
        IEnumerable<string>? endpoints,
        string preferredProtocol = "WireGuard",
        IProgress<string>? progress = null,
        CancellationToken ct = default,
        CensorshipOptions? censorship = null)
    {
        censorship ??= new CensorshipOptions { Enabled = false, DpiAssist = false };

        if (!IsInstalled())
            return (false, "Cloudflare WARP (warp-cli) is not installed.", null, preferredProtocol);

        // Ensure Windows service is up (auto-start if stopped).
        var (svcOk, svcMsg, _) = await WarpPreflight.EnsureWarpServiceAsync(progress, ct).ConfigureAwait(false);
        if (!svcOk)
            return (false, svcMsg, null, preferredProtocol);

        // DPI assist first — fragment TLS ClientHello so engage/MASQUE H2 is not RST'd on SNI.
        if (censorship.DpiAssist)
        {
            var (dpiOk, dpiMsg) = await WarpDpiAssist.StartAsync(progress: progress).ConfigureAwait(false);
            progress?.Report(dpiMsg);
            if (!dpiOk)
                progress?.Report("Continuing without DPI assist…");
        }

        AcceptTos();
        Disconnect();

        if (!EnsureRegistration(progress))
        {
            if (censorship.DpiAssist) await WarpDpiAssist.StopAsync().ConfigureAwait(false);
            return (false, "WARP registration failed. Open the official WARP app once (or enable DPI assist), accept the ToS, then retry.", null, preferredProtocol);
        }

        // Gaming / low-latency: skip WARP DNS (DNSveil already does DNS) — less hop/overhead.
        if (censorship.LowLatency)
        {
            progress?.Report("Mode: tunnel_only (DNS stays with DNSveil — lower gaming latency)…");
            SetModeTunnelOnly();
            Run("debug", "high-timeouts", "disable");
        }
        else
        {
            SetModeWarp();
        }

        List<string> list = endpoints?.Where(e => !string.IsNullOrWhiteSpace(e)).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                            ?? new List<string>();

        if (censorship.Enabled && list.Count == 0)
        {
            list = await BuildCensorshipCandidatesAsync(preferredProtocol, censorship, progress, ct).ConfigureAwait(false);
        }

        // Under censorship: MASQUE only in the main loop (fast). Optional WG upgrade happens after connect.
        // Full WireGuard second pass was doubling Auto-find time with little gain under Iranian DPI.
        string[] protocols = censorship.Enabled
            ? new[] { "MASQUE" }
            : new[] { preferredProtocol };

        foreach (string protocol in protocols)
        {
            ct.ThrowIfCancellationRequested();
            SetProtocol(protocol);
            if (protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
                SetMasqueOptions("h3-with-h2-fallback");

            List<string> tryList = list;
            if (censorship.Enabled && list.Count > 0 &&
                protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
            {
                // Prefer HTTPS-looking MASQUE ports first (H2 TCP fallback + TLS fragment).
                List<string> masquePorts = list
                    .Where(e => e.EndsWith(":443") || e.EndsWith(":8443") || e.EndsWith(":4443") || e.EndsWith(":8095"))
                    .ToList();
                tryList = masquePorts.Count > 0
                    ? masquePorts.Concat(list.Except(masquePorts, StringComparer.OrdinalIgnoreCase)).ToList()
                    : list;
            }

            if (tryList.Count == 0)
            {
                progress?.Report($"Connecting with Cloudflare default endpoint ({protocol})…");
                ResetEndpoint();
                if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: censorship.Enabled).ConfigureAwait(false))
                {
                    return await FinishConnectedAsync(
                        $"Connected via default endpoint ({protocol}).", null, protocol, censorship, progress, ct).ConfigureAwait(false);
                }
                progress?.Report("Default endpoint failed: " + ParseStatus(Status()));
                continue;
            }

            progress?.Report($"Probing {tryList.Count} endpoints ({protocol}) in parallel…");
            List<string> reachable = await FilterReachableEndpointsAsync(
                tryList, protocol, progress, ct, censorship.ProbeTimeoutMs,
                take: censorship.Enabled ? censorship.MaxConnectAttempts : 12).ConfigureAwait(false);

            if (reachable.Count == 0)
            {
                progress?.Report("Probe found nothing — trying IRCF/seed top entries anyway…");
                reachable = tryList.Take(censorship.Enabled ? 6 : 8).ToList();
            }
            else
            {
                progress?.Report($"{reachable.Count} endpoints look reachable (fastest first) — connecting…");
            }

            int n = 0;
            foreach (string endpoint in reachable)
            {
                ct.ThrowIfCancellationRequested();
                n++;
                progress?.Report($"[{n}/{reachable.Count}] Connecting {endpoint} ({protocol})…");
                Disconnect();
                Result setEp = SetEndpoint(endpoint);
                if (!setEp.Ok)
                {
                    progress?.Report($"Skip {endpoint}: {setEp.ErrorLine}");
                    continue;
                }

                if (await PollConnectedAsync(progress, verifyWarpOn: false, ct, longPoll: censorship.Enabled).ConfigureAwait(false))
                {
                    PublicIpInfo info = await FetchPublicIpInfoAsync(5000).ConfigureAwait(false);
                    if (info.WarpOn != false)
                    {
                        return await FinishConnectedAsync(
                            $"Connected via {endpoint} ({protocol}).", endpoint, protocol, censorship, progress, ct).ConfigureAwait(false);
                    }
                    progress?.Report("Status connected but warp=off — trying next…");
                }
                else
                {
                    progress?.Report($"No connect on {endpoint}: {ParseStatus(Status())}");
                }
            }
        }

        // Last resort without custom list
        if (!censorship.Enabled || list.Count > 0)
        {
            progress?.Report("Last resort: default endpoint + MASQUE…");
            Disconnect();
            ResetEndpoint();
            SetProtocol("MASQUE");
            SetMasqueOptions("h3-with-h2-fallback");
            if (await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false))
            {
                return await FinishConnectedAsync(
                    "Connected via default endpoint (MASQUE).", null, "MASQUE", censorship, progress, ct).ConfigureAwait(false);
            }
        }

        if (censorship.DpiAssist) await WarpDpiAssist.StopAsync().ConfigureAwait(false);

        return (false,
            "Could not connect under censorship. Tips: keep \"DPI assist\" on, try again (new CF IPs), " +
            "or paste a working IP:443 from Clean IP Scanner / IRCF. " +
            "If WARP IPs themselves are fully blocked, official warp-cli cannot fake MASQUE SNI — " +
            "tools like usque/masque-plus with custom SNI may be required as a last resort.",
            null, preferredProtocol);
    }

    /// <summary>
    /// Post-connect latency pass: stop WinDivert fragmentor, optional WG upgrade, IR split-tunnel excludes.
    /// </summary>
    private static async Task<(bool Ok, string Message, string? Endpoint, string Protocol)> FinishConnectedAsync(
        string message,
        string? endpoint,
        string protocol,
        CensorshipOptions opt,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        // Critical for gaming: GoodbyeDPI/WinDivert adds latency to all TCP — stop once tunnel is up.
        if (opt.DpiAssist || WarpDpiAssist.IsActive)
        {
            progress?.Report("Stopping DPI assist (WinDivert fragment adds latency to games)…");
            await WarpDpiAssist.StopAsync().ConfigureAwait(false);
        }

        string usedProtocol = protocol;
        string? usedEndpoint = endpoint;

        if (opt.LowLatency)
        {
            SetModeTunnelOnly();
            Run("debug", "high-timeouts", "disable");

            // WG upgrade is optional — under Iranian DPI it often fails and wastes 15–40s.
            if (opt.TryWireGuardUpgrade &&
                protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase))
            {
                var upgraded = await TryUpgradeToWireGuardAsync(endpoint, progress, ct).ConfigureAwait(false);
                if (upgraded.Ok)
                {
                    usedProtocol = "WireGuard";
                    usedEndpoint = upgraded.Endpoint ?? endpoint;
                    message = $"Connected via {usedEndpoint ?? "default"} (WireGuard, upgraded from MASQUE for lower latency).";
                }
                else
                {
                    progress?.Report("WireGuard upgrade skipped — staying on MASQUE.");
                }
            }

            if (opt.ApplyIranExcludes)
            {
                progress?.Report("Excluding Iran/domestic ranges from tunnel (cached after first run)…");
                await Task.Run(() => ApplyDomesticSplitTunnelExcludes(progress), ct).ConfigureAwait(false);
            }

            message += " Low-latency profile applied.";
        }

        return (true, message, usedEndpoint, usedProtocol);
    }

    /// <summary>Try same host on classic WG ports — lower overhead than MASQUE/H2 when UDP works.</summary>
    private static async Task<(bool Ok, string? Endpoint)> TryUpgradeToWireGuardAsync(
        string? currentEndpoint,
        IProgress<string>? progress,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(currentEndpoint) ||
            !TryParseHostPort(currentEndpoint, out string host, out _))
        {
            host = (!string.IsNullOrWhiteSpace(currentEndpoint) && currentEndpoint.IndexOf(':') < 0)
                ? currentEndpoint.Trim()
                : "engage.cloudflareclient.com";
        }

        int[] ports = { 2408, 500 }; // keep short — full port sweep was a major Auto-find delay
        foreach (int port in ports)
        {
            ct.ThrowIfCancellationRequested();
            string ep = $"{host}:{port}";
            progress?.Report($"Low-latency: trying WireGuard {ep}…");
            Disconnect();
            SetProtocol("WireGuard");
            Result set = SetEndpoint(ep);
            if (!set.Ok) continue;
            if (!await PollConnectedAsync(progress, verifyWarpOn: false, ct, longPoll: false).ConfigureAwait(false))
                continue;
            PublicIpInfo info = await FetchPublicIpInfoAsync(3000).ConfigureAwait(false);
            if (info.WarpOn != false)
                return (true, ep);
        }

        // Revert to MASQUE on original endpoint
        progress?.Report("Reverting to MASQUE…");
        Disconnect();
        SetProtocol("MASQUE");
        SetMasqueOptions("h3-with-h2-fallback");
        if (!string.IsNullOrWhiteSpace(currentEndpoint))
            SetEndpoint(currentEndpoint);
        else
            ResetEndpoint();
        await PollConnectedAsync(progress, verifyWarpOn: true, ct, longPoll: true).ConfigureAwait(false);
        return (false, null);
    }
    private static bool _iranExcludesApplied;

    /// <summary>
    /// Keep Iranian / private traffic off WARP so only foreign destinations (game servers) use the tunnel.
    /// Runs once per process — re-applying 80+ ranges was a major post-connect stall.
    /// </summary>
    public static void ApplyDomesticSplitTunnelExcludes(IProgress<string>? progress = null)
    {
        if (_iranExcludesApplied)
        {
            progress?.Report("Iran/domestic excludes already applied this session.");
            return;
        }

        // Fewer large aggregates (speed) — private RFC1918 + major IR blocks
        string[] ranges =
        {
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
            "2.144.0.0/14", "5.208.0.0/12", "5.232.0.0/14", "31.56.0.0/14",
            "37.156.0.0/14", "46.209.0.0/16", "78.38.0.0/15", "79.127.0.0/16",
            "81.12.0.0/16", "85.185.0.0/16", "89.198.0.0/16", "91.98.0.0/15",
            "94.182.0.0/15", "95.38.0.0/16", "151.232.0.0/14", "151.238.0.0/15",
            "176.65.192.0/18", "178.131.0.0/16", "185.4.0.0/16", "188.209.0.0/16",
            "188.245.0.0/16", "194.225.0.0/16", "217.218.0.0/15",
        };

        int ok = 0;
        foreach (string range in ranges)
        {
            Result r = Run("tunnel", "ip", "add-range", range);
            if (r.Ok || r.Combined.Contains("already", StringComparison.OrdinalIgnoreCase))
                ok++;
        }
        _iranExcludesApplied = true;
        progress?.Report($"Split-tunnel excludes applied ({ok}/{ranges.Length} ranges).");
    }

    public static async Task<List<string>> FilterReachableEndpointsAsync(
        IList<string> endpoints,
        string protocol,
        IProgress<string>? progress,
        CancellationToken ct,
        int timeoutMs = 350,
        int take = 12)
    {
        bool masque = protocol.Equals("MASQUE", StringComparison.OrdinalIgnoreCase);
        var scored = new ConcurrentBag<(string Ep, int Ms)>();

        await Parallel.ForEachAsync(
            endpoints,
            new ParallelOptions { MaxDegreeOfParallelism = 96, CancellationToken = ct },
            async (ep, token) =>
            {
                if (!TryParseHostPort(ep, out string host, out int port)) return;

                int ms;
                if (masque)
                {
                    // Real TCP connect on the MASQUE port (patterniha: do not rely on ICMP).
                    ms = await MeasureTcpMsAsync(host, port, timeoutMs, token).ConfigureAwait(false);
                    if (ms < 0 && port == 443)
                        ms = await MeasureTcpMsAsync(host, 8443, timeoutMs, token).ConfigureAwait(false);
                }
                else
                {
                    // WG is UDP — try cheap UDP send; also TCP/443 as CF-edge liveness.
                    ms = await MeasureUdpMsAsync(host, port, timeoutMs, token).ConfigureAwait(false);
                    if (ms < 0)
                    {
                        int tcp = await MeasureTcpMsAsync(host, 443, timeoutMs, token).ConfigureAwait(false);
                        if (tcp >= 0) ms = tcp + 80; // deprioritize vs real UDP hits
                    }
                }

                if (ms >= 0)
                    scored.Add((ep, ms));
            }).ConfigureAwait(false);

        List<string> ordered = scored
            .OrderBy(x => x.Ms)
            .Select(x => x.Ep)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(4, take))
            .ToList();

        progress?.Report(ordered.Count > 0
            ? $"Fastest probe: {ordered[0]} (~{scored.First(s => s.Ep == ordered[0]).Ms}ms)"
            : "Reachability probe found no open ports.");
        return ordered;
    }

    private static bool TryParseHostPort(string endpoint, out string host, out int port)
    {
        host = "";
        port = 0;
        int idx = endpoint.LastIndexOf(':');
        if (idx <= 0 || idx >= endpoint.Length - 1) return false;
        host = endpoint[..idx].Trim();
        return int.TryParse(endpoint[(idx + 1)..], out port) && port > 0 && port <= 65535 && host.Length > 0;
    }

    private static async Task<int> MeasureTcpMsAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var sw = Stopwatch.StartNew();
            using var client = new TcpClient { NoDelay = true };
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeoutMs);
            await client.ConnectAsync(host, port, linked.Token).ConfigureAwait(false);
            sw.Stop();
            return client.Connected ? (int)sw.ElapsedMilliseconds : -1;
        }
        catch
        {
            return -1;
        }
    }

    private static async Task<int> MeasureUdpMsAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var sw = Stopwatch.StartNew();
            using var udp = new UdpClient();
            udp.Client.SendTimeout = timeoutMs;
            udp.Client.ReceiveTimeout = timeoutMs;
            // WireGuard handshake-ish bytes — we only care that the path accepts UDP.
            byte[] payload = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeoutMs);
            await udp.SendAsync(payload, host, port, linked.Token).ConfigureAwait(false);
            sw.Stop();
            // No reliable reply expected; treat successful send as weak positive.
            return (int)Math.Max(1, sw.ElapsedMilliseconds);
        }
        catch
        {
            return -1;
        }
    }

    private static async Task<bool> PollConnectedAsync(
        IProgress<string>? progress, bool verifyWarpOn, CancellationToken ct, bool longPoll = false)
    {
        Connect();
        int loops = longPoll ? (verifyWarpOn ? 20 : 14) : (verifyWarpOn ? 12 : 8);
        int delay = longPoll ? 500 : 400;
        for (int i = 0; i < loops; i++)
        {
            await Task.Delay(delay, ct).ConfigureAwait(false);
            Result st = Status();
            string parsed = ParseStatus(st);
            if (parsed.Contains("Failed", StringComparison.OrdinalIgnoreCase))
                return false;
            if (i >= 3 && (parsed.Contains("Disconnected", StringComparison.OrdinalIgnoreCase) ||
                           parsed.Contains("Not connected", StringComparison.OrdinalIgnoreCase)))
                return false;

            if (!IsConnected(st)) continue;

            if (!verifyWarpOn) return true;

            PublicIpInfo info = await FetchPublicIpInfoAsync(4000).ConfigureAwait(false);
            if (info.WarpOn == true) return true;
            if (info.WarpOn == false)
                progress?.Report("warp-cli says Connected but trace shows warp=off — waiting…");
            else if (i >= 6)
                return true;
        }
        return IsConnected(Status());
    }

    public sealed class PublicIpInfo
    {
        public string? Ip { get; init; }
        public bool? WarpOn { get; init; }
        public string? Loc { get; init; }
    }

    public static async Task<PublicIpInfo> FetchPublicIpInfoAsync(int timeoutMs = 8000)
    {
        try
        {
            using CancellationTokenSource cts = new(timeoutMs);
            string body = await SharedHttp.GetStringAsync("https://cloudflare.com/cdn-cgi/trace", cts.Token).ConfigureAwait(false);
            string? ip = null;
            bool? warp = null;
            string? loc = null;
            foreach (string line in body.Split('\n'))
            {
                if (line.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                    ip = line[3..].Trim();
                else if (line.StartsWith("warp=", StringComparison.OrdinalIgnoreCase))
                    warp = line[5..].Trim().Equals("on", StringComparison.OrdinalIgnoreCase);
                else if (line.StartsWith("loc=", StringComparison.OrdinalIgnoreCase))
                    loc = line[4..].Trim();
            }
            if (!string.IsNullOrEmpty(ip))
                return new PublicIpInfo { Ip = ip, WarpOn = warp, Loc = loc };
        }
        catch (Exception ex)
        {
            Debug.WriteLine("FetchPublicIpInfoAsync cf: " + ex.Message);
        }
        try
        {
            using CancellationTokenSource cts = new(timeoutMs);
            string ip = (await SharedHttp.GetStringAsync("https://api.ipify.org", cts.Token).ConfigureAwait(false)).Trim();
            return new PublicIpInfo { Ip = ip, WarpOn = null, Loc = null };
        }
        catch (Exception ex)
        {
            Debug.WriteLine("FetchPublicIpInfoAsync ipify: " + ex.Message);
            return new PublicIpInfo();
        }
    }

    public static async Task<string?> FetchPublicIpAsync(int timeoutMs = 8000)
        => (await FetchPublicIpInfoAsync(timeoutMs).ConfigureAwait(false)).Ip;

    private static IEnumerable<IPAddress> SampleCidr(string cidr, int count)
    {
        if (!TryParseCidr(cidr, out uint start, out int prefix))
            yield break;

        int hostBits = 32 - prefix;
        long size = hostBits >= 31 ? int.MaxValue : (1L << hostBits);
        if (size <= 2)
        {
            yield return ToIp(start);
            yield break;
        }

        // Skip network/broadcast; sample randomly
        var seen = new HashSet<uint>();
        int attempts = 0;
        while (seen.Count < count && attempts++ < count * 8)
        {
            uint offset = (uint)(Random.Shared.NextInt64(1, Math.Min(size - 1, int.MaxValue)));
            uint ip = start + offset;
            if (seen.Add(ip))
                yield return ToIp(ip);
        }
    }

    private static bool TryParseCidr(string cidr, out uint network, out int prefix)
    {
        network = 0;
        prefix = 0;
        string[] parts = cidr.Split('/');
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(parts[0], out IPAddress? ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            return false;
        if (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > 32) return false;
        byte[] b = ip.GetAddressBytes();
        uint addr = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        network = addr & mask;
        return true;
    }

    private static IPAddress ToIp(uint addr) =>
        new(new byte[] { (byte)(addr >> 24), (byte)(addr >> 16), (byte)(addr >> 8), (byte)addr });

    private static void Shuffle<T>(IList<T> list)
    {
        for (int i = list.Count - 1; i > 0; i--)
        {
            int j = Random.Shared.Next(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
    }

    private static string? FindOnPath(string fileName)
    {
        string? pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(pathEnv)) return null;
        foreach (string dir in pathEnv.Split(Path.PathSeparator))
        {
            try
            {
                string full = Path.Combine(dir.Trim(), fileName);
                if (File.Exists(full)) return full;
            }
            catch { /* ignore */ }
        }
        return null;
    }

    private static string Quote(string a)
    {
        if (string.IsNullOrEmpty(a)) return "\"\"";
        if (a.Contains(' ') || a.Contains('"')) return "\"" + a.Replace("\"", "\\\"") + "\"";
        return a;
    }
}

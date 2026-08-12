using CustomControls;
using MsmhToolsClass;
using SecureDNSClient.GeoHide;
using System.Diagnostics;

namespace SecureDNSClient;

/// <summary>
/// GeoHide via official Cloudflare WARP (warp-cli), patterned after pywarp:
/// https://github.com/saeedmasoudie/pywarp
/// Censorship mode: IRCF endpoints + CF CIDR scan + GoodbyeDPI TLS fragment
/// (GFW-knocker / patterniha lessons for Iranian DPI).
/// </summary>
public class FormGeoHideWarp : Form
{
    private readonly Label _lblHelp = new();
    private readonly Label _lblStatus = new();
    private readonly Label _lblIp = new();
    private readonly Label _lblEp = new();
    private readonly Label _lblProto = new();
    private readonly Label _lblPreset = new();
    private readonly Label _lblFoot = new();
    private readonly ComboBox _cmbEndpoint = new();
    private readonly ComboBox _cmbProtocol = new();
    private readonly ComboBox _cmbPreset = new();
    private readonly CustomButton _btnRefresh = new();
    private readonly CustomButton _btnConnect = new();
    private readonly CustomButton _btnDisconnect = new();
    private readonly CustomButton _btnCancel = new();
    private readonly CustomButton _btnInstall = new();
    private readonly CustomButton _btnImportPreset = new();
    private readonly CustomButton _btnHelp = new();
    private readonly TextBox _log = new();
    private readonly CheckBox _chkImportAfterConnect = new();
    private readonly CheckBox _chkCensorship = new();
    private readonly CheckBox _chkDpiAssist = new();
    private readonly CheckBox _chkLowLatency = new();
    private readonly CustomButton _btnMinimize = new();
    private CancellationTokenSource? _cts;
    private CancellationTokenSource? _watchCts;
    private string? _activeEndpoint;
    private string _activeProtocol = "MASQUE";
    private WarpCli.CensorshipOptions? _lastOpt;
    private bool _busy;
    private bool _reloadingEndpoints;

    public FormGeoHideWarp()
    {
        Text = "GeoHide — Cloudflare WARP";
        ClientSize = new Size(640, 590);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.Sizable;
        MaximizeBox = false;
        MinimizeBox = true;
        ShowInTaskbar = true;
        ShowIcon = true;
        MinimumSize = new Size(640, 520);
        BackColor = Color.FromArgb(32, 32, 32);
        ForeColor = Color.WhiteSmoke;
        Font = new Font("Segoe UI", 9F);

        SuspendLayout();

        _lblHelp.AutoSize = false;
        _lblHelp.Location = new Point(12, 10);
        _lblHelp.Size = new Size(616, 40);
        _lblHelp.Text = "Uses official Cloudflare WARP (warp-cli). Under Iranian DPI: enable Censorship + DPI assist, then Connect (scans IRCF/CF and connects). Destinations see a Cloudflare exit IP — not your ISP.";

        _lblStatus.AutoSize = false;
        _lblStatus.Location = new Point(12, 54);
        _lblStatus.Size = new Size(490, 22);
        _lblStatus.Text = "Status: …";
        _lblStatus.AutoEllipsis = true;

        _lblIp.AutoSize = false;
        _lblIp.Location = new Point(12, 76);
        _lblIp.Size = new Size(600, 22);
        _lblIp.Text = "Public IP: …";
        _lblIp.AutoEllipsis = true;

        StyleBtn(_btnRefresh, "Refresh", new Point(510, 50), 100);
        _btnRefresh.Click += async (_, _) =>
        {
            try { await RefreshStatusAsync(fromUser: true).ConfigureAwait(true); }
            catch (Exception ex) { Log("Refresh error: " + ex.Message); }
        };
        _btnRefresh.BringToFront();

        _lblEp.AutoSize = true;
        _lblEp.Location = new Point(12, 108);
        _lblEp.Text = "Endpoint";
        _cmbEndpoint.Location = new Point(80, 104);
        _cmbEndpoint.Size = new Size(280, 28);
        _cmbEndpoint.DropDownStyle = ComboBoxStyle.DropDown;
        StyleCombo(_cmbEndpoint);

        _lblProto.AutoSize = true;
        _lblProto.Location = new Point(380, 108);
        _lblProto.Text = "Protocol";
        _cmbProtocol.Location = new Point(440, 104);
        _cmbProtocol.Size = new Size(120, 28);
        _cmbProtocol.DropDownStyle = ComboBoxStyle.DropDownList;
        StyleCombo(_cmbProtocol);
        _cmbProtocol.Items.AddRange(new object[] { "MASQUE", "WireGuard" });
        _cmbProtocol.SelectedIndexChanged += (_, _) =>
        {
            if (_reloadingEndpoints) return;
            ReloadEndpointList();
        };
        _cmbProtocol.SelectedIndex = 0; // MASQUE first under censorship

        StyleBtn(_btnConnect, "Connect", new Point(12, 140), 110);
        StyleBtn(_btnDisconnect, "Disconnect", new Point(128, 140), 90);
        StyleBtn(_btnCancel, "Cancel", new Point(224, 140), 70);
        StyleBtn(_btnMinimize, "Minimize", new Point(300, 140), 80);
        StyleBtn(_btnInstall, "Get WARP…", new Point(386, 140), 100);
        StyleBtn(_btnHelp, "Help", new Point(492, 140), 64);
        _btnCancel.Enabled = false;
        _btnConnect.Click += async (_, _) => await ConnectAsync();
        _btnDisconnect.Click += async (_, _) => await DisconnectAsync();
        _btnCancel.Click += (_, _) => { try { _cts?.Cancel(); } catch { } };
        _btnMinimize.Click += (_, _) => { WindowState = FormWindowState.Minimized; };
        _btnInstall.Click += (_, _) => OpenLinks.OpenUrl("https://one.one.one.one/");
        _btnHelp.Click += (_, _) => CustomMessageBox.Show(this, GeoHidePresets.HelpSummary, "GeoHide help",
            MessageBoxButtons.OK, MessageBoxIcon.Information);

        _chkCensorship.AutoSize = true;
        _chkCensorship.Location = new Point(12, 176);
        _chkCensorship.Text = "Censorship mode (Iran) — IRCF + CF scan, MASQUE (needed under DPI)";
        _chkCensorship.ForeColor = Color.WhiteSmoke;
        _chkCensorship.BackColor = Color.Transparent;
        _chkCensorship.Checked = true;
        _chkCensorship.CheckedChanged += (_, _) => SyncOptionConflicts(fromUser: true);

        _chkDpiAssist.AutoSize = true;
        _chkDpiAssist.Location = new Point(12, 200);
        _chkDpiAssist.Text = "DPI assist — GoodbyeDPI only during connect (auto-stopped after)";
        _chkDpiAssist.ForeColor = Color.WhiteSmoke;
        _chkDpiAssist.BackColor = Color.Transparent;
        _chkDpiAssist.Checked = true;

        _chkLowLatency.AutoSize = true;
        _chkLowLatency.Location = new Point(12, 224);
        _chkLowLatency.Text = "Low latency — stop DPI after connect (keeps WARP DNS; Iran excludes off for stability)";
        _chkLowLatency.ForeColor = Color.WhiteSmoke;
        _chkLowLatency.BackColor = Color.Transparent;
        _chkLowLatency.Checked = true;
        _chkLowLatency.CheckedChanged += (_, _) => SyncOptionConflicts(fromUser: true);

        _lblPreset.AutoSize = true;
        _lblPreset.Location = new Point(12, 256);
        _lblPreset.Text = "Rules preset";
        _cmbPreset.Location = new Point(100, 252);
        _cmbPreset.Size = new Size(260, 28);
        _cmbPreset.DropDownStyle = ComboBoxStyle.DropDownList;
        StyleCombo(_cmbPreset);
        _cmbPreset.Items.AddRange(new object[]
        {
            "Shecan anti-sanction (web/dev)",
            "Via upstream proxy",
            "Gaming Smart DNS template"
        });
        _cmbPreset.SelectedIndex = 0;
        StyleBtn(_btnImportPreset, "Import into Rules", new Point(372, 250), 150);
        _btnImportPreset.Click += async (_, _) => await ImportSelectedPresetAsync(silent: false);

        _chkImportAfterConnect.AutoSize = true;
        _chkImportAfterConnect.Location = new Point(12, 286);
        _chkImportAfterConnect.Text = "Also import selected preset after successful connect";
        _chkImportAfterConnect.ForeColor = Color.WhiteSmoke;
        _chkImportAfterConnect.BackColor = Color.Transparent;
        _chkImportAfterConnect.Checked = false;

        _log.Location = new Point(12, 314);
        _log.Size = new Size(616, 216);
        _log.Multiline = true;
        _log.ScrollBars = ScrollBars.Vertical;
        _log.ReadOnly = true;
        _log.BackColor = Color.FromArgb(24, 24, 24);
        _log.ForeColor = Color.Gainsboro;
        _log.BorderStyle = BorderStyle.FixedSingle;

        _lblFoot.AutoSize = false;
        _lblFoot.Location = new Point(12, 538);
        _lblFoot.Size = new Size(616, 44);
        _lblFoot.Text = "Preflight checks Iran IP / other VPNs and starts CloudflareWARP if stopped. Options are complementary: DPI only for handshake; low-latency after connect.";

        Controls.AddRange(new Control[]
        {
            _lblHelp, _lblStatus, _lblIp, _btnRefresh,
            _lblEp, _cmbEndpoint, _lblProto, _cmbProtocol,
            _btnConnect, _btnDisconnect, _btnCancel, _btnMinimize, _btnInstall, _btnHelp,
            _chkCensorship, _chkDpiAssist, _chkLowLatency,
            _lblPreset, _cmbPreset, _btnImportPreset, _chkImportAfterConnect,
            _log, _lblFoot
        });

        foreach (Control c in Controls)
        {
            if (c is Label lbl)
            {
                lbl.ForeColor = Color.WhiteSmoke;
                lbl.BackColor = Color.Transparent;
            }
        }

        ResumeLayout(true);
        ReloadEndpointList();
        SyncOptionConflicts(fromUser: false);

        Shown += async (_, _) =>
        {
            await RunStartupPreflightAsync().ConfigureAwait(true);
        };
        FormClosing += (_, _) =>
        {
            StopLinkWatch();
            try { _cts?.Cancel(); } catch { }
            try { _cts?.Dispose(); } catch { }
            _cts = null;
        };
    }

    private void SyncOptionConflicts(bool fromUser)
    {
        // Censorship needs MASQUE + DPI under Iranian filtering.
        if (_chkCensorship.Checked)
        {
            if (_cmbProtocol.Items.Count > 0 &&
                !string.Equals(_cmbProtocol.SelectedItem?.ToString(), "MASQUE", StringComparison.OrdinalIgnoreCase))
                _cmbProtocol.SelectedIndex = 0;
            if (fromUser && !_chkDpiAssist.Checked)
                _chkDpiAssist.Checked = true;
        }

        // No real mutual exclusion: DPI runs only during handshake; low-latency applies after.
        // WireGuard upgrade under censorship is slow/rarely works — kept off by default in ConnectAsync.
    }

    private async Task RunStartupPreflightAsync()
    {
        if (!WarpCli.IsInstalled())
        {
            Log("warp-cli NOT found — click Get WARP… and install Cloudflare WARP.");
            await RefreshStatusAsync().ConfigureAwait(true);
            return;
        }

        Log("Running preflight (service / Iran IP / VPN conflict)…");
        var report = await WarpPreflight.RunAsync(new Progress<string>(Log)).ConfigureAwait(true);
        foreach (string n in report.Notes) Log(n);
        foreach (string w in report.Warnings) Log("WARN: " + w);

        // Auto-tune options from geo
        if (report.LikelyIran)
        {
            _chkCensorship.Checked = true;
            _chkDpiAssist.Checked = true;
            SyncOptionConflicts(fromUser: false);
        }
        else if (!report.AlreadyOnWarp && !string.IsNullOrEmpty(report.Loc))
        {
            // Outside IR and not on WARP — censorship scan is unnecessary overhead
            Log("Tip: not in IR — uncheck Censorship mode for a much faster Connect.");
        }

        if (report.OtherVpnLikely)
        {
            CustomMessageBox.Show(this,
                "Another VPN/tunnel appears active (" + report.OtherVpnHint + ").\n\n" +
                "Disconnect it before GeoHide Connect, or WARP will fight it (slow/fail/high latency).",
                "VPN conflict", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        await RefreshStatusAsync().ConfigureAwait(true);
    }

    private static void StyleCombo(ComboBox c)
    {
        c.BackColor = Color.FromArgb(45, 45, 45);
        c.ForeColor = Color.White;
        c.FlatStyle = FlatStyle.Flat;
    }

    private GeoHidePresets.PresetKind SelectedPresetKind() => _cmbPreset.SelectedIndex switch
    {
        1 => GeoHidePresets.PresetKind.ViaUpstreamProxy,
        2 => GeoHidePresets.PresetKind.GamingSmartDns,
        _ => GeoHidePresets.PresetKind.AntiSanctionShecanShelter
    };

    private void ReloadEndpointList()
    {
        if (_reloadingEndpoints) return;
        _reloadingEndpoints = true;
        try
        {
            string protocol = _cmbProtocol.SelectedItem?.ToString() ?? "MASQUE";
            string keep = _cmbEndpoint.Text;
            _cmbEndpoint.BeginUpdate();
            _cmbEndpoint.Items.Clear();
            _cmbEndpoint.Items.Add("(Cloudflare default)");
            foreach (string ep in WarpCli.EnumerateEndpointCandidates(protocol, 40))
                _cmbEndpoint.Items.Add(ep);
            if (!string.IsNullOrWhiteSpace(keep) && _cmbEndpoint.Items.Contains(keep))
                _cmbEndpoint.Text = keep;
            else
                _cmbEndpoint.SelectedIndex = 0;
            _cmbEndpoint.EndUpdate();
        }
        finally { _reloadingEndpoints = false; }
    }

    private static void StyleBtn(CustomButton b, string text, Point loc, int width)
    {
        b.Text = text;
        b.Location = loc;
        b.Size = new Size(width, 28);
        b.BorderColor = Color.DodgerBlue;
        b.FlatStyle = FlatStyle.Flat;
        b.RoundedCorners = 5;
        b.ForeColor = Color.White;
        b.BackColor = Color.FromArgb(50, 50, 50);
    }

    private void Log(string msg)
    {
        try
        {
            if (InvokeRequired)
            {
                BeginInvoke(() => Log(msg));
                return;
            }
            _log.AppendText($"{DateTime.Now:HH:mm:ss} {msg}{Environment.NewLine}");
        }
        catch { }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        _btnConnect.Enabled = !busy;
        _btnDisconnect.Enabled = !busy;
        _btnRefresh.Enabled = !busy;
        _btnImportPreset.Enabled = !busy;
        _btnCancel.Enabled = busy;
        _cmbEndpoint.Enabled = !busy;
        _cmbProtocol.Enabled = !busy;
        _cmbPreset.Enabled = !busy;
        _chkCensorship.Enabled = !busy;
        _chkDpiAssist.Enabled = !busy;
        _chkLowLatency.Enabled = !busy;
        _btnMinimize.Enabled = true; // always allow minimize
    }

    private async Task RefreshStatusAsync(bool fromUser = false)
    {
        if (fromUser)
        {
            _lblStatus.Text = "Status: refreshing…";
            _lblIp.Text = "Public IP: …";
            Log("Refreshing WARP status / public IP…");
            _btnRefresh.Enabled = false;
        }

        try
        {
            if (!WarpCli.IsInstalled())
            {
                _lblStatus.Text = "Status: WARP not installed";
                _lblIp.Text = "Public IP: —";
                if (fromUser) Log("Refresh: warp-cli not installed.");
                return;
            }

            // User Refresh should try to wake a stopped service (same as Connect preflight).
            if (fromUser && !WarpCli.IsServiceRunning())
            {
                _lblStatus.Text = "Status: starting WARP service…";
                var (svcOk, svcMsg, _) = await WarpPreflight.EnsureWarpServiceAsync(
                    fromUser ? new Progress<string>(Log) : null).ConfigureAwait(true);
                if (!svcOk)
                {
                    _lblStatus.Text = "Status: WARP service not running";
                    _lblIp.Text = "Public IP: —";
                    Log("Refresh: " + svcMsg);
                    return;
                }
            }
            else if (!WarpCli.IsServiceRunning())
            {
                _lblStatus.Text = "Status: WARP service not running";
            }

            var st = await Task.Run(() => WarpCli.Status()).ConfigureAwait(true);
            string parsed = WarpCli.ParseStatus(st);
            if (!WarpCli.IsServiceRunning() && string.IsNullOrWhiteSpace(st.Combined))
                _lblStatus.Text = "Status: WARP service not running";
            else
                _lblStatus.Text = "Status: " + (string.IsNullOrWhiteSpace(parsed) ? "(empty)" : parsed);

            var info = await WarpCli.FetchPublicIpInfoAsync(6000).ConfigureAwait(true);
            string ipPart = info.Ip ?? "unavailable";
            string warpPart = info.WarpOn == true ? " (warp=on)" : info.WarpOn == false ? " (warp=off)" : " (warp=?)";
            string locPart = string.IsNullOrEmpty(info.Loc) ? "" : $" [{info.Loc}]";
            string coloPart = string.IsNullOrEmpty(info.Colo) ? "" : $" colo={info.Colo}";
            _lblIp.Text = "Public IP: " + ipPart + warpPart + locPart + coloPart;

            if (fromUser)
            {
                Log($"Refresh done — {parsed} | IP {ipPart}{warpPart}{locPart}{coloPart}" +
                    (string.IsNullOrEmpty(info.Error) ? "" : $" ({info.Error})"));
            }
        }
        catch (Exception ex)
        {
            _lblStatus.Text = "Status: refresh failed";
            if (fromUser) Log("Refresh error: " + ex.Message);
            else throw;
        }
        finally
        {
            if (fromUser && !_busy)
                _btnRefresh.Enabled = true;
        }
    }

    private async Task DisconnectAsync()
    {
        if (_busy) return;
        StopLinkWatch();
        SetBusy(true);
        try
        {
            var r = await Task.Run(() => WarpCli.Disconnect()).ConfigureAwait(true);
            Log(r.Ok ? "Disconnected." : "Disconnect: " + r.ErrorLine);
            await RefreshStatusAsync().ConfigureAwait(true);
        }
        finally { SetBusy(false); }
    }

    private void StopLinkWatch()
    {
        try { _watchCts?.Cancel(); } catch { }
        try { _watchCts?.Dispose(); } catch { }
        _watchCts = null;
        _activeEndpoint = null;
    }

    private void StartLinkWatch(string? endpoint, string protocol, WarpCli.CensorshipOptions opt)
    {
        StopLinkWatch();
        _activeEndpoint = endpoint;
        _activeProtocol = protocol;
        _lastOpt = opt;
        _watchCts = new CancellationTokenSource();
        CancellationToken ct = _watchCts.Token;
        _ = Task.Run(async () =>
        {
            try { await LinkWatchLoopAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                try
                {
                    if (!IsDisposed)
                        BeginInvoke(() => Log("Health watch stopped: " + ex.Message));
                }
                catch { }
            }
        }, ct);
        Log("Health watch started — will rotate endpoints if quality drops or times out.");
    }

    private async Task LinkWatchLoopAsync(CancellationToken ct)
    {
        int fails = 0;
        // First check after ~25s — late DPI timeouts often show up here.
        await Task.Delay(25_000, ct).ConfigureAwait(false);

        while (!ct.IsCancellationRequested)
        {
            if (!WarpCli.IsConnected(WarpCli.Status()))
            {
                fails++;
                UiLog($"Health: tunnel not Connected (fail {fails}/2).");
            }
            else
            {
                var progress = new Progress<string>(UiLog);
                var q = await WarpLinkQuality.EvaluateHealthAsync(progress, ct).ConfigureAwait(false);
                if (q.Ok)
                {
                    fails = 0;
                    UiLog($"Health: OK (med={q.MedianRttMs}ms dl={q.DownloadMs}ms).");
                }
                else
                {
                    fails++;
                    UiLog($"Health: WEAK — {q.Reason} (fail {fails}/2).");
                }
            }

            if (fails >= 2)
            {
                fails = 0;
                UiLog("Health: rotating to another address…");
                await RotateFromWatchAsync().ConfigureAwait(false);
                return; // RotateUi restarts a fresh watch on success
            }

            await Task.Delay(20_000, ct).ConfigureAwait(false);
        }
    }

    private void UiLog(string msg)
    {
        try
        {
            if (IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(() => Log(msg));
                return;
            }
            Log(msg);
        }
        catch { }
    }

    private async Task RotateFromWatchAsync()
    {
        if (_busy) return;
        string? from = _activeEndpoint;
        string proto = _activeProtocol;
        var opt = _lastOpt ?? new WarpCli.CensorshipOptions
        {
            Enabled = true,
            DpiAssist = false,
            LowLatency = true,
            RequireLinkQuality = true,
            MaxConnectAttempts = 10,
        };

        var tcs = new TaskCompletionSource<bool>();
        void Work() => _ = RotateUiAsync(from, proto, opt, tcs);
        if (InvokeRequired) BeginInvoke(Work);
        else Work();
        await tcs.Task.ConfigureAwait(false);
    }

    private async Task RotateUiAsync(
        string? from,
        string proto,
        WarpCli.CensorshipOptions opt,
        TaskCompletionSource<bool> done)
    {
        if (_busy)
        {
            done.TrySetResult(false);
            return;
        }
        SetBusy(true);
        try
        {
            using var rotateCts = new CancellationTokenSource(TimeSpan.FromMinutes(4));
            var progress = new Progress<string>(msg =>
            {
                Log(msg);
                WarpSessionLog.Step("ui", msg);
            });

            WarpSessionLog.BeginSession("health-rotate",
                new Dictionary<string, object?>
                {
                    ["from"] = from,
                    ["protocol"] = proto,
                });

            var (ok, message, ep, usedProtocol) = await WarpCli.RotateToNextEndpointAsync(
                from, proto, opt with { DpiAssist = false }, progress, rotateCts.Token).ConfigureAwait(true);

            Log(message);
            WarpSessionLog.End(ok, message,
                new Dictionary<string, object?> { ["endpoint"] = ep, ["protocol"] = usedProtocol });

            if (ok)
            {
                _activeEndpoint = ep;
                _activeProtocol = usedProtocol;
                if (ep != null)
                {
                    if (!_cmbEndpoint.Items.Contains(ep))
                        _cmbEndpoint.Items.Insert(1, ep);
                    _cmbEndpoint.Text = ep;
                }
                await RefreshStatusAsync().ConfigureAwait(true);
                StartLinkWatch(ep, usedProtocol, opt);
            }
            else
            {
                Log("Failover failed — tunnel may be down. Press Connect to rescan.");
                _activeEndpoint = null;
            }
            done.TrySetResult(ok);
        }
        catch (OperationCanceledException)
        {
            WarpSessionLog.End(false, "rotate cancelled");
            done.TrySetResult(false);
        }
        catch (Exception ex)
        {
            Log("Rotate error: " + ex.Message);
            WarpSessionLog.End(false, "rotate exception: " + ex.Message);
            done.TrySetResult(false);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task ConnectAsync()
    {
        if (_busy) return;
        if (!WarpCli.IsInstalled())
        {
            CustomMessageBox.Show(this,
                "Install Cloudflare WARP first (includes warp-cli), then reopen this window.",
                "WARP required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            OpenLinks.OpenUrl("https://one.one.one.one/");
            return;
        }

        SetBusy(true);
        StopLinkWatch();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var progress = new Progress<string>(msg =>
        {
            Log(msg);
            WarpSessionLog.Step("ui", msg);
        });
        bool sessionEnded = false;
        try
        {
            // Fresh preflight every connect — start service, warn on VPN / existing WARP
            var pre = await WarpPreflight.RunAsync(progress, _cts.Token).ConfigureAwait(true);
            foreach (string w in pre.Warnings) Log("WARN: " + w);

            if (!pre.ServiceRunning)
            {
                CustomMessageBox.Show(this, pre.Warnings.FirstOrDefault() ?? "WARP service not running.",
                    "WARP service", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (pre.OtherVpnLikely)
            {
                var dr = CustomMessageBox.Show(this,
                    "Another VPN/tunnel looks active (" + pre.OtherVpnHint + ").\n\n" +
                    "Continue anyway? (usually causes conflicts)",
                    "VPN conflict", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (dr != DialogResult.Yes) return;
            }

            if (pre.AlreadyOnWarp)
                Log("Already on WARP — will disconnect and reconnect with GeoHide settings.");

            bool censorship = _chkCensorship.Checked;
            bool dpi = _chkDpiAssist.Checked;
            bool lowLatency = _chkLowLatency.Checked;

            // Iran → force censorship path
            if (pre.LikelyIran)
            {
                censorship = true;
                dpi = true;
            }

            if (!censorship && !pre.LikelyIran)
                Log("Fast path: censorship off.");

            SyncOptionConflicts(fromUser: false);
            string protocol = censorship ? "MASQUE" : (_cmbProtocol.SelectedItem?.ToString() ?? "MASQUE");

            string selected = _cmbEndpoint.Text.Trim();
            bool hasSpecific = !string.IsNullOrEmpty(selected) && !selected.StartsWith("(");

            WarpSessionLog.BeginSession("connect",
                new Dictionary<string, object?>
                {
                    ["censorship"] = censorship,
                    ["dpi"] = dpi,
                    ["lowLatency"] = lowLatency,
                    ["likelyIran"] = pre.LikelyIran,
                    ["service"] = pre.ServiceRunning,
                    ["otherVpn"] = pre.OtherVpnLikely,
                    ["alreadyWarp"] = pre.AlreadyOnWarp,
                    ["protocol"] = protocol,
                    ["endpoint"] = hasSpecific ? selected : "(scan/default)",
                });
            Log("Session log → " + WarpSessionLog.CurrentLogPath);

            var opt = new WarpCli.CensorshipOptions
            {
                Enabled = censorship,
                DpiAssist = dpi,
                LowLatency = lowLatency,
                TryWireGuardUpgrade = false,
                ApplyIranExcludes = false,
                RequireLinkQuality = true,
                MaxCandidates = censorship ? 48 : 24,
                // More attempts: quality rejects should still leave room to try other addresses
                MaxConnectAttempts = censorship ? 12 : 8,
                CidrSamplePerRange = censorship ? 12 : 8,
                ProbeTimeoutMs = 350,
            };
            _lastOpt = opt;

            // One Connect path: censorship/empty → scan; otherwise use the Endpoint box.
            List<string>? endpointList;
            if (censorship || !hasSpecific)
            {
                endpointList = null;
                Log(censorship
                    ? "Connect: scan → quality gate → failover if weak…"
                    : "Connecting with Cloudflare default…");
            }
            else
            {
                endpointList = new List<string> { selected };
                Log($"Connecting {selected}…");
            }

            var (ok, message, ep, usedProtocol) = await WarpCli.TryConnectWithFallbackAsync(
                endpointList, protocol, progress, _cts.Token, opt).ConfigureAwait(true);
            Log(message);
            WarpSessionLog.End(ok, message,
                new Dictionary<string, object?>
                {
                    ["endpoint"] = ep,
                    ["protocol"] = usedProtocol,
                });
            sessionEnded = true;
            if (!string.IsNullOrEmpty(WarpSessionLog.CurrentLogPath))
                Log("Full diagnostics: " + WarpSessionLog.CurrentLogPath);
            if (!string.IsNullOrEmpty(usedProtocol) &&
                !string.Equals(usedProtocol, _cmbProtocol.SelectedItem?.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                int idx = _cmbProtocol.Items.IndexOf(usedProtocol);
                if (idx >= 0) _cmbProtocol.SelectedIndex = idx;
            }
            if (ep != null)
            {
                if (!_cmbEndpoint.Items.Contains(ep))
                    _cmbEndpoint.Items.Insert(1, ep);
                _cmbEndpoint.Text = ep;
            }
            await RefreshStatusAsync().ConfigureAwait(true);
            if (ok)
            {
                StartLinkWatch(ep, usedProtocol, opt);
                if (_chkImportAfterConnect.Checked)
                    await ImportSelectedPresetAsync(silent: true).ConfigureAwait(true);
                CustomMessageBox.Show(this,
                    message + "\n\nHealth watch is on — weak/timeout links auto-rotate to other addresses.\nMinimize anytime — WARP stays connected.\n\nLog: " +
                    (WarpSessionLog.CurrentLogPath ?? "(see UserData/GeoHideLogs)"),
                    "GeoHide", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                CustomMessageBox.Show(this,
                    message + "\n\nLog: " + (WarpSessionLog.CurrentLogPath ?? "(see UserData/GeoHideLogs)"),
                    "GeoHide", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        catch (OperationCanceledException)
        {
            Log("Cancelled.");
            if (!sessionEnded)
                WarpSessionLog.End(false, "cancelled");
            sessionEnded = true;
            try
            {
                await Task.Run(() =>
                {
                    WarpCli.Disconnect();
                    WarpCli.ResetEndpoint();
                }).ConfigureAwait(true);
                await WarpDpiAssist.StopAsync().ConfigureAwait(true);
            }
            catch { }
        }
        catch (Exception ex)
        {
            Log("Error: " + ex.Message);
            if (!sessionEnded)
                WarpSessionLog.End(false, "exception: " + ex.Message);
            sessionEnded = true;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task ImportSelectedPresetAsync(bool silent)
    {
        try
        {
            var kind = SelectedPresetKind();
            var (ok, message) = await GeoHidePresets.ImportIntoRulesAsync(kind, merge: true).ConfigureAwait(true);
            Log(message);
            if (Application.OpenForms["FormMain"] is FormMain main)
                await main.EnableRulesSettingAndReapplyAsync().ConfigureAwait(true);
            if (!silent)
                CustomMessageBox.Show(this, message, ok ? "Rules" : "Rules error",
                    MessageBoxButtons.OK, ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }
        catch (Exception ex)
        {
            Log("Preset import: " + ex.Message);
        }
    }
}

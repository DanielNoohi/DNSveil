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
    private readonly CustomButton _btnAuto = new();
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
    private bool _busy;
    private bool _reloadingEndpoints;

    public FormGeoHideWarp()
    {
        Text = "GeoHide — Cloudflare WARP";
        ClientSize = new Size(640, 590);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        MinimizeBox = true;
        ShowInTaskbar = true;
        ShowIcon = true;
        BackColor = Color.FromArgb(32, 32, 32);
        ForeColor = Color.WhiteSmoke;
        Font = new Font("Segoe UI", 9F);

        SuspendLayout();

        _lblHelp.AutoSize = false;
        _lblHelp.Location = new Point(12, 10);
        _lblHelp.Size = new Size(616, 40);
        _lblHelp.Text = "Uses official Cloudflare WARP (warp-cli). Under Iranian DPI: enable Censorship mode + DPI assist (TLS fragment), then Auto-find. Destinations see a Cloudflare exit IP — not your ISP.";

        _lblStatus.AutoSize = true;
        _lblStatus.Location = new Point(12, 56);
        _lblStatus.Text = "Status: …";
        _lblIp.AutoSize = true;
        _lblIp.Location = new Point(260, 56);
        _lblIp.Text = "Public IP: …";

        StyleBtn(_btnRefresh, "Refresh", new Point(520, 50), 90);
        _btnRefresh.Click += async (_, _) => await RefreshStatusAsync();

        _lblEp.AutoSize = true;
        _lblEp.Location = new Point(12, 90);
        _lblEp.Text = "Endpoint";
        _cmbEndpoint.Location = new Point(80, 86);
        _cmbEndpoint.Size = new Size(280, 28);
        _cmbEndpoint.DropDownStyle = ComboBoxStyle.DropDown;
        StyleCombo(_cmbEndpoint);

        _lblProto.AutoSize = true;
        _lblProto.Location = new Point(380, 90);
        _lblProto.Text = "Protocol";
        _cmbProtocol.Location = new Point(440, 86);
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

        StyleBtn(_btnConnect, "Connect", new Point(12, 126), 90);
        StyleBtn(_btnDisconnect, "Disconnect", new Point(108, 126), 90);
        StyleBtn(_btnAuto, "Auto-find", new Point(204, 126), 90);
        StyleBtn(_btnCancel, "Cancel", new Point(300, 126), 70);
        StyleBtn(_btnMinimize, "Minimize", new Point(376, 126), 80);
        StyleBtn(_btnInstall, "Get WARP…", new Point(462, 126), 90);
        StyleBtn(_btnHelp, "Help", new Point(558, 126), 64);
        _btnCancel.Enabled = false;
        _btnConnect.Click += async (_, _) => await ConnectAsync(auto: false);
        _btnDisconnect.Click += async (_, _) => await DisconnectAsync();
        _btnAuto.Click += async (_, _) => await ConnectAsync(auto: true);
        _btnCancel.Click += (_, _) => { try { _cts?.Cancel(); } catch { } };
        _btnMinimize.Click += (_, _) => { WindowState = FormWindowState.Minimized; };
        _btnInstall.Click += (_, _) => OpenLinks.OpenUrl("https://one.one.one.one/");
        _btnHelp.Click += (_, _) => CustomMessageBox.Show(this, GeoHidePresets.HelpSummary, "GeoHide help",
            MessageBoxButtons.OK, MessageBoxIcon.Information);

        _chkCensorship.AutoSize = true;
        _chkCensorship.Location = new Point(12, 162);
        _chkCensorship.Text = "Censorship mode (Iran) — IRCF + CF scan, MASQUE (needed under DPI)";
        _chkCensorship.ForeColor = Color.WhiteSmoke;
        _chkCensorship.BackColor = Color.Transparent;
        _chkCensorship.Checked = true;
        _chkCensorship.CheckedChanged += (_, _) => SyncOptionConflicts(fromUser: true);

        _chkDpiAssist.AutoSize = true;
        _chkDpiAssist.Location = new Point(12, 186);
        _chkDpiAssist.Text = "DPI assist — GoodbyeDPI only during connect (auto-stopped after)";
        _chkDpiAssist.ForeColor = Color.WhiteSmoke;
        _chkDpiAssist.BackColor = Color.Transparent;
        _chkDpiAssist.Checked = true;

        _chkLowLatency.AutoSize = true;
        _chkLowLatency.Location = new Point(12, 210);
        _chkLowLatency.Text = "Low latency (gaming) — tunnel_only before connect + Iran excludes (keeps proven tunnel)";
        _chkLowLatency.ForeColor = Color.WhiteSmoke;
        _chkLowLatency.BackColor = Color.Transparent;
        _chkLowLatency.Checked = true;
        _chkLowLatency.CheckedChanged += (_, _) => SyncOptionConflicts(fromUser: true);

        _lblPreset.AutoSize = true;
        _lblPreset.Location = new Point(12, 242);
        _lblPreset.Text = "Rules preset";
        _cmbPreset.Location = new Point(100, 238);
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
        StyleBtn(_btnImportPreset, "Import into Rules", new Point(372, 236), 150);
        _btnImportPreset.Click += async (_, _) => await ImportSelectedPresetAsync(silent: false);

        _chkImportAfterConnect.AutoSize = true;
        _chkImportAfterConnect.Location = new Point(12, 272);
        _chkImportAfterConnect.Text = "Also import selected preset after successful connect";
        _chkImportAfterConnect.ForeColor = Color.WhiteSmoke;
        _chkImportAfterConnect.BackColor = Color.Transparent;
        _chkImportAfterConnect.Checked = false;

        _log.Location = new Point(12, 300);
        _log.Size = new Size(616, 230);
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
            _btnConnect, _btnDisconnect, _btnAuto, _btnCancel, _btnMinimize, _btnInstall, _btnHelp,
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
                "Disconnect it before GeoHide Auto-find, or WARP will fight it (slow/fail/high latency).",
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
        _btnAuto.Enabled = !busy;
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

    private async Task RefreshStatusAsync()
    {
        if (!WarpCli.IsInstalled())
        {
            _lblStatus.Text = "Status: WARP not installed";
            _lblIp.Text = "Public IP: —";
            return;
        }
        if (!WarpCli.IsServiceRunning())
            _lblStatus.Text = "Status: WARP service not running";
        var st = await Task.Run(() => WarpCli.Status()).ConfigureAwait(true);
        if (WarpCli.IsServiceRunning())
            _lblStatus.Text = "Status: " + WarpCli.ParseStatus(st);
        var info = await WarpCli.FetchPublicIpInfoAsync().ConfigureAwait(true);
        string ipPart = info.Ip ?? "unavailable";
        string warpPart = info.WarpOn == true ? " (warp=on)" : info.WarpOn == false ? " (warp=off)" : "";
        string locPart = string.IsNullOrEmpty(info.Loc) ? "" : $" [{info.Loc}]";
        _lblIp.Text = "Public IP: " + ipPart + warpPart + locPart;
    }

    private async Task DisconnectAsync()
    {
        if (_busy) return;
        SetBusy(true);
        try
        {
            var r = await Task.Run(() => WarpCli.Disconnect()).ConfigureAwait(true);
            Log(r.Ok ? "Disconnected." : "Disconnect: " + r.ErrorLine);
            await RefreshStatusAsync().ConfigureAwait(true);
        }
        finally { SetBusy(false); }
    }

    private async Task ConnectAsync(bool auto)
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

            // Option conflict resolution for this attempt
            bool censorship = _chkCensorship.Checked || auto;
            bool dpi = _chkDpiAssist.Checked;
            bool lowLatency = _chkLowLatency.Checked;

            // If user is in Iran, force censorship path for Auto-find
            if (auto && pre.LikelyIran)
            {
                censorship = true;
                dpi = true;
            }

            // Outside Iran + not censorship: skip heavy scan
            if (!censorship && !pre.LikelyIran)
                Log("Fast path: censorship off.");

            SyncOptionConflicts(fromUser: false);
            string protocol = censorship ? "MASQUE" : (_cmbProtocol.SelectedItem?.ToString() ?? "MASQUE");

            WarpSessionLog.BeginSession(auto ? "auto-find" : "connect",
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
                });
            Log("Session log → " + WarpSessionLog.CurrentLogPath);

            var opt = new WarpCli.CensorshipOptions
            {
                Enabled = censorship,
                DpiAssist = dpi,
                LowLatency = lowLatency,
                // WG upgrade under DPI rarely works and made Auto-find feel stuck — off by default
                TryWireGuardUpgrade = false,
                ApplyIranExcludes = lowLatency,
                MaxCandidates = censorship ? 48 : 24,
                MaxConnectAttempts = censorship ? 8 : 6,
                CidrSamplePerRange = censorship ? 12 : 8,
                ProbeTimeoutMs = 350,
            };

            IEnumerable<string>? endpoints;
            if (auto)
            {
                endpoints = null;
                Log("Auto-find (fast): service OK → DPI → MASQUE IRCF/CF probe → connect…");
            }
            else
            {
                string selected = _cmbEndpoint.Text.Trim();
                if (string.IsNullOrEmpty(selected) || selected.StartsWith("("))
                {
                    endpoints = censorship ? null : new List<string>();
                    Log(censorship ? "Connect (censorship scan)…" : "Connecting with Cloudflare default…");
                }
                else
                {
                    endpoints = new[] { selected };
                }
            }

            List<string>? endpointList = endpoints?.ToList();
            if (censorship && (endpointList == null || endpointList.Count == 0))
                endpointList = null;

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
                !usedProtocol.Equals(_cmbProtocol.SelectedItem?.ToString(), StringComparison.OrdinalIgnoreCase))
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
                if (_chkImportAfterConnect.Checked)
                    await ImportSelectedPresetAsync(silent: true).ConfigureAwait(true);
                CustomMessageBox.Show(this,
                    message + "\n\nMinimize anytime — WARP stays connected.\n\nLog: " +
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

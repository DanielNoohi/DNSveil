using CustomControls;
using MsmhToolsClass;
using MsmhToolsWinFormsClass.Themes;
using SecureDNSClient.GeoHide;
using System.Diagnostics;

namespace SecureDNSClient;

/// <summary>
/// GeoHide via official Cloudflare WARP (warp-cli).
/// Automatic protocol recovery and read-only diagnostics; country verification is a separate strict option.
/// </summary>
public class FormGeoHideWarp : Form
{
    private readonly Panel _pnlHeader = new();
    private readonly Label _lblBrand = new();
    private readonly Label _lblTagline = new();
    private readonly Label _lblStatus = new();
    private readonly Label _lblIp = new();
    private readonly Label _lblHealth = new();
    private readonly Label _lblEp = new();
    private readonly Label _lblProto = new();
    private readonly ComboBox _cmbEndpoint = new();
    private readonly ComboBox _cmbProtocol = new();
    private readonly CustomButton _btnRefresh = new();
    private readonly CustomButton _btnTest = new();
    private readonly CustomButton _btnConnect = new();
    private readonly CustomButton _btnDisconnect = new();
    private readonly CustomButton _btnCancel = new();
    private readonly CustomButton _btnInstall = new();
    private readonly CustomButton _btnHelp = new();
    private readonly CustomButton _btnLogs = new();
    private readonly CustomButton _btnMinimize = new();
    private readonly TextBox _log = new();
    private readonly CheckBox _chkCensorship = new();
    private readonly CheckBox _chkDpiAssist = new();
    private readonly CheckBox _chkLowLatency = new();
    private readonly CheckBox _chkRegionalExit = new();
    private readonly ToolTip _tips = new();
    private readonly CancellationTokenSource _lifetime = new();
    private bool _closing;
    private CancellationTokenSource? _cts;
    private CancellationTokenSource? _watchCts;
    private string? _activeEndpoint;
    private string _activeProtocol = "MASQUE";
    private WarpCli.CensorshipOptions? _lastOpt;
    private bool _busy;
    private bool _reloadingEndpoints;
    private string _lastHealthSummary = "Health: idle";

    public FormGeoHideWarp()
    {
        Text = "DNSveil GeoHide";
        ClientSize = new Size(720, 560);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.Sizable;
        MaximizeBox = true;
        MinimizeBox = true;
        ShowInTaskbar = true;
        ShowIcon = true;
        MinimumSize = new Size(680, 500);
        Font = new Font("Segoe UI", 9F);

        BuildLayout();
        Theme.LoadTheme(this, Theme.Themes.Dark);
        ApplyHeaderStyle();

        ReloadEndpointList();
        SyncOptionConflicts(fromUser: false);

        Shown += async (_, _) =>
        {
            using var operation = BeginOperation();
            try { await RunStartupPreflightAsync(operation.Token).ConfigureAwait(true); }
            catch (OperationCanceledException) { Log("Startup check cancelled."); }
            catch (Exception ex) { Log("Startup check failed: " + ex.Message); }
            finally { EndOperation(operation); }
        };
        FormClosing += (_, e) =>
        {
            // Keep the window alive until cancellation and network cleanup finish.
            // Reopening it cannot start another operation while the old one is exiting.
            e.Cancel = _busy;
            if (_busy) _lblStatus.Text = "Status: cancelling before close…";
            _closing = true;
            _lifetime.Cancel();
            StopLinkWatch();
            try { _cts?.Cancel(); } catch { }
            if (!_busy)
            {
                _tips.Dispose();
                _lifetime.Dispose();
            }
        };
    }

    private void BuildLayout()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            Padding = new Padding(12),
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 108)); // header
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));  // endpoint row
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));  // actions
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 106));  // options
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // log

        // ---- Header status strip ----
        _pnlHeader.Dock = DockStyle.Fill;
        _pnlHeader.Padding = new Padding(14, 10, 14, 10);

        _lblBrand.AutoSize = true;
        _lblBrand.Text = "GeoHide";
        _lblBrand.Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold);
        _lblBrand.Location = new Point(14, 8);

        _lblTagline.AutoSize = true;
        _lblTagline.Text = "WARP connection · country and service checks";
        _lblTagline.Location = new Point(14, 38);

        _lblStatus.AutoSize = false;
        _lblStatus.Text = "Status: …";
        _lblStatus.AutoEllipsis = true;
        _lblStatus.SetBounds(14, 62, 520, 18);

        _lblIp.AutoSize = false;
        _lblIp.Text = "Public IP: …";
        _lblIp.AutoEllipsis = true;
        _lblIp.SetBounds(14, 80, 520, 18);

        _lblHealth.AutoSize = false;
        _lblHealth.Text = _lastHealthSummary;
        _lblHealth.AutoEllipsis = true;
        _lblHealth.TextAlign = ContentAlignment.TopRight;
        _lblHealth.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _lblHealth.SetBounds(540, 62, 150, 36);

        StyleBtn(_btnRefresh, "Refresh", 88);
        _btnRefresh.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _btnRefresh.Location = new Point(600, 12);
        _btnRefresh.Click += async (_, _) =>
        {
            try { await RefreshStatusAsync(fromUser: true).ConfigureAwait(true); }
            catch (Exception ex) { Log("Refresh error: " + ex.Message); }
        };

        StyleBtn(_btnTest, "Test connection", 126);
        _btnTest.Location = new Point(468, 12);
        _btnTest.Click += async (_, _) => await TestConnectionAsync();

        _pnlHeader.Controls.AddRange(new Control[]
        {
            _lblBrand, _lblTagline, _lblStatus, _lblIp, _lblHealth, _btnRefresh, _btnTest
        });
        _pnlHeader.Resize += (_, _) =>
        {
            int w = Math.Max(200, _pnlHeader.ClientSize.Width - 28 - 160);
            _lblStatus.Width = w;
            _lblIp.Width = w;
            _lblHealth.Left = _pnlHeader.ClientSize.Width - 14 - _lblHealth.Width;
            _btnRefresh.Left = _pnlHeader.ClientSize.Width - 14 - _btnRefresh.Width;
            _btnTest.Left = _btnRefresh.Left - _btnTest.Width - 6;
        };

        // ---- Endpoint / protocol ----
        var rowEp = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 4,
            RowCount = 1,
        };
        rowEp.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 72));
        rowEp.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        rowEp.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 64));
        rowEp.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));

        _lblEp.Text = "Endpoint";
        _lblEp.Dock = DockStyle.Fill;
        _lblEp.TextAlign = ContentAlignment.MiddleLeft;
        _cmbEndpoint.Dock = DockStyle.Fill;
        _cmbEndpoint.DropDownStyle = ComboBoxStyle.DropDown;
        StyleCombo(_cmbEndpoint);

        _lblProto.Text = "Protocol";
        _lblProto.Dock = DockStyle.Fill;
        _lblProto.TextAlign = ContentAlignment.MiddleLeft;
        _cmbProtocol.Dock = DockStyle.Fill;
        _cmbProtocol.DropDownStyle = ComboBoxStyle.DropDownList;
        StyleCombo(_cmbProtocol);
        _cmbProtocol.Items.AddRange(new object[] { "Auto", "MASQUE", "WireGuard" });
        _cmbProtocol.SelectedIndexChanged += (_, _) =>
        {
            if (_reloadingEndpoints) return;
            ReloadEndpointList();
        };
        _cmbProtocol.SelectedIndex = 0;

        rowEp.Controls.Add(_lblEp, 0, 0);
        rowEp.Controls.Add(_cmbEndpoint, 1, 0);
        rowEp.Controls.Add(_lblProto, 2, 0);
        rowEp.Controls.Add(_cmbProtocol, 3, 0);

        // ---- Actions ----
        var rowAct = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Padding = new Padding(0, 4, 0, 0),
        };
        StyleBtn(_btnConnect, "Connect", 100);
        StyleBtn(_btnDisconnect, "Disconnect", 96);
        StyleBtn(_btnCancel, "Cancel", 72);
        StyleBtn(_btnMinimize, "Minimize", 84);
        StyleBtn(_btnInstall, "Get WARP…", 96);
        StyleBtn(_btnLogs, "Open logs", 88);
        StyleBtn(_btnHelp, "Help", 64);
        _btnCancel.Enabled = false;

        _btnConnect.Click += async (_, _) => await ConnectAsync();
        _btnDisconnect.Click += async (_, _) => await DisconnectAsync();
        _btnCancel.Click += (_, _) =>
        {
            _btnCancel.Enabled = false;
            _btnCancel.Text = "Cancelling…";
            Log("Cancellation requested — finishing cleanup…");
            try { _cts?.Cancel(); } catch { }
        };
        _btnMinimize.Click += (_, _) => { WindowState = FormWindowState.Minimized; };
        _btnInstall.Click += (_, _) => OpenLinks.OpenUrl("https://one.one.one.one/");
        _btnHelp.Click += (_, _) => CustomMessageBox.Show(this, GeoHidePresets.HelpSummary, "GeoHide help",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
        _btnLogs.Click += (_, _) => OpenLogsFolder();

        rowAct.Controls.AddRange(new Control[]
        {
            _btnConnect, _btnDisconnect, _btnCancel, _btnMinimize, _btnInstall, _btnLogs, _btnHelp
        });

        // ---- Options ----
        var rowOpt = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(0, 2, 0, 0),
        };

        _chkCensorship.AutoSize = true;
        _chkCensorship.Text = "Iran mode";
        _chkCensorship.Checked = true;
        _chkCensorship.CheckedChanged += (_, _) => SyncOptionConflicts(fromUser: true);
        _tips.SetToolTip(_chkCensorship, "Prefer MASQUE over TCP, with optional DPI assistance if its handshake fails.");

        _chkDpiAssist.AutoSize = true;
        _chkDpiAssist.Text = "DPI assist";
        _chkDpiAssist.Checked = true;
        _tips.SetToolTip(_chkDpiAssist, "GoodbyeDPI during connect: fake TTL / wrong-seq packets (survives TCP reassembly) then Light fragment. Auto-stopped after connect.");

        _chkLowLatency.AutoSize = true;
        _chkLowLatency.Text = "Low latency";
        _chkLowLatency.Checked = true;
        _chkLowLatency.CheckedChanged += (_, _) => SyncOptionConflicts(fromUser: true);
        _tips.SetToolTip(_chkLowLatency, "Stop DPI after connect; keep WARP DNS; Iran excludes off for stability.");

        _chkRegionalExit.AutoSize = true;
        _chkRegionalExit.Text = "Require exit outside Iran (strict; may not connect)";
        _tips.SetToolTip(_chkRegionalExit, "Rejects working Iranian exits. Tries both tunnel protocols for up to 2 minutes. Uncheck for normal connectivity; this cannot select a country. Requires verified IPv4 and IPv6 countries outside IR. WARP may never provide one. Not a kill switch or guarantee of service access.");
        rowOpt.Controls.AddRange(new Control[] { _chkCensorship, _chkDpiAssist, _chkLowLatency, _chkRegionalExit });

        // ---- Log ----
        _log.Dock = DockStyle.Fill;
        _log.Multiline = true;
        _log.ScrollBars = ScrollBars.Vertical;
        _log.ReadOnly = true;
        _log.BorderStyle = BorderStyle.FixedSingle;
        _log.Font = new Font("Consolas", 9F);

        root.Controls.Add(_pnlHeader, 0, 0);
        root.Controls.Add(rowEp, 0, 1);
        root.Controls.Add(rowAct, 0, 2);
        root.Controls.Add(rowOpt, 0, 3);
        root.Controls.Add(_log, 0, 4);

        Controls.Add(root);
    }

    private void ApplyHeaderStyle()
    {
        _pnlHeader.BackColor = Color.FromArgb(28, 36, 48);
        _lblBrand.ForeColor = Color.White;
        _lblBrand.BackColor = Color.Transparent;
        _lblTagline.ForeColor = Color.FromArgb(160, 190, 220);
        _lblTagline.BackColor = Color.Transparent;
        _lblStatus.ForeColor = Color.WhiteSmoke;
        _lblStatus.BackColor = Color.Transparent;
        _lblIp.ForeColor = Color.Gainsboro;
        _lblIp.BackColor = Color.Transparent;
        _lblHealth.ForeColor = Color.FromArgb(120, 200, 160);
        _lblHealth.BackColor = Color.Transparent;
        _btnRefresh.BorderColor = Color.DodgerBlue;
    }

    private void OpenLogsFolder()
    {
        try
        {
            string? path = WarpSessionLog.CurrentLogPath;
            string dir = !string.IsNullOrEmpty(path)
                ? Path.GetDirectoryName(path)!
                : Path.Combine(SecureDNS.UserDataDirPath, "GeoHideLogs");
            FileDirectory.CreateEmptyDirectory(dir);
            Process.Start(new ProcessStartInfo
            {
                FileName = dir,
                UseShellExecute = true,
            });
            Log("Opened log folder: " + dir);
        }
        catch (Exception ex)
        {
            Log("Open logs failed: " + ex.Message);
        }
    }

    private void SyncOptionConflicts(bool fromUser)
    {
        if (_chkCensorship.Checked && fromUser && !_chkDpiAssist.Checked)
            _chkDpiAssist.Checked = true;
    }

    private async Task RunStartupPreflightAsync(CancellationToken ct)
    {
        if (!WarpCli.IsInstalled())
        {
            Log("warp-cli NOT found — click Get WARP… and install Cloudflare WARP.");
            await RefreshStatusAsync().ConfigureAwait(true);
            return;
        }

        Log("Running preflight (service / Iran IP / VPN conflict)…");
        var progress = new Progress<string>(Log);
        var report = await WarpCli.RunOperationAsync(() => WarpPreflight.RunAsync(progress, ct), ct).ConfigureAwait(true);
        ct.ThrowIfCancellationRequested();
        foreach (string n in report.Notes) Log(n);
        foreach (string w in report.Warnings) Log("WARN: " + w);

        if (report.LikelyIran)
        {
            Log("Iran detected — leave Iran mode on for DPI scan, or uncheck it for a simple Cloudflare default connect.");
            if (string.Equals(_cmbProtocol.SelectedItem?.ToString(), "WireGuard", StringComparison.OrdinalIgnoreCase))
                Log("WireGuard selected. If UDP is blocked, switch Protocol to MASQUE.");
        }
        else if (!report.AlreadyOnWarp && !string.IsNullOrEmpty(report.Loc))
        {
            Log("Tip: not in IR — uncheck Iran mode for a faster Connect.");
        }

        if (report.OtherVpnLikely)
        {
            Log("WARN: Another VPN/tunnel appears active (" + report.OtherVpnHint + "). Disconnect it before Connect.");
        }

        await RefreshStatusAsync().ConfigureAwait(true);
    }

    private static void StyleCombo(ComboBox c)
    {
        c.FlatStyle = FlatStyle.Flat;
    }

    private void ReloadEndpointList()
    {
        if (_reloadingEndpoints) return;
        _reloadingEndpoints = true;
        try
        {
            string protocol = _cmbProtocol.SelectedItem?.ToString() ?? "Auto";
            if (protocol == "Auto") protocol = "MASQUE";
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

    private static void StyleBtn(CustomButton b, string text, int width)
    {
        b.Text = text;
        b.Size = new Size(width, 30);
        b.Margin = new Padding(0, 0, 6, 0);
        b.BorderColor = Color.DodgerBlue;
        b.FlatStyle = FlatStyle.Flat;
        b.RoundedCorners = 5;
        b.SelectionColor = Color.LightBlue;
    }

    private void Log(string msg)
    {
        try
        {
            if (_closing || IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(() => Log(msg));
                return;
            }
            _log.AppendText($"{DateTime.Now:HH:mm:ss} {msg}{Environment.NewLine}");
        }
        catch { }
    }

    private void SetHealthUi(string summary, bool ok)
    {
        try
        {
            if (_closing || IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(() => SetHealthUi(summary, ok));
                return;
            }
            _lastHealthSummary = summary;
            _lblHealth.Text = summary;
            _lblHealth.ForeColor = ok
                ? Color.FromArgb(120, 200, 160)
                : Color.FromArgb(230, 160, 100);
        }
        catch { }
    }

    private CancellationTokenSource BeginOperation()
    {
        var operation = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        _cts = operation;
        _btnCancel.Text = "Cancel";
        SetBusy(true);
        return operation;
    }

    private void EndOperation(CancellationTokenSource operation)
    {
        if (ReferenceEquals(_cts, operation)) _cts = null;
        SetBusy(false);
        if (_closing && !IsDisposed) BeginInvoke(new Action(Close));
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        if (_closing || IsDisposed) return;
        _btnConnect.Enabled = !busy;
        _btnDisconnect.Enabled = !busy;
        _btnRefresh.Enabled = !busy;
        _btnTest.Enabled = !busy;
        _btnCancel.Enabled = busy;
        _cmbEndpoint.Enabled = !busy;
        _cmbProtocol.Enabled = !busy;
        _chkCensorship.Enabled = !busy;
        _chkDpiAssist.Enabled = !busy;
        _chkLowLatency.Enabled = !busy;
        _chkRegionalExit.Enabled = !busy;
        _btnMinimize.Enabled = true;
        _btnLogs.Enabled = true;
    }

    private async Task RefreshStatusAsync(bool fromUser = false)
    {
        if (_closing || (fromUser && _busy)) return;
        using var refreshOperation = fromUser ? BeginOperation() : null;
        CancellationToken ct = (_cts ?? _lifetime).Token;
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

            if (fromUser && !WarpCli.IsServiceRunning())
            {
                _lblStatus.Text = "Status: starting WARP service…";
                var (svcOk, svcMsg, _) = await WarpPreflight.EnsureWarpServiceAsync(
                    fromUser ? new Progress<string>(Log) : null, ct).ConfigureAwait(true);
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

            var st = await WarpCli.RunAsync(ct, "status").ConfigureAwait(true);
            string parsed = WarpCli.ParseStatus(st);
            if (!WarpCli.IsServiceRunning() && string.IsNullOrWhiteSpace(st.Combined))
                _lblStatus.Text = "Status: WARP service not running";
            else
                _lblStatus.Text = "Status: " + (string.IsNullOrWhiteSpace(parsed) ? "(empty)" : parsed);

            var info = await WarpCli.FetchPublicIpInfoAsync(6000, ct).ConfigureAwait(true);
            string ipPart = info.Ip ?? "unavailable";
            string warpPart = info.WarpOn == true ? " · warp=on" : info.WarpOn == false ? " · warp=off" : " · warp=?";
            string locPart = string.IsNullOrEmpty(info.Loc) ? "" : $" · {info.Loc}";
            string coloPart = string.IsNullOrEmpty(info.Colo) ? "" : $" · data center {info.Colo}";
            if (info.WarpOn == true && string.Equals(info.Loc, "IR", StringComparison.OrdinalIgnoreCase))
                Log("Exit country is still Iran. Connected does not mean regional restrictions are removed.");
            _lblIp.Text = "Public IP: " + ipPart + warpPart + locPart + coloPart;

            if (fromUser)
            {
                Log($"Refresh done — {parsed} | IP {ipPart}{warpPart}{locPart}{coloPart}" +
                    (string.IsNullOrEmpty(info.Error) ? "" : $" ({info.Error})"));
            }
        }
        catch (OperationCanceledException) when (fromUser) { Log("Refresh cancelled."); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            if (_closing) return;
            _lblStatus.Text = "Status: refresh failed";
            if (fromUser) Log("Refresh error: " + ex.Message);
            else throw;
        }
        finally
        {
            if (refreshOperation != null) EndOperation(refreshOperation);
        }
    }

    private async Task TestConnectionAsync()
    {
        if (_busy || _closing) return;
        using var operation = BeginOperation();
        try
        {
            var ct = operation.Token;
            Log("Connection test started. Public pages only; login, playback and gameplay are not tested.");
            var statusTask = WarpCli.RunAsync(ct, "status");
            var exitsTask = WarpExitCheck.FetchAsync(ct);
            var servicesTask = WarpDiagnostics.FetchAsync(ct);
            await Task.WhenAll(statusTask, exitsTask, servicesTask).ConfigureAwait(true);
            var reportLines = new List<string> { "DNSveil connection test — " + DateTimeOffset.Now.ToString("O"),
                "WARP: " + WarpCli.ParseStatus(await statusTask) };
            Log(reportLines[1]);
            var exits = await exitsTask;
            Log(exits.Summary);
            reportLines.Add(exits.Summary);
            foreach (var line in await servicesTask) { Log(line); reportLines.Add(line); }
            Log(exits.IsOutside("IR")
                ? "Both tested IP families report outside Iran. Service-specific restrictions remain unverified."
                : "Outside-Iran requirement not verified. A connected tunnel and a changed country are separate results.");
            reportLines.Add("No game, login or playback test was performed. Country observations are not proof of service access.");
            Log("Where Winds Meet: game connection not tested; a website response cannot verify gameplay.");
            string directory = Path.Combine(SecureDNS.UserDataDirPath, "GeoHideLogs");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, "connection-test-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8] + ".txt");
            await File.WriteAllLinesAsync(path, reportLines, ct).ConfigureAwait(true);
            Log("Saved connection report: " + path);
        }
        catch (OperationCanceledException) { Log("Connection test cancelled."); }
        catch (Exception ex) { Log("Connection test failed: " + ex.Message); }
        finally { EndOperation(operation); }
    }

    private async Task DisconnectAsync()
    {
        if (_busy || _closing) return;
        StopLinkWatch();
        using var operation = BeginOperation();
        try
        {
            var r = await WarpCli.RunAsync(operation.Token, "disconnect").ConfigureAwait(true);
            await WarpDpiAssist.StopAsync().ConfigureAwait(true);
            Log(r.Ok ? "Disconnected." : "Disconnect: " + r.ErrorLine);
            SetHealthUi("Health: idle", true);
            await RefreshStatusAsync().ConfigureAwait(true);
        }
        catch (OperationCanceledException) { Log("Disconnect cancelled."); }
        catch (Exception ex) { Log("Disconnect failed: " + ex.Message); }
        finally { EndOperation(operation); }
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
        if (_closing) return;
        StopLinkWatch();
        _activeEndpoint = endpoint;
        _activeProtocol = protocol;
        _lastOpt = opt;
        _watchCts = new CancellationTokenSource();
        CancellationToken ct = _watchCts.Token;
        SetHealthUi("Health: watching…", true);
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
        Log("Health watch started — rotates endpoints if quality drops.");
    }

    private async Task LinkWatchLoopAsync(CancellationToken ct)
    {
        int fails = 0;
        await Task.Delay(25_000, ct).ConfigureAwait(false);

        while (!ct.IsCancellationRequested)
        {
            if (_busy) { await Task.Delay(1000, ct).ConfigureAwait(false); continue; }
            if (_lastOpt?.TryExitOutsideIran == true)
            {
                var exit = await WarpExitCheck.FetchAsync(ct).ConfigureAwait(false);
                UiLog("Exit recheck: " + exit.Summary);
                if (!exit.IsOutside("IR"))
                {
                    if (_busy) continue;
                    ct.ThrowIfCancellationRequested();
                    await WarpCli.RunAsync(ct, "disconnect").ConfigureAwait(false);
                    SetHealthUi("Exit country changed or unverified — reconnect manually", false);
                    UiLog("WARP was asked to disconnect because the exit requirement is no longer verified. Normal Internet traffic is not blocked.");
                    return;
                }
            }
            if (!WarpCli.IsConnected(await WarpCli.RunAsync(ct, "status").ConfigureAwait(false)))
            {
                fails++;
                SetHealthUi($"Health: down ({fails}/2)", false);
                UiLog($"Health: tunnel not Connected (fail {fails}/2).");
            }
            else
            {
                var progress = new Progress<string>(UiLog);
                var q = await WarpLinkQuality.EvaluateHealthAsync(progress, ct).ConfigureAwait(false);
                if (q.Ok)
                {
                    fails = 0;
                    SetHealthUi($"Health: OK · {q.MedianRttMs} ms", true);
                    UiLog($"Health: OK (med={q.MedianRttMs}ms dl={q.DownloadMs}ms).");
                }
                else
                {
                    fails++;
                    SetHealthUi($"Health: weak ({fails}/2)", false);
                    UiLog($"Health: WEAK — {q.Reason} (fail {fails}/2).");
                }
            }

            if (fails >= 2)
            {
                fails = 0;
                SetHealthUi("Health: rotating…", false);
                UiLog("Health: rotating to another address…");
                await RotateFromWatchAsync(ct).ConfigureAwait(false);
                return;
            }

            await Task.Delay(20_000, ct).ConfigureAwait(false);
        }
    }

    private void UiLog(string msg)
    {
        try
        {
            if (IsDisposed) return;
            if (_closing || IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(() => Log(msg));
                return;
            }
            Log(msg);
        }
        catch { }
    }

    private async Task RotateFromWatchAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (_busy || _closing) return;
        string? from = _activeEndpoint;
        string proto = _activeProtocol;
        var opt = _lastOpt ?? new WarpCli.CensorshipOptions
        {
            Enabled = true,
            DpiAssist = true,
            LowLatency = true,
            RequireLinkQuality = false,
            MaxConnectAttempts = 10,
        };

        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Work() => _ = RotateUiAsync(from, proto, opt, tcs, ct);
        if (InvokeRequired) BeginInvoke(Work);
        else Work();
        await tcs.Task.WaitAsync(ct).ConfigureAwait(false);
    }

    private async Task RotateUiAsync(
        string? from,
        string proto,
        WarpCli.CensorshipOptions opt,
        TaskCompletionSource<bool> done,
        CancellationToken watchToken)
    {
        if (_busy || _closing || watchToken.IsCancellationRequested)
        {
            done.TrySetResult(false);
            return;
        }
        using var rotateCts = BeginOperation();
        using var watchCancellation = watchToken.Register(() => rotateCts.Cancel());
        rotateCts.CancelAfter(TimeSpan.FromMinutes(4));
        try
        {
            var progress = new Progress<string>(msg =>
            {
                Log(msg);
                WarpSessionLog.Step("ui", msg);
            });

            // Restart FakeTTL DPI for rotate under censorship — handshake often needs it again
            var rotateOpt = opt;
            if (opt.Enabled && opt.DpiAssist)
            {
                var (dpiOk, dpiMsg) = await WarpDpiAssist.StartProfileAsync(
                    MasqueDpiProfile.FakeTtl, progress).ConfigureAwait(true);
                Log(dpiMsg);
                if (!dpiOk) Log("Rotate continuing without DPI…");
            }
            else
            {
                rotateOpt = opt with { DpiAssist = false };
            }

            WarpSessionLog.BeginSession("health-rotate",
                new Dictionary<string, object?>
                {
                    ["from"] = from,
                    ["protocol"] = proto,
                });

            var (ok, message, ep, usedProtocol) = await WarpCli.RotateToNextEndpointAsync(
                from, proto, rotateOpt with { DpiAssist = false }, progress, rotateCts.Token).ConfigureAwait(true);

            try { await WarpDpiAssist.StopAsync().ConfigureAwait(true); } catch { }

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
                Log("Failover failed — press Connect to rescan.");
                SetHealthUi("Health: failed", false);
                _activeEndpoint = null;
            }
            done.TrySetResult(ok);
        }
        catch (OperationCanceledException)
        {
            WarpSessionLog.End(false, "rotate cancelled");
            try { await WarpCli.RunCleanupAsync("disconnect").ConfigureAwait(true); } catch { }
            try { await WarpDpiAssist.StopAsync().ConfigureAwait(true); } catch { }
            done.TrySetResult(false);
        }
        catch (Exception ex)
        {
            Log("Rotate error: " + ex.Message);
            WarpSessionLog.End(false, "rotate exception: " + ex.Message);
            try { await WarpDpiAssist.StopAsync().ConfigureAwait(true); } catch { }
            done.TrySetResult(false);
        }
        finally
        {
            EndOperation(rotateCts);
            done.TrySetResult(false);
        }
    }

    private async Task ConnectAsync()
    {
        if (_busy || _closing) return;
        if (!WarpCli.IsInstalled())
        {
            Log("Install Cloudflare WARP first (Get WARP…), then retry Connect.");
            OpenLinks.OpenUrl("https://one.one.one.one/");
            return;
        }

        StopLinkWatch();
        using var operation = BeginOperation();
        CancellationToken ct = operation.Token;
        bool connectionStarted = false;
        var progress = new Progress<string>(msg =>
        {
            Log(msg);
            WarpSessionLog.Step("ui", msg);
        });
        bool sessionEnded = false;
        try
        {
            var pre = await WarpCli.RunOperationAsync(() => WarpPreflight.RunAsync(progress, ct), ct).ConfigureAwait(true);
            ct.ThrowIfCancellationRequested();
            foreach (string w in pre.Warnings) Log("WARN: " + w);

            if (!pre.ServiceRunning)
            {
                Log(pre.Warnings.FirstOrDefault() ?? "WARP service not running.");
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

            // Honor the checkboxes — never re-check Iran mode on Connect.
            if (pre.LikelyIran && !censorship)
                Log("Iran detected, but Iran mode is off — Cloudflare default only (no IP scan).");
            else if (!censorship)
                Log("Iran mode off — Cloudflare default connect.");

            SyncOptionConflicts(fromUser: false);
            string protocol = _cmbProtocol.SelectedItem?.ToString() ?? "MASQUE";
            if (protocol == "Auto")
                Log("Auto: tries MASQUE first, then bounded WireGuard recovery if needed.");
            else if (censorship && protocol.Equals("WireGuard", StringComparison.OrdinalIgnoreCase))
                Log("Protocol: WireGuard (UDP). If connect fails under DPI, switch to MASQUE.");
            else if (censorship)
                Log("Protocol: MASQUE (TCP/H2 — usually best under Iranian DPI).");

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
                TryExitOutsideIran = _chkRegionalExit.Checked,
                AutomaticProtocol = protocol == "Auto",
                RequireLinkQuality = !censorship,
                MaxCandidates = censorship ? 48 : 24,
                MaxConnectAttempts = censorship ? 14 : 8,
                CidrSamplePerRange = censorship ? 12 : 8,
                ProbeTimeoutMs = 400,
            };
            _lastOpt = opt;
            if (opt.TryExitOutsideIran)
                Log("Experimental country search: tries both protocols; no account access guarantee. Normal Internet traffic is not blocked if the search fails.");

            List<string>? endpointList;
            if (!hasSpecific)
            {
                endpointList = null;
                Log(censorship
                    ? "Connect: automatic endpoint selection with bounded handshake attempts."
                    : "Connecting with Cloudflare default…");
            }
            else
            {
                endpointList = new List<string> { selected };
                Log($"Connecting {selected}…");
            }

            ct.ThrowIfCancellationRequested();
            connectionStarted = true;
            var (ok, message, ep, usedProtocol) = await WarpCli.TryConnectWithFallbackAsync(
                endpointList, protocol, progress, ct, opt).ConfigureAwait(true);
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
            if (protocol != "Auto" && !string.IsNullOrEmpty(usedProtocol) &&
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
                Log(opt.TryExitOutsideIran
                    ? "Both tested routes reported outside Iran. Services may use different location data; login, playback and games are not verified."
                    : "WARP connected. Your exit may still be located in Iran; a Frankfurt data center does not change that.");
                SetHealthUi("Health: watching…", true);
            }
            else
            {
                SetHealthUi("Connection not established", false);
                if (opt.TryExitOutsideIran)
                    Log("Strict country requirement was not met. To allow a normal WARP connection, uncheck Require exit outside Iran and choose Auto. Your exit may remain Iranian.");
                Log("Connect failed — see log above, or Open logs for the session file.");
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
                if (connectionStarted)
                {
                    await WarpCli.RunCleanupAsync("disconnect").ConfigureAwait(true);
                    await WarpDpiAssist.StopAsync().ConfigureAwait(true);
                }
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
            EndOperation(operation);
        }
    }
}

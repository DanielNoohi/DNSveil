using SecureDNSClient.GeoHide;
using MsmhToolsWinFormsClass.Themes;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Principal;

namespace SecureDNSClient;

/// <summary>Optional BPB-inspired backend. Scanning never installs routes; Connect does so only after a real tunnel test.</summary>
internal sealed class FormGeoHideXray : Form
{
    private readonly ComboBox mode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 240 };
    private readonly CheckBox noise = new() { Text = "Warp Pro noise", Checked = true, AutoSize = true };
    private readonly NumericUpDown count = Number(1, 10, 5), sizeMin = Number(1, 1280, 50), sizeMax = Number(1, 1280, 100),
        delayMin = Number(0, 100, 1), delayMax = Number(0, 100, 5);
    private readonly CheckBox strict = new() { Text = "Require both exit countries outside Iran (may not connect)", Checked = true, AutoSize = true };
    private readonly CheckBox terms = new() { Text = "I accept Cloudflare's terms for creating WARP profiles", AutoSize = true };
    private readonly TextBox endpoints = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
    private readonly DataGridView results = new() { Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false,
        AllowUserToDeleteRows = false, MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill, RowHeadersVisible = false };
    private readonly TextBox log = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical };
    private readonly Label status = new() { Text = "Not connected. Scan first; no country change is guaranteed.", Dock = DockStyle.Fill, AutoEllipsis = true };
    private readonly Button scan = new() { Text = "Scan endpoints", AutoSize = true }, connect = new() { Text = "Connect this PC", AutoSize = true },
        stop = new() { Text = "Disconnect", AutoSize = true }, cancel = new() { Text = "Cancel", AutoSize = true },
        test = new() { Text = "Test tunnel", AutoSize = true }, logs = new() { Text = "Open logs", AutoSize = true };
    private readonly System.Windows.Forms.Timer health = new() { Interval = 15000 };
    private CancellationTokenSource? operation;
    private XrayWarpSession? session;
    private bool closeRequested, mayClose, healthBusy;
    private bool activeStrict;
    private readonly string root = Path.Combine(SecureDNS.UserDataDirPath, "XrayWarp");
    private readonly string tools = Path.Combine(AppContext.BaseDirectory, "Backends");
    private string? reportPath;

    internal bool HasActiveWork => operation != null || session != null;

    internal FormGeoHideXray()
    {
        Name = nameof(FormGeoHideXray);
        Text = "DNSveil — Advanced WARP (Xray)";
        ClientSize = new Size(850, 710); MinimumSize = new Size(780, 690); StartPosition = FormStartPosition.CenterParent;
        Font = new Font("Segoe UI", 9);
        mode.Items.AddRange(new object[] { "WARP-on-WARP (two tunnels)", "WARP (one tunnel)" }); mode.SelectedIndex = 0;
        endpoints.Text = string.Join(Environment.NewLine, XrayWarpConfig.DefaultEndpoints);
        foreach (string column in new[] { "Endpoint", "HTTPS ms", "UDP", "IPv4 country", "IPv6 country", "Result" }) results.Columns.Add(column, column);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 9, Padding = new Padding(12) };
        foreach (int height in new[] { 40, 38, 34, 30, 90, 40, 170, 36 }) layout.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label { Text = "Real tunnel scanning • TCP + UDP for this PC • Experimental country change", AutoSize = true }, 0, 0);
        layout.Controls.Add(Row(mode, noise, new Label { Text = "Packets", AutoSize = true }, count), 0, 1);
        layout.Controls.Add(Row(new Label { Text = "Noise bytes", AutoSize = true }, sizeMin, sizeMax,
            new Label { Text = "Delay ms", AutoSize = true }, delayMin, delayMax), 0, 2);
        layout.Controls.Add(strict, 0, 3);
        layout.Controls.Add(endpoints, 0, 4);
        layout.Controls.Add(Row(scan, connect, stop, cancel, test, logs), 0, 5);
        layout.Controls.Add(results, 0, 6);
        var termsLink = new LinkLabel { Text = "Cloudflare terms", AutoSize = true };
        termsLink.LinkClicked += (_, _) => Process.Start(new ProcessStartInfo("https://www.cloudflare.com/application/terms/") { UseShellExecute = true });
        layout.Controls.Add(Row(terms, termsLink), 0, 7);
        var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2 };
        bottom.RowStyles.Add(new RowStyle(SizeType.Absolute, 34)); bottom.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        bottom.Controls.Add(status, 0, 0); bottom.Controls.Add(log, 0, 1); layout.Controls.Add(bottom, 0, 8);
        Controls.Add(layout); Theme.LoadTheme(this, Theme.Themes.Dark);
        results.BackgroundColor = Color.FromArgb(22, 27, 34);
        results.DefaultCellStyle.BackColor = Color.FromArgb(28, 36, 48);
        results.DefaultCellStyle.ForeColor = Color.WhiteSmoke;
        scan.Click += async (_, _) => await RunAsync(ScanAsync);
        connect.Click += async (_, _) => await RunAsync(ConnectAsync);
        stop.Click += async (_, _) => await RunAsync(async _ => await StopAsync());
        test.Click += async (_, _) => await RunAsync(async ct => { if (session != null) await CheckSessionAsync(ct); });
        cancel.Click += (_, _) => operation?.Cancel();
        logs.Click += (_, _) => { Directory.CreateDirectory(root); Process.Start(new ProcessStartInfo(root) { UseShellExecute = true }); };
        health.Tick += async (_, _) => {
            if (operation != null || healthBusy || session == null) return;
            healthBusy = true;
            try { await RunAsync(CheckSessionAsync); }
            finally { healthBusy = false; }
        };
        FormClosing += async (_, e) => {
            if (mayClose) return;
            e.Cancel = true; closeRequested = true; operation?.Cancel();
            if (operation == null) { await StopAsync(); mayClose = true; Close(); }
        };
        FormClosed += (_, _) => health.Dispose();
        SetControls();
    }

    private static NumericUpDown Number(int min, int max, int value) => new() { Minimum = min, Maximum = max, Value = value, Width = 66 };
    private static FlowLayoutPanel Row(params Control[] controls) {
        var row = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false }; row.Controls.AddRange(controls); return row;
    }
    private XrayWarpOptions Options() => new(mode.SelectedIndex == 0, noise.Checked, (int)count.Value,
        (int)sizeMin.Value, (int)sizeMax.Value, (int)delayMin.Value, (int)delayMax.Value);
    private string[] Endpoints() {
        var list = endpoints.Text.Split(new[] { '\r', '\n', ',', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (list.Length is < 1 or > 16) throw new ArgumentException("Enter between 1 and 16 IP:port endpoints.");
        foreach (string endpoint in list) XrayWarpConfig.ParseEndpoint(endpoint);
        return list;
    }
    private void SetControls() {
        bool idle = operation == null, connected = session != null;
        scan.Enabled = connect.Enabled = idle && !connected; stop.Enabled = test.Enabled = idle && connected;
        cancel.Enabled = !idle; endpoints.Enabled = mode.Enabled = noise.Enabled = strict.Enabled = terms.Enabled = idle && !connected;
        foreach (var item in new[] { count, sizeMin, sizeMax, delayMin, delayMax }) item.Enabled = idle && !connected;
    }
    private void Log(string message) {
        if (IsDisposed) return;
        log.AppendText(message + Environment.NewLine);
        if (log.TextLength > 60000) log.Text = log.Text[^40000..];
        try { if (reportPath != null) File.AppendAllText(reportPath, DateTimeOffset.Now.ToString("O") + " " + message + Environment.NewLine); } catch (IOException) { }
    }
    private async Task RunAsync(Func<CancellationToken, Task> action) {
        if (operation != null) return;
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5)); operation = cts; SetControls();
        try {
            XrayWarpProfiles.RestrictDirectory(root);
            reportPath ??= Path.Combine(root, "session-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8] + ".log");
            await action(cts.Token);
        }
        catch (OperationCanceledException) { Log("Cancelled or operation deadline reached."); await StopAsync(); }
        catch (Exception ex) { Log("Operation stopped: " + ex.Message); await StopAsync(); status.Text = ex.Message; }
        finally {
            operation = null; SetControls();
            if (closeRequested) { await StopAsync(); mayClose = true; Close(); }
        }
    }
    private async Task<XrayWarpAccount[]> PrepareAsync(CancellationToken ct) {
        Options().Validate();
        await XrayWarpTools.VerifyAsync(tools, ct);
        if (WarpCli.IsInstalled() && WarpCli.IsConnected(await WarpCli.RunAsync(ct, "status")))
            throw new InvalidOperationException("Disconnect the official WARP tunnel before using Advanced WARP.");
        return await XrayWarpProfiles.LoadOrCreateAsync(root, Path.Combine(tools, "xray.exe"), terms.Checked, new Progress<string>(Log), ct);
    }
    private async Task ScanAsync(CancellationToken ct) {
        string[] candidates = Endpoints(); var options = Options(); var accounts = await PrepareAsync(ct);
        results.Rows.Clear(); status.Text = "Scanning real tunnels; system routes are unchanged.";
        Log($"Scan: {(options.DoubleTunnel ? "two" : "one")} tunnel(s), noise={options.Noise}, {candidates.Length} endpoints.");
        int? bestRow = null; XrayWarpProbeResult? bestProbe = null;
        int iranExits = 0;
        foreach (string endpoint in candidates) {
            ct.ThrowIfCancellationRequested();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(22));
            try {
                await using var candidate = await XrayWarpSession.StartAsync(root, tools, accounts, endpoint, options, deadline.Token);
                var probe = await candidate.ProbeAsync(deadline.Token);
                bool eligible = probe.IsEligible(strict.Checked);
                if (probe.HasIranExit) iranExits++;
                int row = results.Rows.Add(endpoint, probe.LatencyMs, probe.UdpOk ? "Pass" : "Unverified",
                    probe.Exit.IPv4.Country ?? "?", probe.Exit.IPv6.Country ?? "?", probe.SelectionStatus(strict.Checked));
                if (eligible && probe.IsPreferredTo(bestProbe)) { bestRow = row; bestProbe = probe; }
                Log(endpoint + " — " + probe.Summary);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { results.Rows.Add(endpoint, "—", "?", "?", "?", "Timeout"); Log(endpoint + " — timed out."); }
            catch (Exception ex) when (ex is IOException or SocketException or InvalidOperationException) { results.Rows.Add(endpoint, "—", "?", "?", "?", "Failed"); Log(endpoint + " — " + ex.Message); }
        }
        results.ClearSelection();
        if (bestRow.HasValue) { results.Rows[bestRow.Value].Selected = true; results.CurrentCell = results.Rows[bestRow.Value].Cells[0]; }
        status.Text = bestProbe != null
            ? (bestProbe.Exit.IsOutside("IR") ? "Verified outside-Iran candidate selected; Connect tests it again."
                : "Connectivity only: exit is IR or unverified. Location restriction is not resolved.")
            : iranExits > 0 ? "Working WARP exits still report IR. No verified outside-Iran exit found."
                : "No qualifying tunnel found. Try another noise setting or endpoint list.";
        Log(status.Text);
    }
    private async Task ConnectAsync(CancellationToken ct) {
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Run DNSveil as Administrator to connect this PC through the game adapter.");
        string endpoint = results.SelectedRows.Count > 0 ? results.SelectedRows[0].Cells[0].Value?.ToString() ?? "" : Endpoints()[0];
        XrayWarpConfig.ParseEndpoint(endpoint);
        var options = Options(); var accounts = await PrepareAsync(ct);
        status.Text = "Verifying selected tunnel before enabling PC routing…";
        session = await XrayWarpSession.StartAsync(root, tools, accounts, endpoint, options, ct);
        var probe = await session.ProbeAsync(ct); Log(probe.Summary);
        if (!probe.TunnelOk || !probe.UdpOk) throw new InvalidOperationException("HTTPS WARP and a real UDP response must both pass before PC routing is enabled.");
        if (strict.Checked && !probe.Exit.IsOutside("IR")) throw new InvalidOperationException("Outside-Iran requirement failed. No PC routes were changed.");
        await session.StartFullDeviceAsync(ct);
        activeStrict = strict.Checked;
        if (activeStrict && !(await WarpExitCheck.FetchAsync(ct)).IsOutside("IR"))
            throw new InvalidOperationException("System-route country requirement failed after adapter startup.");
        status.Text = ConnectionStatus(probe);
        Log(status.Text); Log("Changing main-app pages keeps the tunnel connected; tray Exit disconnects. No persistent kill switch; ordinary traffic resumes after disconnect.");
        health.Start();
    }
    private async Task CheckSessionAsync(CancellationToken ct) {
        if (session == null) return;
        if (!session.Running) throw new InvalidOperationException("A backend process exited; disconnecting owned adapter.");
        var probe = await session.ProbeAsync(ct); Log(probe.Summary);
        if (!probe.TunnelOk || (activeStrict && !probe.Exit.IsOutside("IR")))
            throw new InvalidOperationException("Tunnel or country verification was lost; disconnecting.");
        if (activeStrict && !(await WarpExitCheck.FetchAsync(ct)).IsOutside("IR"))
            throw new InvalidOperationException("System-route country verification was lost; disconnecting.");
        status.Text = ConnectionStatus(probe);
    }
    private static string ConnectionStatus(XrayWarpProbeResult probe) =>
        $"Connected: IPv4 {probe.Exit.IPv4.Country ?? "unknown"}, IPv6 {probe.Exit.IPv6.Country ?? "unknown"}. " +
        (probe.HasIranExit ? "IR location restriction is not resolved." : "Service access is not verified.");

    private async Task StopAsync() {
        health.Stop();
        if (session != null) {
            var owned = session; session = null;
            try { await owned.DisposeAsync(); Log("Advanced WARP stopped. Ordinary traffic is no longer protected by this tunnel."); }
            catch (Exception ex) { Log("Cleanup warning: " + ex.Message + ". Check the PC connection before continuing."); }
        }
        status.Text = "Not connected.";
    }
}

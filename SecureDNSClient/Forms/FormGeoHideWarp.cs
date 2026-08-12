using CustomControls;
using MsmhToolsClass;
using MsmhToolsWinFormsClass.Themes;
using SecureDNSClient.GeoHide;
using System.Diagnostics;

namespace SecureDNSClient;

/// <summary>
/// GeoHide via official Cloudflare WARP (warp-cli), patterned after pywarp:
/// https://github.com/saeedmasoudie/pywarp
/// </summary>
public class FormGeoHideWarp : Form
{
    private readonly CustomLabel _lblStatus = new();
    private readonly CustomLabel _lblIp = new();
    private readonly CustomComboBox _cmbEndpoint = new();
    private readonly CustomComboBox _cmbProtocol = new();
    private readonly CustomComboBox _cmbPreset = new();
    private readonly CustomButton _btnRefresh = new();
    private readonly CustomButton _btnConnect = new();
    private readonly CustomButton _btnDisconnect = new();
    private readonly CustomButton _btnAuto = new();
    private readonly CustomButton _btnCancel = new();
    private readonly CustomButton _btnInstall = new();
    private readonly CustomButton _btnImportPreset = new();
    private readonly CustomButton _btnHelp = new();
    private readonly CustomRichTextBox _log = new();
    private readonly CustomCheckBox _chkImportAfterConnect = new();
    private CancellationTokenSource? _cts;
    private bool _busy;

    public FormGeoHideWarp()
    {
        Text = "GeoHide — Cloudflare WARP";
        Width = 660;
        Height = 560;
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        Theme.LoadTheme(this, Theme.Themes.Dark);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 7,
            Padding = new Padding(12),
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(root);

        var help = new CustomLabel
        {
            AutoSize = true,
            MaximumSize = new Size(620, 0),
            Text = "Uses official Cloudflare WARP (warp-cli), like PyWarp. Connect so destinations see a Cloudflare exit IP — not your ISP. Encrypted DNS / Shecan alone cannot change your public IP."
        };
        root.Controls.Add(help, 0, 0);

        var rowStatus = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false };
        _lblStatus.Text = "Status: …";
        _lblStatus.AutoSize = true;
        _lblStatus.Margin = new Padding(0, 8, 16, 8);
        _lblIp.Text = "Public IP: …";
        _lblIp.AutoSize = true;
        _lblIp.Margin = new Padding(0, 8, 8, 8);
        _btnRefresh.Text = "Refresh";
        _btnRefresh.Size = new Size(90, 28);
        _btnRefresh.Click += async (_, _) => await RefreshStatusAsync();
        rowStatus.Controls.Add(_lblStatus);
        rowStatus.Controls.Add(_lblIp);
        rowStatus.Controls.Add(_btnRefresh);
        root.Controls.Add(rowStatus, 0, 1);

        var rowEp = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = false };
        var lblEp = new CustomLabel { Text = "Endpoint", AutoSize = true, Margin = new Padding(0, 8, 8, 0) };
        _cmbEndpoint.Size = new Size(280, 28);
        _cmbEndpoint.DropDownStyle = ComboBoxStyle.DropDown;
        var lblProto = new CustomLabel { Text = "Protocol", AutoSize = true, Margin = new Padding(12, 8, 8, 0) };
        _cmbProtocol.Size = new Size(120, 28);
        _cmbProtocol.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbProtocol.Items.AddRange(new object[] { "WireGuard", "MASQUE" });
        _cmbProtocol.SelectedIndex = 0;
        _cmbProtocol.SelectedIndexChanged += (_, _) => ReloadEndpointList();
        ReloadEndpointList();
        rowEp.Controls.Add(lblEp);
        rowEp.Controls.Add(_cmbEndpoint);
        rowEp.Controls.Add(lblProto);
        rowEp.Controls.Add(_cmbProtocol);
        root.Controls.Add(rowEp, 0, 2);

        var rowBtn = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        StyleBtn(_btnConnect, "Connect", 100);
        StyleBtn(_btnDisconnect, "Disconnect", 100);
        StyleBtn(_btnAuto, "Auto-find endpoint", 140);
        StyleBtn(_btnCancel, "Cancel", 80);
        StyleBtn(_btnInstall, "Get WARP…", 100);
        StyleBtn(_btnHelp, "Help", 70);
        _btnCancel.Enabled = false;
        _btnConnect.Click += async (_, _) => await ConnectAsync(auto: false);
        _btnDisconnect.Click += async (_, _) => await DisconnectAsync();
        _btnAuto.Click += async (_, _) => await ConnectAsync(auto: true);
        _btnCancel.Click += (_, _) => { try { _cts?.Cancel(); } catch { } };
        _btnInstall.Click += (_, _) => OpenLinks.OpenUrl("https://one.one.one.one/");
        _btnHelp.Click += (_, _) => CustomMessageBox.Show(this, GeoHidePresets.HelpSummary, "GeoHide help",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
        rowBtn.Controls.Add(_btnConnect);
        rowBtn.Controls.Add(_btnDisconnect);
        rowBtn.Controls.Add(_btnAuto);
        rowBtn.Controls.Add(_btnCancel);
        rowBtn.Controls.Add(_btnInstall);
        rowBtn.Controls.Add(_btnHelp);
        root.Controls.Add(rowBtn, 0, 3);

        var rowPreset = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        var lblPreset = new CustomLabel { Text = "Rules preset", AutoSize = true, Margin = new Padding(0, 8, 8, 0) };
        _cmbPreset.Size = new Size(260, 28);
        _cmbPreset.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbPreset.Items.AddRange(new object[]
        {
            "Shecan anti-sanction (web/dev)",
            "Via upstream proxy",
            "Gaming Smart DNS template"
        });
        _cmbPreset.SelectedIndex = 0;
        StyleBtn(_btnImportPreset, "Import into Rules", 140);
        _btnImportPreset.Click += async (_, _) => await ImportSelectedPresetAsync(silent: false);
        _chkImportAfterConnect.Text = "Also import selected preset after successful connect";
        _chkImportAfterConnect.AutoSize = true;
        _chkImportAfterConnect.Checked = false;
        rowPreset.Controls.Add(lblPreset);
        rowPreset.Controls.Add(_cmbPreset);
        rowPreset.Controls.Add(_btnImportPreset);
        rowPreset.Controls.Add(_chkImportAfterConnect);
        root.Controls.Add(rowPreset, 0, 4);

        _log.Dock = DockStyle.Fill;
        _log.ReadOnly = true;
        root.Controls.Add(_log, 0, 5);

        var foot = new CustomLabel
        {
            AutoSize = true,
            MaximumSize = new Size(620, 0),
            Text = "Tip: after importing rules while DNS/Share is running, DNSveil re-applies them automatically. Keep WARP Connected while you need a Cloudflare exit IP."
        };
        root.Controls.Add(foot, 0, 6);

        Shown += async (_, _) =>
        {
            if (!WarpCli.IsInstalled())
                Log("warp-cli NOT found — click Get WARP… and install Cloudflare WARP.");
            else if (!WarpCli.IsServiceRunning())
                Log("warp-cli found, but WARP service is not running — open the official WARP app once.");
            else
                Log("warp-cli found.");
            await RefreshStatusAsync();
        };
        FormClosing += (_, _) =>
        {
            try { _cts?.Cancel(); } catch { }
            try { _cts?.Dispose(); } catch { }
            _cts = null;
        };
    }

    private GeoHidePresets.PresetKind SelectedPresetKind() => _cmbPreset.SelectedIndex switch
    {
        1 => GeoHidePresets.PresetKind.ViaUpstreamProxy,
        2 => GeoHidePresets.PresetKind.GamingSmartDns,
        _ => GeoHidePresets.PresetKind.AntiSanctionShecanShelter
    };

    private void ReloadEndpointList()
    {
        string protocol = _cmbProtocol.SelectedItem?.ToString() ?? "WireGuard";
        string keep = _cmbEndpoint.Text;
        _cmbEndpoint.Items.Clear();
        _cmbEndpoint.Items.Add("(Cloudflare default)");
        foreach (string ep in WarpCli.EnumerateEndpointCandidates(protocol, 40))
            _cmbEndpoint.Items.Add(ep);
        if (!string.IsNullOrWhiteSpace(keep) && _cmbEndpoint.Items.Contains(keep))
            _cmbEndpoint.Text = keep;
        else
            _cmbEndpoint.SelectedIndex = 0;
    }

    private static void StyleBtn(CustomButton b, string text, int width)
    {
        b.Text = text;
        b.Size = new Size(width, 28);
        b.BorderColor = Color.Blue;
        b.FlatStyle = FlatStyle.Flat;
        b.RoundedCorners = 5;
        b.Margin = new Padding(0, 4, 8, 4);
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
        var progress = new Progress<string>(Log);
        try
        {
            string protocol = _cmbProtocol.SelectedItem?.ToString() ?? "WireGuard";
            IEnumerable<string>? endpoints;
            if (auto)
            {
                endpoints = WarpCli.EnumerateEndpointCandidates(protocol, 16);
                Log("Auto-scanning endpoints (PyWarp-style)…");
            }
            else
            {
                string selected = _cmbEndpoint.Text.Trim();
                if (string.IsNullOrEmpty(selected) || selected.StartsWith("("))
                {
                    endpoints = null;
                    Log("Connecting with Cloudflare default endpoint…");
                }
                else
                {
                    endpoints = new[] { selected };
                }
            }

            var (ok, message, ep, usedProtocol) = await WarpCli.TryConnectWithFallbackAsync(
                endpoints, protocol, progress, _cts.Token).ConfigureAwait(true);
            Log(message);
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
                    message + "\n\nKeep WARP Connected while you need remotes to see the Cloudflare exit IP.",
                    "GeoHide", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                CustomMessageBox.Show(this, message, "GeoHide", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        catch (OperationCanceledException)
        {
            Log("Cancelled.");
            try
            {
                await Task.Run(() =>
                {
                    WarpCli.Disconnect();
                    WarpCli.ResetEndpoint();
                }).ConfigureAwait(true);
            }
            catch { }
        }
        catch (Exception ex)
        {
            Log("Error: " + ex.Message);
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

using CustomControls;
using MsmhToolsClass;
using SecureDNSClient.GeoHide;
using System.Diagnostics;

namespace SecureDNSClient;

/// <summary>
/// GeoHide via official Cloudflare WARP (warp-cli), patterned after pywarp:
/// https://github.com/saeedmasoudie/pywarp
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
    private CancellationTokenSource? _cts;
    private bool _busy;
    private bool _reloadingEndpoints;

    public FormGeoHideWarp()
    {
        Text = "GeoHide — Cloudflare WARP";
        ClientSize = new Size(640, 520);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        BackColor = Color.FromArgb(32, 32, 32);
        ForeColor = Color.WhiteSmoke;
        Font = new Font("Segoe UI", 9F);

        SuspendLayout();

        _lblHelp.AutoSize = false;
        _lblHelp.Location = new Point(12, 10);
        _lblHelp.Size = new Size(616, 48);
        _lblHelp.Text = "Uses official Cloudflare WARP (warp-cli). Connect so destinations see a Cloudflare exit IP — not your ISP. Encrypted DNS / Shecan alone cannot change your public IP.";

        _lblStatus.AutoSize = true;
        _lblStatus.Location = new Point(12, 66);
        _lblStatus.Text = "Status: …";
        _lblIp.AutoSize = true;
        _lblIp.Location = new Point(260, 66);
        _lblIp.Text = "Public IP: …";

        StyleBtn(_btnRefresh, "Refresh", new Point(520, 60), 90);
        _btnRefresh.Click += async (_, _) => await RefreshStatusAsync();

        _lblEp.AutoSize = true;
        _lblEp.Location = new Point(12, 100);
        _lblEp.Text = "Endpoint";
        _cmbEndpoint.Location = new Point(80, 96);
        _cmbEndpoint.Size = new Size(280, 28);
        _cmbEndpoint.DropDownStyle = ComboBoxStyle.DropDown;
        StyleCombo(_cmbEndpoint);

        _lblProto.AutoSize = true;
        _lblProto.Location = new Point(380, 100);
        _lblProto.Text = "Protocol";
        _cmbProtocol.Location = new Point(440, 96);
        _cmbProtocol.Size = new Size(120, 28);
        _cmbProtocol.DropDownStyle = ComboBoxStyle.DropDownList;
        StyleCombo(_cmbProtocol);
        _cmbProtocol.Items.AddRange(new object[] { "WireGuard", "MASQUE" });
        _cmbProtocol.SelectedIndexChanged += (_, _) =>
        {
            if (_reloadingEndpoints) return;
            ReloadEndpointList();
        };
        _cmbProtocol.SelectedIndex = 0;

        StyleBtn(_btnConnect, "Connect", new Point(12, 136), 100);
        StyleBtn(_btnDisconnect, "Disconnect", new Point(120, 136), 100);
        StyleBtn(_btnAuto, "Auto-find", new Point(228, 136), 100);
        StyleBtn(_btnCancel, "Cancel", new Point(336, 136), 80);
        StyleBtn(_btnInstall, "Get WARP…", new Point(424, 136), 100);
        StyleBtn(_btnHelp, "Help", new Point(532, 136), 80);
        _btnCancel.Enabled = false;
        _btnConnect.Click += async (_, _) => await ConnectAsync(auto: false);
        _btnDisconnect.Click += async (_, _) => await DisconnectAsync();
        _btnAuto.Click += async (_, _) => await ConnectAsync(auto: true);
        _btnCancel.Click += (_, _) => { try { _cts?.Cancel(); } catch { } };
        _btnInstall.Click += (_, _) => OpenLinks.OpenUrl("https://one.one.one.one/");
        _btnHelp.Click += (_, _) => CustomMessageBox.Show(this, GeoHidePresets.HelpSummary, "GeoHide help",
            MessageBoxButtons.OK, MessageBoxIcon.Information);

        _lblPreset.AutoSize = true;
        _lblPreset.Location = new Point(12, 178);
        _lblPreset.Text = "Rules preset";
        _cmbPreset.Location = new Point(100, 174);
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
        StyleBtn(_btnImportPreset, "Import into Rules", new Point(372, 172), 150);
        _btnImportPreset.Click += async (_, _) => await ImportSelectedPresetAsync(silent: false);

        _chkImportAfterConnect.AutoSize = true;
        _chkImportAfterConnect.Location = new Point(12, 210);
        _chkImportAfterConnect.Text = "Also import selected preset after successful connect";
        _chkImportAfterConnect.ForeColor = Color.WhiteSmoke;
        _chkImportAfterConnect.BackColor = Color.Transparent;
        _chkImportAfterConnect.Checked = false;

        _log.Location = new Point(12, 240);
        _log.Size = new Size(616, 230);
        _log.Multiline = true;
        _log.ScrollBars = ScrollBars.Vertical;
        _log.ReadOnly = true;
        _log.BackColor = Color.FromArgb(24, 24, 24);
        _log.ForeColor = Color.Gainsboro;
        _log.BorderStyle = BorderStyle.FixedSingle;

        _lblFoot.AutoSize = false;
        _lblFoot.Location = new Point(12, 478);
        _lblFoot.Size = new Size(616, 36);
        _lblFoot.Text = "Tip: after importing rules while DNS/Share is running, DNSveil re-applies them. Keep WARP Connected while you need a Cloudflare exit IP.";

        Controls.AddRange(new Control[]
        {
            _lblHelp, _lblStatus, _lblIp, _btnRefresh,
            _lblEp, _cmbEndpoint, _lblProto, _cmbProtocol,
            _btnConnect, _btnDisconnect, _btnAuto, _btnCancel, _btnInstall, _btnHelp,
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
            string protocol = _cmbProtocol.SelectedItem?.ToString() ?? "WireGuard";
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
                endpoints = WarpCli.EnumerateEndpointCandidates(protocol, 32);
                Log("Auto-scanning: parallel probe then fast connect…");
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

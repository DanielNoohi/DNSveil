using System.Diagnostics;
using System.Text;
using MsmhToolsClass;

namespace SecureDNSClient;

/// <summary>
/// Imports GeoHide rule presets (Smart DNS anti-sanction / upstream proxy examples).
/// Encrypted DNS alone does not hide the client IP from destinations.
/// </summary>
public static class GeoHidePresets
{
    public enum PresetKind
    {
        AntiSanctionShecanShelter,
        ViaUpstreamProxy,
        GamingSmartDns
    }

    public static string BundledPresetsDir =>
        Path.GetFullPath(Path.Combine(SecureDNS.CurrentPath, "Assets", "Presets"));

    public static string RepoPresetsDir =>
        Path.GetFullPath(Path.Combine(SecureDNS.CurrentPath, "..", "Assets", "Presets"));

    public static string UserPresetsDir =>
        Path.GetFullPath(Path.Combine(SecureDNS.AssetDirPath, "Presets"));

    public static string GetPresetFileName(PresetKind kind) => kind switch
    {
        PresetKind.AntiSanctionShecanShelter => "Rules_ShecanShelter_AntiSanction.txt",
        PresetKind.ViaUpstreamProxy => "Rules_ViaUpstreamProxy.txt",
        PresetKind.GamingSmartDns => "Rules_GamingSmartDns_ShelterRadar.txt",
        _ => string.Empty
    };

    public static string GetMarker(PresetKind kind) => kind switch
    {
        PresetKind.AntiSanctionShecanShelter => "DNSveil GeoHide — Anti-sanction",
        PresetKind.ViaUpstreamProxy => "DNSveil GeoHide — route selected hosts via UPSTREAM PROXY",
        PresetKind.GamingSmartDns => "DNSveil GeoHide — Gaming Smart DNS",
        _ => "DNSveil GeoHide"
    };

    public static string? ResolvePresetPath(PresetKind kind)
    {
        string name = GetPresetFileName(kind);
        if (string.IsNullOrEmpty(name)) return null;

        string[] candidates =
        {
            Path.Combine(UserPresetsDir, name),
            Path.Combine(BundledPresetsDir, name),
            Path.Combine(RepoPresetsDir, name)
        };

        foreach (string path in candidates)
        {
            if (File.Exists(path)) return path;
        }

        return null;
    }

    public static void EnsureUserPresetsCopied()
    {
        try
        {
            Directory.CreateDirectory(UserPresetsDir);
            string[] sources = { BundledPresetsDir, RepoPresetsDir };
            foreach (string srcDir in sources)
            {
                if (!Directory.Exists(srcDir)) continue;
                foreach (string file in Directory.GetFiles(srcDir))
                {
                    string dest = Path.Combine(UserPresetsDir, Path.GetFileName(file));
                    // Always refresh README*; copy rule presets only if missing so user edits survive.
                    string name = Path.GetFileName(file);
                    bool isReadme = name.StartsWith("README", StringComparison.OrdinalIgnoreCase);
                    if (isReadme || !File.Exists(dest))
                        File.Copy(file, dest, overwrite: isReadme);
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("GeoHidePresets.EnsureUserPresetsCopied: " + ex.Message);
        }
    }

    public static async Task<(bool Ok, string Message)> ImportIntoRulesAsync(PresetKind kind, bool merge)
    {
        try
        {
            EnsureUserPresetsCopied();
            string name = GetPresetFileName(kind);
            // Prefer UserData customized preset when present; otherwise bundled/repo stock.
            string userPath = Path.Combine(UserPresetsDir, name);
            string bundled = Path.Combine(BundledPresetsDir, name);
            string repo = Path.Combine(RepoPresetsDir, name);
            string? path = null;
            if (File.Exists(userPath)) path = userPath;
            else if (File.Exists(bundled)) path = bundled;
            else if (File.Exists(repo)) path = repo;
            if (path == null || !File.Exists(path))
                return (false, "Preset file not found. Place presets under Assets/Presets next to the app or in UserData/Assets/Presets.");

            List<string> presetLines = new();
            await presetLines.LoadFromFileAsync(path, true, true);
            if (presetLines.Count == 0)
                return (false, "Preset file is empty.");

            FileDirectory.CreateEmptyFile(SecureDNS.RulesPath);

            List<string> existing = new();
            if (merge && File.Exists(SecureDNS.RulesPath))
                await existing.LoadFromFileAsync(SecureDNS.RulesPath, true, true);

            string marker = GetMarker(kind);
            // Drop previous import of the same preset (marker lines + exact preset lines).
            existing = existing.Where(l => !l.Contains(marker, StringComparison.OrdinalIgnoreCase)).ToList();
            HashSet<string> presetSet = new(presetLines, StringComparer.OrdinalIgnoreCase);
            if (merge)
                existing = existing.Where(l => !presetSet.Contains(l)).ToList();
            else
                existing.Clear();

            List<string> output = new();
            if (merge && existing.Count > 0)
            {
                output.AddRange(existing);
                output.Add(string.Empty);
            }

            output.AddRange(presetLines);
            await File.WriteAllLinesAsync(SecureDNS.RulesPath, output, new UTF8Encoding(false));

            // Seed UserData from stock only when missing — never overwrite user edits.
            try
            {
                Directory.CreateDirectory(UserPresetsDir);
                if (!File.Exists(userPath) && (File.Exists(bundled) || File.Exists(repo)))
                    File.Copy(File.Exists(bundled) ? bundled : repo, userPath, overwrite: false);
            }
            catch { /* ignore */ }

            string tip = kind switch
            {
                PresetKind.ViaUpstreamProxy => " Edit GeoHideProxy= in Rules.txt to your foreign SOCKS/HTTP exit.",
                PresetKind.GamingSmartDns => " Add game domains under GamingDns; titles not on the provider list need GeoHide WARP.",
                _ => " Smart DNS helps only for domains those providers proxy — use Tools → GeoHide WARP to change your public IP."
            };

            return (true, $"Imported {Path.GetFileName(path)} into Rules.txt.{tip}");
        }
        catch (Exception ex)
        {
            Debug.WriteLine("GeoHidePresets.ImportIntoRulesAsync: " + ex.Message);
            return (false, ex.Message);
        }
    }

    public static string HelpSummary =>
        "DNS alone does not hide your IP from websites or apps.\n\n" +
        "• Tools → GeoHide WARP: controls official warp-cli (like PyWarp).\n" +
        "• Iran / heavy DPI: enable Censorship mode + DPI assist, protocol MASQUE, then Auto-find.\n" +
        "  – DPI assist = GoodbyeDPI TLS ClientHello fragment (GFW-knocker style).\n" +
        "  – Scans IRCF endpoints + Cloudflare WARP CIDRs over TCP (not ICMP).\n" +
        "  – MASQUE with HTTP/2 fallback when QUIC is blocked.\n" +
        "• Connect WARP so remotes see a Cloudflare exit IP.\n" +
        "• Import Shecan / gaming / upstream-proxy presets from the GeoHide window.\n\n" +
        "Hard limit: warp-cli cannot fake MASQUE SNI. If CF engage IPs are fully blocked, you need another tunnel.\n\n" +
        "See Assets/Presets/README_WARP.md and README_GeoHide.md";
}

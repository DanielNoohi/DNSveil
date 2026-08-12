using System.Diagnostics;
using System.Text;

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
        ViaUpstreamProxy
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
        _ => string.Empty
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
                    if (!File.Exists(dest))
                        File.Copy(file, dest, overwrite: false);
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
            string? path = ResolvePresetPath(kind);
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

            string marker = kind == PresetKind.AntiSanctionShecanShelter
                ? "DNSveil GeoHide — Anti-sanction"
                : "DNSveil GeoHide — route selected hosts via UPSTREAM PROXY";

            existing = existing.Where(l => !l.Contains(marker, StringComparison.OrdinalIgnoreCase)).ToList();
            HashSet<string> presetSet = new(presetLines, StringComparer.OrdinalIgnoreCase);
            if (merge)
                existing = existing.Where(l => !presetSet.Contains(l)).ToList();

            List<string> output = new();
            if (merge && existing.Count > 0)
            {
                output.AddRange(existing);
                output.Add(string.Empty);
            }

            output.AddRange(presetLines);
            await File.WriteAllLinesAsync(SecureDNS.RulesPath, output, new UTF8Encoding(false));

            string tip = kind == PresetKind.ViaUpstreamProxy
                ? " Edit GeoHideProxy= in Rules.txt to your foreign SOCKS/HTTP exit."
                : " Smart DNS helps only for domains those providers proxy — use Tools → GeoHide WARP to change your public IP.";

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
        "• Connect WARP so remotes see a Cloudflare exit IP.\n" +
        "• Auto-find endpoint helps when ISPs block default WARP.\n" +
        "• Shecan / gaming Smart DNS presets only cover listed domains.\n\n" +
        "See Assets/Presets/README_WARP.md and README_GeoHide.md";
}

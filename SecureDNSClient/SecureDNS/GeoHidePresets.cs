using System.Diagnostics;

namespace SecureDNSClient;

/// <summary>
/// GeoHide is Cloudflare WARP only — remotes should see a Cloudflare exit IP.
/// </summary>
public static class GeoHidePresets
{
    public static string BundledPresetsDir =>
        Path.GetFullPath(Path.Combine(SecureDNS.CurrentPath, "Assets", "Presets"));

    public static string RepoPresetsDir =>
        Path.GetFullPath(Path.Combine(SecureDNS.CurrentPath, "..", "Assets", "Presets"));

    public static string UserPresetsDir =>
        Path.GetFullPath(Path.Combine(SecureDNS.AssetDirPath, "Presets"));

    /// <summary>Copy WARP docs into UserData/Assets/Presets (no Smart DNS / proxy rule presets).</summary>
    public static void EnsureUserPresetsCopied()
    {
        try
        {
            Directory.CreateDirectory(UserPresetsDir);
            foreach (string srcDir in new[] { BundledPresetsDir, RepoPresetsDir })
            {
                if (!Directory.Exists(srcDir)) continue;
                foreach (string file in Directory.GetFiles(srcDir))
                {
                    string name = Path.GetFileName(file);
                    // Only docs — rule presets (Shecan / upstream / gaming Smart DNS) were removed.
                    if (!name.StartsWith("README", StringComparison.OrdinalIgnoreCase))
                        continue;
                    string dest = Path.Combine(UserPresetsDir, name);
                    File.Copy(file, dest, overwrite: true);
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("GeoHidePresets.EnsureUserPresetsCopied: " + ex.Message);
        }
    }

    public static string HelpSummary =>
        "GeoHide uses Cloudflare WARP only (DNSveil 3.6).\n\n" +
        "After Connect, game servers and websites should see a Cloudflare exit IP — not your ISP.\n\n" +
        "• Iran / heavy DPI: enable Iran mode + DPI assist, then Connect.\n" +
        "  – DPI assist = GoodbyeDPI fake-TTL / wrong-seq (Iran DPI reassembles fragments).\n" +
        "  – Then Light fragment, optional Mode9 if your goodbyedpi supports -q.\n" +
        "  – MASQUE h2-only on Cloudflare default; forced IPs skipped on warp-cli 2026.\n" +
        "• Protocol: try WireGuard for lower latency; switch to MASQUE if UDP fails.\n" +
        "• Health watch rotates weak endpoints automatically.\n" +
        "• Open logs shows UserData/GeoHideLogs session files.\n\n" +
        "Hard limit: if Cloudflare engage IPs are fully blocked, warp-cli cannot fake MASQUE SNI.\n\n" +
        "See Assets/Presets/README_WARP.md";
}

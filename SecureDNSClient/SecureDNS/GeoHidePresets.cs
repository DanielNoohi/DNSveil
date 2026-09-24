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
        "GeoHide offers official WARP and Advanced WARP (Xray).\n\n" +
        "• Advanced WARP adds two-tunnel WARP, noise, real scanning and TCP/UDP PC routing.\n" +
        "  Read ADVANCED_WARP.md. Close the advanced window to disconnect its tunnel.\n" +
        "• Auto tries MASQUE first and WireGuard if needed.\n" +
        "• WireGuard uses bounded real handshakes on distinct endpoints; UDP may still be blocked.\n" +
        "• Test connection checks WARP, IPv4/IPv6 countries and public web responses without reconnecting.\n" +
        "• Require exit outside Iran is strict: working Iranian exits are rejected. Leave it off for normal connectivity.\n" +
        "• Open logs shows the connection attempts and test results.\n\n" +
        "WARP cannot guarantee another country or acceptance by games, Spotify or ChatGPT. " +
        "A Frankfurt data center is not proof of a German exit. This is not a kill switch.";
}

using System.Security.Cryptography;

namespace SecureDNSClient.GeoHide;

internal static class XrayWarpTools
{
    internal static readonly IReadOnlyDictionary<string, string> Hashes = new Dictionary<string, string> {
        ["xray.exe"] = "15C2D007954AC53BA69B80EC91242786B3C0B71D52649165B4CA1D5CC96EF8F1",
        ["sing-box.exe"] = "B838DE45BD0B2E6DDBED1977E4745622F7DFFAB3B293807FF4C6B1B640FED909",
        ["wintun.dll"] = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE"
    };
    internal static async Task VerifyAsync(string directory, CancellationToken ct)
    {
        if (!Environment.Is64BitProcess) throw new PlatformNotSupportedException("Advanced WARP requires the Windows x64 build.");
        foreach (var item in Hashes)
        {
            string path = Path.Combine(directory, item.Key);
            if (!File.Exists(path)) throw new FileNotFoundException("Missing verified backend. Use the complete v4 portable download or restore backends when building from source.", item.Key);
            using var stream = File.OpenRead(path);
            using var hash = SHA256.Create();
            string actual = Convert.ToHexString(await hash.ComputeHashAsync(stream, ct).ConfigureAwait(false));
            if (!actual.Equals(item.Value, StringComparison.Ordinal)) throw new InvalidOperationException("Backend checksum mismatch: " + item.Key);
        }
    }
}

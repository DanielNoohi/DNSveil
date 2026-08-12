using System.Text.Json;

namespace SecureDNSClient.GeoHide;

/// <summary>
/// Remembers successful GeoHide endpoints for ~24h so Connect tries them before a full scan.
/// Stored at <c>UserData/GeoHideSuccessCache.json</c>.
/// </summary>
public static class WarpSuccessCache
{
    private static readonly object Gate = new();
    private static readonly TimeSpan Ttl = TimeSpan.FromHours(24);
    private const int MaxEntries = 16;

    private sealed class Store
    {
        public List<Entry> Entries { get; set; } = new();
    }

    public sealed class Entry
    {
        public string Endpoint { get; set; } = "";
        public string Protocol { get; set; } = "MASQUE";
        public DateTime Utc { get; set; }
        public string? ExitIp { get; set; }
        public string? Loc { get; set; }
        public string? Colo { get; set; }
    }

    private static string PathFile =>
        Path.Combine(SecureDNS.UserDataDirPath, "GeoHideSuccessCache.json");

    public static IReadOnlyList<Entry> GetRecent(TimeSpan? maxAge = null)
    {
        maxAge ??= Ttl;
        lock (Gate)
        {
            Store store = LoadUnlocked();
            DateTime cutoff = DateTime.UtcNow - maxAge.Value;
            return store.Entries
                .Where(e => e.Utc >= cutoff && !string.IsNullOrWhiteSpace(e.Endpoint))
                .OrderByDescending(e => e.Utc)
                .ToList();
        }
    }

    /// <summary>Endpoints only, newest first, distinct.</summary>
    public static List<string> GetRecentEndpoints(TimeSpan? maxAge = null)
    {
        return GetRecent(maxAge)
            .Select(e => e.Endpoint.Trim())
            .Where(e => e.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static void Record(string? endpoint, string protocol, WarpCli.PublicIpInfo? egress = null)
    {
        if (string.IsNullOrWhiteSpace(endpoint)) return;
        lock (Gate)
        {
            Store store = LoadUnlocked();
            DateTime cutoff = DateTime.UtcNow - Ttl;
            store.Entries.RemoveAll(e =>
                e.Utc < cutoff ||
                string.Equals(e.Endpoint, endpoint, StringComparison.OrdinalIgnoreCase));

            store.Entries.Insert(0, new Entry
            {
                Endpoint = endpoint.Trim(),
                Protocol = string.IsNullOrWhiteSpace(protocol) ? "MASQUE" : protocol,
                Utc = DateTime.UtcNow,
                ExitIp = egress?.Ip,
                Loc = egress?.Loc,
                Colo = egress?.Colo,
            });

            if (store.Entries.Count > MaxEntries)
                store.Entries = store.Entries.Take(MaxEntries).ToList();

            SaveUnlocked(store);
            WarpSessionLog.Step("cache", $"remembered {endpoint}",
                new Dictionary<string, object?>
                {
                    ["protocol"] = protocol,
                    ["ip"] = egress?.Ip,
                    ["loc"] = egress?.Loc,
                    ["count"] = store.Entries.Count,
                });
        }
    }

    private static Store LoadUnlocked()
    {
        try
        {
            if (!File.Exists(PathFile)) return new Store();
            string json = File.ReadAllText(PathFile);
            return JsonSerializer.Deserialize<Store>(json) ?? new Store();
        }
        catch
        {
            return new Store();
        }
    }

    private static void SaveUnlocked(Store store)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PathFile)!);
            string json = JsonSerializer.Serialize(store, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(PathFile, json);
        }
        catch { /* ignore */ }
    }
}

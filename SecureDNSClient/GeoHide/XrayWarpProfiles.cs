using System.Net.Http.Json;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace SecureDNSClient.GeoHide;

internal static class XrayWarpProfiles
{
    internal static void RestrictDirectory(string directory)
    {
        Directory.CreateDirectory(directory);
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { WindowsIdentity.GetCurrent().User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(acl);
    }

    internal static async Task<XrayWarpAccount[]> LoadOrCreateAsync(string directory, string xray, bool acceptedTerms,
        IProgress<string>? progress, CancellationToken ct)
    {
        RestrictDirectory(directory);
        string file = Path.Combine(directory, "profiles.dpapi");
        var accounts = new List<XrayWarpAccount>();
        if (File.Exists(file))
        {
            byte[] plain = ProtectedData.Unprotect(await File.ReadAllBytesAsync(file, ct).ConfigureAwait(false), null, DataProtectionScope.CurrentUser);
            try { accounts.AddRange(JsonSerializer.Deserialize<XrayWarpAccount[]>(plain) ?? Array.Empty<XrayWarpAccount>()); }
            finally { CryptographicOperations.ZeroMemory(plain); }
            if (accounts.Count > 2) throw new FormatException("Unexpected profile count.");
            foreach (var account in accounts) account.Validate();
        }
        if (accounts.Count == 2) return accounts.ToArray();
        if (!acceptedTerms) throw new InvalidOperationException("Accept Cloudflare's terms to create the two WARP profiles.");
        using var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(20) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("DNSveil/4.0");
        while (accounts.Count < 2)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report($"Creating WARP profile {accounts.Count + 1}/2 with Cloudflare…");
            var keys = await WarpCommandRunner.RunAsync(xray, new[] { "x25519", "--std-encoding" }, TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
            if (!keys.Ok) throw new InvalidOperationException("Xray key generation failed.");
            string Key(string prefix) => keys.StdOut.Split('\n').FirstOrDefault(x => x.StartsWith(prefix, StringComparison.Ordinal))?.Split(':', 2)[1].Trim()
                ?? throw new FormatException("Unexpected key generator output.");
            string privateKey = Key("PrivateKey:");
            string publicKey = Key("Password (PublicKey):");
            using var response = await http.PostAsJsonAsync("https://api.cloudflareclient.com/v0a4005/reg", new {
                install_id = "", fcm_token = "", tos = DateTime.UtcNow.ToString("O"), type = "Android", model = "PC", locale = "en_US",
                warp_enabled = true, key = publicKey
            }, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) throw new HttpRequestException($"Cloudflare profile registration returned HTTP {(int)response.StatusCode}. No account details were logged.");
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            accounts.Add(ParseRegistration(doc.RootElement, privateKey));
            // Persist each completed registration to avoid creating replacement accounts after a failed second request.
            byte[] plain = JsonSerializer.SerializeToUtf8Bytes(accounts);
            try
            {
                await File.WriteAllBytesAsync(file + ".tmp", ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser), ct).ConfigureAwait(false);
                File.Move(file + ".tmp", file, true);
            }
            finally { CryptographicOperations.ZeroMemory(plain); }
            if (accounts.Count < 2) await Task.Delay(2000, ct).ConfigureAwait(false);
        }
        return accounts.ToArray();
    }

    internal static XrayWarpAccount ParseRegistration(JsonElement response, string privateKey)
    {
        var config = response.GetProperty("config");
        string address = config.GetProperty("interface").GetProperty("addresses").GetProperty("v6").GetString()!;
        var result = new XrayWarpAccount(privateKey, config.GetProperty("peers")[0].GetProperty("public_key").GetString()!,
            address + (address.Contains('/') ? "" : "/128"), Convert.FromBase64String(config.GetProperty("client_id").GetString()!).Select(b => (int)b).ToArray());
        result.Validate();
        return result;
    }
}

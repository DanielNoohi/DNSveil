using System.Net;

namespace SecureDNSClient.GeoHide;

/// <summary>Read-only public-page checks. No authentication, playback or gameplay is attempted.</summary>
internal static class WarpDiagnostics
{
    internal static string DescribeHttp(string name, int status) => status switch
    {
        >= 200 and < 400 => $"{name}: public web endpoint reachable (HTTP {status}); app access not tested.",
        401 or 403 => $"{name}: request denied (HTTP {status}); this alone does not prove a country block.",
        429 => $"{name}: rate limited (HTTP 429).",
        _ => $"{name}: HTTP {status}; service did not return a successful public-page response."
    };

    internal static async Task<string[]> FetchAsync(CancellationToken ct)
    {
        using var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        var targets = new[] { ("Spotify", "https://open.spotify.com/"),
            ("ChatGPT", "https://chatgpt.com/"), ("YouTube", "https://www.youtube.com/") };
        return await Task.WhenAll(targets.Select(async target =>
        {
            try
            {
                using var response = await http.GetAsync(target.Item2, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                return DescribeHttp(target.Item1, (int)response.StatusCode);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return target.Item1 + ": request timed out."; }
            catch (HttpRequestException ex) { return target.Item1 + ": network/TLS request failed: " + ex.Message; }
        })).ConfigureAwait(false);
    }
}

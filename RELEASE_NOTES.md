# DNSveil v3.8.0 — experimental exit-country search

## What changed

- Add an opt-in **Try exit outside Iran (experimental)** checkbox in GeoHide WARP.
- Try the selected protocol, an alternate protocol, and another candidate in at most three rounds within a two-minute search budget plus cleanup. Experiments run without DPI assist.
- Verify direct IPv4 and IPv6 exits separately with normal HTTPS certificate validation. Accept only known non-IR country observations with WARP on for both families. Unknown or unavailable families do not pass.
- Recheck the country requirement during health monitoring and request disconnection when it is no longer verified.
- Clarify that exit country and Cloudflare data-center location are different. A connected tunnel is not evidence of unrestricted service access.
- Add 13 regression checks for country evidence, mixed IP families, bounded search, acceptance and cancellation cleanup (32 checks total).

## How to use

Extract the portable archive, run `SecureDNSClientPortable.exe`, open Tools → GeoHide WARP, select **Try exit outside Iran (experimental)**, then Connect. Read the reported IPv4 and IPv6 countries. The option is off by default.

## Limits

Cloudflare controls exit assignment. No successful change of country has been demonstrated on the affected network. This may find no qualifying exit. A different observed country does not guarantee Spotify playback, ChatGPT login, or Where Winds Meet access, and Cloudflare's location data may differ from a service's data.

This is not a kill switch. Normal Internet traffic remains possible during attempts, after failure, and between checks. The app does not change GPS permissions, account regions, or supply another VPN/server. A missing IPv6 observation causes rejection even if that route might simply be unavailable.

Validation uses simulated connections and local fixtures; no live region-unblocking claim is made. Existing .NET 6 / dependency warnings remain.

## Download

`SecureDNSClientPortable_v3.8.0_x64.7z` and `SHA256SUMS.txt`. Requires Windows x64, .NET Desktop 6 and ASP.NET Core 6 runtimes. Administrator privileges are needed for DPI / WinDivert and related adapter operations.

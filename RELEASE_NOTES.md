# DNSveil v3.9.0 — connection recovery and diagnostics

## What changed

- Auto is the default protocol choice: try MASQUE first, then WireGuard if necessary. Keep successful tunnels and retain Auto during health recovery. Each protocol has a 100-second work budget plus cleanup.
- Replace repeated WireGuard default attempts with up to four distinct real handshakes, including UDP ports 500, 4500 and 1701. Each has a 22-second work budget plus cleanup. Explicit endpoints are preserved.
- Remove fake WireGuard reachability/latency results based only on sending UDP. Candidates remain unverified until a real WARP handshake succeeds.
- Finish failed-attempt cleanup before recovery. Cancellation never starts another protocol, and unconfirmed disconnect stops recovery.
- Add Test connection: current WARP status, IPv4/IPv6 countries, and public-page responses from Spotify, ChatGPT and YouTube. It does not reconnect. Save reports under UserData/GeoHideLogs.
- Rename the experimental option to Require exit outside Iran (strict; may not connect). Explain why a working Iranian exit is rejected, retain the strict requirement, and stop penalizing those working endpoints in the connectivity cache.
- Update Help and add 12 regression checks (44 total).

## Use

Extract the portable archive and run SecureDNSClientPortable.exe. Open Tools → GeoHide WARP, choose Auto, and leave Require exit outside Iran unchecked for normal connectivity. Connect, then use Test connection for a saved diagnostic report.

Enable the strict country option only if you want Iranian or unverified exits rejected. It may find no acceptable exit and disconnect. It is not a kill switch; ordinary traffic remains possible during attempts, after failure and between checks.

## Validation and limits

The affected network's logs show working MASQUE tunnels with Iranian exits and stalled WireGuard handshakes. Regression validation uses local fixtures and simulated recovery; no working WireGuard connection or country change has been demonstrated on this network by this release. Public-page responses do not verify login, Spotify playback or Where Winds Meet gameplay. A 403 response alone does not establish a regional block.

Cloudflare controls exit assignment; a Frankfurt data center is not proof of a German exit. DNSveil cannot guarantee another country or service acceptance. Existing .NET 6/dependency warnings remain. Requires Windows x64, .NET Desktop 6 and ASP.NET Core 6 runtimes; administrator privileges are required for DPI/adapter operations.

## Downloads

SecureDNSClientPortable_v3.9.0_x64.7z and SHA256SUMS.txt.

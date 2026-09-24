# Advanced WARP in DNSveil v4

This optional backend uses Xray for WARP / WARP-on-WARP and sing-box for this PC's TCP and UDP routing. It is inspired by BPB Worker Panel and BPB Warp Scanner. No paid server is required; connectivity still depends on Cloudflare and your network.

## First connection

1. Extract the complete portable x64 release and run SecureDNSClientPortable.exe as Administrator.
2. Disconnect the official WARP tunnel and other VPNs. Open Tools → GeoHide WARP and select Advanced WARP inside the main DNSveil window.
3. Read Cloudflare's terms using the link. If you accept, tick the checkbox to allow creation of two WARP profiles. Existing profiles are reused.
4. Start with WARP-on-WARP and Warp Pro noise enabled. The default endpoint list and noise values are starting points, not known-working settings for your ISP.
5. Click Scan endpoints. It tests actual HTTPS traffic and a UDP DNS response through each candidate. Scanning does not install PC routes. Up to 16 custom IP:port endpoints are accepted; bracket IPv6 addresses.
6. Inspect the HTTPS, UDP and country columns. Verified outside-Iran candidates are preferred, then ranked by latency. Click Connect this PC to verify it again and then activate the adapter.
7. Test the game or service. Changing main-app pages or minimizing DNSveil keeps the tunnel running. Disconnect in Advanced WARP or use tray → Exit to stop it. Switching to Official WARP is disabled while Advanced WARP is busy or connected.

If no candidate works, try single WARP to distinguish outer-tunnel connectivity from WARP-on-WARP failure, or adjust noise values and scan again. Noise must be 1–10 packets of 1–1280 bytes with 0–100 ms delays. No setting guarantees connectivity.

## Reading results

- Outside IR verified means both country checks, HTTPS WARP and a matching UDP DNS response passed. IR — location unchanged means connectivity works but the country requirement failed. It is not proof that a game login, gameplay or Spotify playback will work.
- HTTPS latency is one trace request measured during this scan, not a full game latency benchmark.
- Country comes from separate IPv4/IPv6 Cloudflare trace observations. A data-center location is not the exit country. Unknown remains unknown.
- Require both exit countries outside Iran is on by default. While enabled, Iranian or unverified exits are rejected, including after PC routing starts and during health checks. This may prevent any connection.
- Test tunnel rechecks the active tunnel. Automatic health checks run while connected; a failed tunnel or strict country check triggers cleanup rather than silently switching to another mode.

## Routing and privacy

PC routing uses a dual-stack TUN adapter, DNS over HTTPS through the proxy, and the adapter core's strict-route mode. The outer endpoint is excluded from TUN routing to avoid feeding the tunnel into itself. There is no automatic direct fallback for proxied application traffic.

This is **not a persistent kill switch**. Ordinary traffic can resume after disconnection, failure or process exit. Country checks are periodic, not per-packet enforcement. Existing connections, other VPNs, explicit application routing, and game anti-cheat may affect results. Gameplay and live system-wide routing on your network were not validated by the release tests.

## Profiles and diagnostics

Profiles are stored under UserData/XrayWarp/profiles.dpapi, encrypted for the current Windows user. Temporary configuration directories are restricted to that user and SYSTEM; plaintext configurations are deleted after startup or cleanup. If Windows crashes before cleanup, a restricted temporary configuration may remain. Do not share the profile or sessions folders. Logs record endpoint test results without private keys. Open logs opens UserData/XrayWarp.

Cloudflare's registration API may change or reject requests. If registration fails, the software reports the failure and preserves any already-created profile instead of continuously creating accounts.

## Build and dependencies

Run Scripts/Restore-XrayBackends.ps1 before building or testing from source. The release package includes pinned Xray 26.3.27, sing-box 1.14.1, and signed Wintun; modified or missing executables are rejected by hash checks. See THIRD_PARTY_BACKENDS.md for licenses and corresponding sources.

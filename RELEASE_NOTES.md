# DNSveil v4.0.0 — Advanced WARP, inspired by BPB

## New backend

- Add Advanced WARP (Xray) alongside the existing official WARP mode.
- Support two-account WARP-on-WARP and single WARP with configurable Warp Pro UDP noise.
- Scan up to 16 endpoints using actual tunneled HTTPS and matching UDP DNS replies. Show IPv4/IPv6 countries separately from latency and select a qualifying candidate. Scanning leaves system routes unchanged.
- Connect this PC verifies the selected tunnel again before starting a dual-stack TCP/UDP adapter with DNS through the tunnel. Require outside-Iran exits remains optional and strict; it does not silently fall back to an Iranian exit.
- Reuse two Cloudflare profiles protected by Windows DPAPI. Require Cloudflare terms acceptance before creating profiles. Restrict temporary configuration access and delete those files after startup/cleanup.
- Own backend process trees with Windows jobs, stop them on window close/disconnect, and monitor tunnel/country health while connected.
- Bundle hash-verified Xray 26.3.27, sing-box 1.14.1 and signed Wintun. Include licenses, reproducible restoration scripts and corresponding upstream source archives.

## Try it

Extract the complete portable archive, run SecureDNSClientPortable.exe as Administrator, disconnect other VPNs and open Tools → GeoHide WARP → Advanced WARP (Xray). Read and accept Cloudflare's terms if you want profiles created, then Scan endpoints and Connect this PC. Keep the advanced window open while connected. Read ADVANCED_WARP.md for results, settings and limits.

## Validation and limits

69 checks passed locally, including all four generated Xray mode/noise combinations checked by the real core, adapter configuration validation, actual loopback SOCKS TCP/UDP forwarding, protected profiles and process cleanup. Tests do not create Cloudflare profiles or install PC routes.

Live ISP connectivity, WARP-on-WARP country changes, full-device routing on the affected network, and Where Winds Meet/Spotify/ChatGPT access are not established by these tests. This is an experimental backend, not a location guarantee or persistent kill switch. Ordinary traffic may resume after failure, disconnect or process exit. Existing .NET 6/dependency warnings remain.

## Downloads

- SecureDNSClientPortable_v4.0.0_x64.7z — Windows x64 portable application, backends and guides.
- Xray-core-v26.3.27-source.tar.gz and sing-box-v1.14.1-source.tar.gz — corresponding unmodified upstream source.
- SHA256SUMS.txt — checksums for all three archives.

Requires .NET Desktop 6 and ASP.NET Core 6 runtimes. Attribution and licenses are in THIRD_PARTY_BACKENDS.md and the Backends folder.

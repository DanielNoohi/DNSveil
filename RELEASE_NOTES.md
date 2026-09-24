# v4.1.0

- Advanced WARP scans 1–4 endpoints concurrently (default 2), with results as they complete and a progress indicator.
- Each worker uses its own encrypted, reusable profile pair. Profile creation requires the terms checkbox; choose one worker to keep using the existing pair. Selected results reconnect with the profiles used during scanning.
- Cancellation and unexpected failures wait for all active workers to clean up before another operation can start.
- Official WARP has a dedicated status panel, prominent connection controls, settings explanations and a separate activity log. Both modes remain inside the main DNSveil window.
- Validation: 76 regression checks passed, including bounded concurrency, cancellation, worker-failure cleanup, embedded UI rendering and real local TCP/UDP forwarding. Live parallel WARP performance on the affected ISP has not been measured.
- Country verification remains unchanged; this update does not guarantee an exit outside Iran.

# v4.0.1

- GeoHide is embedded in the main DNSveil window, with Official and Advanced WARP tabs. Reopening it selects the existing page.
- Tray → Exit waits for the embedded advanced tunnel to stop; changing main-app pages keeps the connection running.
- Advanced WARP requires verified IPv4 and IPv6 exits outside Iran by default. Working Iranian exits are explicitly labeled, and verified non-IR candidates rank ahead of faster Iranian candidates.
- Connected status keeps both country results visible. Connection failures retain their explanation.
- Validation: 73 regression checks passed, including embedded-view closure, regional candidate ranking, real local TCP/UDP forwarding and pinned backend configuration validation.
- WARP-on-WARP can still return IR. This update does not guarantee a different country or game/service access.

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

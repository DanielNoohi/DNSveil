# DNSveil

**Secure DNS. DPI bypass. Optional Cloudflare exit — without renting a VPS.**

[![Release](https://img.shields.io/github/v/release/DanielNoohi/DNSveil?style=flat-square&label=release)](https://github.com/DanielNoohi/DNSveil/releases/latest)
[![License](https://img.shields.io/github/license/DanielNoohi/DNSveil?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D4?style=flat-square)](#requirements)
[![.NET](https://img.shields.io/badge/.NET-6-512BD4?style=flat-square)](#requirements)

A hardened fork of [msasanmh/DNSveil](https://github.com/msasanmh/DNSveil) (Secure DNS Client) with **GeoHide WARP**, Iran-aware connect paths, and production-minded reliability work.

**Latest:** [v4.0.1](https://github.com/DanielNoohi/DNSveil/releases/latest) · [Download portable x64](https://github.com/DanielNoohi/DNSveil/releases/latest)

---

## Why DNSveil

| Need | What DNSveil does |
|------|-------------------|
| Hide DNS from the ISP | DoH / DoT / DNSCrypt (local resolver) |
| Bypass SNI / DNS blocks | Fragment, Fake SNI, Share proxy |
| Change the IP remotes see | **GeoHide WARP** — official Cloudflare `warp-cli` |
| Stay fast under DPI | MASQUE + TLS fragment assist, remembered endpoints |
| Rules that stick | Per-domain Smart DNS, SNI, upstream proxy |

Encrypted DNS alone does **not** change your public IP. GeoHide is the optional layer when destinations must not see your ISP address.

---

## Highlights

- **Multi-protocol DNS client** — DNSCrypt, Anonymized DNSCrypt, DoH (H2/H3), DoT, Plain DNS
- **Local DNS / DoH server** — share secure resolution to other devices
- **DPI toolkit** — Fragment & Fake SNI via GoodbyeDPI / WinDivert
- **Share proxy** — HTTP, HTTPS, SOCKS4/4A/5 with per-domain rules
- **GeoHide WARP** — Connect, censorship scan (IRCF + CF CIDRs), DPI assist, gaming profile, 24h endpoint memory
- **Scanners** — Fast DNS finder, Cloudflare clean IP scanner, DNS Lookup, STAMP tools
- **Fork-safe updates** — checks this repo only (never advertises upstream as this build)

Powered by [Msmh Agnostic Server](https://github.com/msasanmh/MsmhAgnosticServer), [DNSLookup](https://github.com/ameshkov/dnslookup), and [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI).

---

## Quick start

### 1. Runtime

Install **both** (match your CPU architecture):

| Arch | Desktop Runtime | ASP.NET Core Runtime |
|------|-----------------|----------------------|
| **x64** | [.NET Desktop 6.0.36](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-6.0.36-windows-x64-installer) | [ASP.NET Core 6.0.36](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-aspnetcore-6.0.36-windows-x64-installer) |
| **x86** | [.NET Desktop 6.0.36](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-6.0.36-windows-x86-installer) | [ASP.NET Core 6.0.36](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-aspnetcore-6.0.36-windows-x86-installer) |

More versions: [Microsoft .NET 6 downloads](https://dotnet.microsoft.com/en-us/download/dotnet/6.0)

### 2. App

1. Grab the latest **portable** build from [Releases](https://github.com/DanielNoohi/DNSveil/releases/latest)
2. Extract and run `SecureDNSClientPortable.exe` **as Administrator** (needed for DPI / WinDivert)
3. Connect to working DNS servers (built-in scan or your own list)
4. Optional: enable Fragment / Share proxy for SNI bypass

### 3. GeoHide (exit IP)

Choose either **Advanced WARP (Xray)** using the [v4 guide](ADVANCED_WARP.md), or the existing official client below. Run one tunnel at a time.

For the official client:

1. Install [Cloudflare WARP](https://one.one.one.one/) (includes `warp-cli`)
2. Open **Tools → GeoHide WARP**
3. Keep **Censorship mode** + **DPI assist** on under heavy filtering
4. Click **Connect** — successful endpoints are remembered for **24 hours** for faster reconnects
5. Confirm status shows **`warp=on`** (Connected alone is not enough)

Guides: [`Assets/Presets/README_WARP.md`](Assets/Presets/README_WARP.md) · [`Assets/Presets/README_GeoHide.md`](Assets/Presets/README_GeoHide.md)

---

## GeoHide WARP

Built for networks that actively filter Cloudflare (including Iranian DPI patterns):

```
Preflight → DPI fragment (handshake) → MASQUE / H2 → IRCF + CF CIDR probe
         → warp=on verify → stop DPI → optional Iran split-tunnel excludes
         → remember endpoint (24h) → structured session logs
```

| Control | Role |
|---------|------|
| **Censorship mode** | IRCF lists + Cloudflare WARP CIDR scan, MASQUE-first |
| **DPI assist** | GoodbyeDPI TLS ClientHello fragment **only during connect**, then stopped |
| **Low latency** | Iran/domestic excludes; keeps WARP DNS so sites like YouTube/X resolve through the tunnel |
| **Connect** | One button — remembered endpoints first, then full scan if needed |

**Diagnostics:** every attempt writes `UserData/GeoHideLogs/session-*.log` + `.jsonl`  
Phases worth reading: `env`, `decision`, `egress`, `attempt_result`, `cache`, `status_change`.

**Honest limits:** official `warp-cli` cannot fake MASQUE SNI or add QUIC noise. If Cloudflare edges are fully IP-blocked on your ISP, you need another tunnel family (e.g. Reality/VLESS) — GeoHide cannot invent a path that does not exist.

Inspired by [PyWarp](https://github.com/saeedmasoudie/pywarp); censorship techniques informed by IRCF, patterniha-style TCP scanning, and GFW-knocker-style TLS fragmentation.

---

## Core capabilities

### DNS & protocols

| Protocol | Example |
|----------|---------|
| DNSCrypt (STAMP) | `sdns://…` |
| Anonymized DNSCrypt | `sdns://…` + relay STAMP or `IP:PORT` |
| DoH | `https://…/dns-query` or `h3://…` |
| DoT | `tls://dns.quad9.net` |
| Plain DNS | `udp://1.1.1.1:53` / `tcp://8.8.8.8:53` |

Also: STAMP encode/decode, advanced DNS scanner (SafeSearch / YouTube / adult filters), Cloudflare clean IP scanner, startup connect, import/export settings.

### Share proxy (SNI bypass)

1. DNS server online and set to System  
2. Enable Fragment and/or SSL Decryption + Fake SNI  
3. Start Share proxy → set proxy to System  

### Text-based rules

```
Domain|Rules;
CIDR|Rules;
```

Useful rules: Fake DNS, custom DNS, DNS via upstream proxy, `dnsdomain:`, `proxy:`, `sni:`, Direct (`--;`), Block (`-;`).

GeoHide does **not** ship Shecan / gaming Smart DNS / upstream-proxy presets anymore — use **Tools → GeoHide WARP** so remotes see a Cloudflare exit IP. Full Rules syntax remains in Settings → Edit Rules.

---

## Requirements & notes

- **Windows only**
- Run as **Administrator** for GoodbyeDPI / WinDivert
- Antivirus often flags WinDivert as PUA — add an exclusion if needed
- After toggling **SSL Decryption**, restart the browser
- Open source under **GPL-3.0**

---

## What's new in v4.0.1

**GeoHide stays inside the main app**, with Official and Advanced WARP tabs. Iranian exits are clearly labeled and verified non-IR candidates are preferred.

**Advanced WARP (Xray)** is an optional backend inspired by BPB Worker Panel and BPB Warp Scanner. It supports single WARP, two-account WARP-on-WARP, configurable UDP noise, and real endpoint tests. The existing official WARP Auto/MASQUE/WireGuard mode remains available.

Open **Tools → GeoHide WARP**, then choose **Advanced WARP** inside the main DNSveil window. After accepting Cloudflare's terms for profile creation, scan endpoints and choose **Connect this PC**. Scans do not change routes; connection enables a TCP/UDP adapter only after WARP HTTPS and a matching UDP response pass. Advanced WARP requires verified outside-Iran exits by default; turn this off only for connectivity without a country-change requirement. Read the [complete setup guide](ADVANCED_WARP.md) before your first trial.

The portable x64 release includes checksum-pinned Xray, sing-box and signed Wintun components. Profiles are encrypted with Windows DPAPI; runtime configurations use restricted directories. Owned backend processes are stopped on disconnect/window close and tied to DNSveil's process lifetime.

**No live country change, full-device routing success on the affected network, or game/service access is claimed.** WARP-on-WARP is an experiment, and Cloudflare controls exit assignment. This is not a persistent kill switch. Country observations do not prove Spotify, ChatGPT or Where Winds Meet acceptance.

The 69 checks include validation by the actual pinned cores, real authenticated TCP/UDP forwarding through local fixtures, encrypted profile reuse, and process cleanup. No Cloudflare accounts are created and no system routes are installed by these tests. See [test instructions](Tests/RegressionTests/README.md), [release notes](RELEASE_NOTES.md), and [third-party notices](THIRD_PARTY_BACKENDS.md). Existing .NET 6/dependency warnings remain.

## Changelog (this fork)

Recent work focuses on GeoHide reliability under censorship:

| Version | Focus |
|---------|--------|
| **4.0.1** | Embedded GeoHide, shared connection tabs, explicit IR results and strict regional default |
| **4.0.0** | Optional Xray/WARP-on-WARP backend, configurable noise, real HTTPS/UDP scanning, PC routing, protected profiles and 69 checks |
| **3.9.0** | Auto protocol recovery, bounded real WireGuard handshakes, read-only connection reports, clearer strict country option and 44 checks |
| **3.8.0** | Experimental bounded exit-country search, separate IPv4/IPv6 verification, truthful country status and 32 regression checks |
| **3.7.0** | Responsive WARP operations, cancellation across recovery and preflight, bounded IP checks, 19 regression checks and Windows CI |
| **3.6.9** | Correct WARP fallback port and scanner limits; retain single-instance lock; add regression checks |
| **3.6.8** | IPv4-only handshake (stop [::]:0 happy-eyeballs); fake-packet DPI without splitting PQ ClientHello |
| **3.6.7** | Stop endpoint-reset/:2408 first shot; honor pasted IP:443; MASQUE without FakeTTL first; wait for warp-cli daemon |
| **3.6.6** | Restart warp-svc so MASQUE actually loads; pin TCP :443 if daemon still dials :2408 |
| **3.6.5** | Force MASQUE to stick on warp-cli 2026 (was silently using WireGuard :2408); taller tabs, GeoHide hero on Tools |
| **3.6.4** | MASQUE DPI ladder: fake-TTL / wrong-seq (survives TCP reassembly); honor Iran-mode checkbox |
| **3.6.3** | Honor Iran-mode checkbox (no auto-recheck); skip forced-IP scan on warp-cli 2026 |
| **3.6.2** | Default Cloudflare endpoint first; detached GoodbyeDPI; WireGuard fallback |
| **3.6.1** | Connect: mid-scan DPI escalate (Light→Medium→Mode5) + warp+doh; whole-app slate theme |
| **3.6.0** | Professional pass: GeoHide UI redesign + DNSveil shell branding; crash DNS/proxy cleanup; ProcessManager timeout kill; tray/exit clarity; Iran Light-DPI path kept |
| **3.5.14** | Restore proven Light-DPI path (Extreme hammer broke MASQUE); longer connect polls; soft settle; quality gate off under IR |
| **3.5.13** | Iran DPI hammer: escalate GoodbyeDPI profiles × MASQUE modes × more endpoints; faster stuck-Connecting rotate |
| **3.5.12** | GeoHide WARP-only: remove Shecan / Smart DNS / upstream-proxy presets (remotes see Cloudflare IPs) |
| **3.5.11** | Honor Protocol choice (WireGuard no longer forced to MASQUE); WG-only cache/scan when selected |
| **3.5.10** | Robust link quality gate (RTT + download + soak); reject weak endpoints and try next; health watch auto-rotates on timeout |
| **3.5.9** | Stability under DPI: MASQUE h2-only + high-timeouts; longer polls; settle checks; Iran excludes off by default (less jitter) |
| **3.5.8** | Remembered endpoints (24h); modeless GeoHide (main window can minimize); stronger Iran detection; WARP DNS kept for site compatibility; Refresh button fix; new README |
| **3.5.7** | Single Connect button; require `warp=on`; rich session logs |
| **3.5.6** | Gaming profile no longer drops proven tunnels; session logging |
| **3.5.5** | Faster connect; Iran/VPN preflight; WARP service auto-start |
| **3.5.4** | Minimize GeoHide; low-latency profile |
| **3.5.3** | Iran censorship mode (IRCF + CF CIDR + MASQUE/H2 + DPI assist) |
| **3.5.2** | Faster Clean IP Scanner & GeoHide probing |
| **3.5.1–3.4.0** | GeoHide foundation, fork-safe updates, proxy fail-closed, presets |

Full notes: [GitHub Releases](https://github.com/DanielNoohi/DNSveil/releases)

---

## Credits

Upstream by [MSasanMH](https://github.com/msasanmh/DNSveil).  
This repository is an independent fork maintained for GeoHide, censorship resilience, and related fixes.

[Upstream help videos](https://github.com/msasanmh/DNSveil/tree/main/Help) · [Guide (rentry)](https://rentry.co/SecureDNSClient)

---

<p align="center">
  <b>DNSveil</b> — resolve securely · bypass filters · exit through Cloudflare when you need to.
  <br/>
  <a href="https://github.com/DanielNoohi/DNSveil/releases/latest">Download latest release</a>
</p>

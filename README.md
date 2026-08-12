# DNSveil

**Secure DNS. DPI bypass. Optional Cloudflare exit — without renting a VPS.**

[![Release](https://img.shields.io/github/v/release/DanielNoohi/DNSveil?style=flat-square&label=release)](https://github.com/DanielNoohi/DNSveil/releases/latest)
[![License](https://img.shields.io/github/license/DanielNoohi/DNSveil?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D4?style=flat-square)](#requirements)
[![.NET](https://img.shields.io/badge/.NET-6-512BD4?style=flat-square)](#requirements)

A hardened fork of [msasanmh/DNSveil](https://github.com/msasanmh/DNSveil) (Secure DNS Client) with **GeoHide WARP**, Iran-aware connect paths, Smart DNS presets, and production-minded reliability work.

**Latest:** [v3.5.8](https://github.com/DanielNoohi/DNSveil/releases/latest) · [Download portable x64](https://github.com/DanielNoohi/DNSveil/releases/latest)

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

When DNS alone is not enough:

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

Presets under `Assets/Presets/`:

- Shecan-style anti-sanction Smart DNS  
- Gaming Smart DNS template  
- Via upstream proxy template  

Import from GeoHide or Settings → Edit Rules. After import, rules re-apply to a running DNS / Share proxy.

Full syntax examples remain in the upstream docs and the rules editor.

---

## Requirements & notes

- **Windows only**
- Run as **Administrator** for GoodbyeDPI / WinDivert
- Antivirus often flags WinDivert as PUA — add an exclusion if needed
- After toggling **SSL Decryption**, restart the browser
- Open source under **GPL-3.0**

---

## Changelog (this fork)

Recent work focuses on GeoHide reliability under censorship:

| Version | Focus |
|---------|--------|
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

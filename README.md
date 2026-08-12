# DNSveil (DanielNoohi fork)

Fork of [msasanmh/DNSveil](https://github.com/msasanmh/DNSveil) (formerly Secure DNS Client) with **GeoHide WARP**, Smart DNS rule presets, and related fixes.

**Current release:** [v3.5.5](https://github.com/DanielNoohi/DNSveil/releases/tag/v3.5.5)

![GitHub](https://img.shields.io/github/license/DanielNoohi/DNSveil)
![GitHub release](https://img.shields.io/github/v/release/DanielNoohi/DNSveil)

**A Secure DNS Client.** Using: _[Msmh Agnostic Server](https://github.com/msasanmh/MsmhAgnosticServer)_, _[DNSLookup](https://github.com/ameshkov/dnslookup)_ and _[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)_. (Windows only)

Client implementation: _DNSCrypt, Anonymized DNSCrypt, DoH, DoT and Plain DNS (UDP & TCP)._<br>
Server implementation: _DoH and Plain DNS (UDP & TCP)._

- *Find and use fastest secure DNS servers.*
- *Hide SNI and website addresses from ISP (Fragment or Fake SNI).*
- *Bypass YouTube, Twitter and any SNI/DNS based blocked websites.*
- *Encode and decode DNSCrypt STAMP (sdns://).*
- *Share to other devices via Proxy (HTTP, HTTPS, SOCKS4, SOCKS4A, SOCKS5).*
- *Optional GeoHide via Cloudflare WARP (`warp-cli`) when remotes must not see your ISP IP (no VPS required).*

**Requirements:** `.NET Desktop Runtime 6` and `ASP.NET Core Runtime 6`

For x64:\
First install [.NET Desktop Runtime x64 v6.0.36](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-6.0.36-windows-x64-installer)\
Then install [ASP.NET Core Runtime x64 v6.0.36](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-aspnetcore-6.0.36-windows-x64-installer)

For x86:\
First install [.NET Desktop Runtime x86 v6.0.36](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-6.0.36-windows-x86-installer)\
Then install [ASP.NET Core Runtime x86 v6.0.36](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-aspnetcore-6.0.36-windows-x86-installer)

[Microsoft .NET 6.0 Runtime Page](https://dotnet.microsoft.com/en-us/download/dotnet/6.0)

**Download:**\
[This fork â€” latest release](https://github.com/DanielNoohi/DNSveil/releases/latest) Â· [Upstream releases](https://github.com/msasanmh/DNSveil/releases/latest)

---

### What's new in this fork (v3.5.5)
* **Faster Auto-find:** fewer candidates/attempts, MASQUE-only scan (no slow WG second pass), Iran excludes cached once, no WG upgrade by default.
* **Preflight:** detects Iran IP / existing WARP / other VPN adapters; warns on conflicts; auto-starts `CloudflareWARP` service if stopped.
* **Option clarity:** DPI assist only during handshake; low-latency after connect — complementary, not conflicting.

### What's new in this fork (v3.5.4)
* **GeoHide minimize:** title-bar minimize + Minimize button (dialog could not minimize before).
* **Gaming / low latency:** stop GoodbyeDPI after connect (WinDivert was adding latency), `tunnel_only` mode (DNSveil keeps DNS), try WireGuard upgrade after MASQUE, exclude Iran/domestic ranges from the tunnel.

### What's new in this fork (v3.5.3)
* **Iran censorship mode for GeoHide:** IRCF live endpoints + Cloudflare WARP CIDR clean-IP scan, MASQUE/H2-first (`h3-with-h2-fallback`), optional GoodbyeDPI TLS ClientHello fragment (GFW-knocker-style) before connect.
* Auto-find defaults to censorship path; protocol default **MASQUE**.

### What's new in this fork (v3.5.2)
* **Faster Clean IP Scanner:** parallel probes (default 48, adjustable), TCP-first then HTTPS, optional ping off by default, shorter timeouts.
* **Faster GeoHide auto-find:** parallel TCP reachability prefilter, shorter WARP status polls, skips redundant checks during auto-scan.

### What's new in this fork (v3.5.1)
* **GeoHide WARP reliability:** strict Connected parsing (no more "Not Connected" false positives), `warp=on` egress verification, longer connect polls, service-running check, Cancel resets endpoint, MASQUE fallback syncs protocol UI.
* **Rules that stick:** importing presets re-applies rules to a running DNS / Share proxy; Shecan / gaming / upstream presets selectable in the GeoHide window.
* **Update check:** fork-only channel (won't advertise upstream SDC as this fork), `finally` clears "checking" lock, proxy retry on fork URL.
* **Proxy fail-closed:** rules that set an upstream equal to this server deny the request instead of leaking Direct.
* **DPI layout:** GeoHide Tools button follows High-DPI repositioning under Benchmark.
* Product name shown as **DNSveil**.
### What's new in this fork (v3.4.1)
* **Bugfix:** Fake SNI / DPI bypass no longer breaks under the tightened TLS callback (name-mismatch allowed).
* **GeoHide WARP:** safer `warp-cli` I/O, registration detection, connect polling, cancel, protocol-aware endpoints, `warp=on` IP status.
* **Shecan preset:** removed Cloudflare/Google catch-alls that conflicted with WARP; Rules button no longer hijacked by GeoHide dialogs.

### What's new in this fork (v3.4.0)
* **Tools â†’ GeoHide WARP** â€” drive official Cloudflare WARP from the app (PyWarp-style `warp-cli`: endpoints, WireGuard/MASQUE, auto-find).
* **Rules presets** in `Assets/Presets/` â€” Shecan anti-sanction, gaming Smart DNS template, upstream-proxy template.
* **Safer defaults** â€” update check without `AllowInsecure`; TLS validation honors `AllowInsecure` but still allows Fake-SNI name mismatches; DNS upstream equal to local server fails closed.
* README clarifies that encrypted DNS alone does not change your public IP.

---

### Notes
* **Encrypted DNS is not a VPN.** DoH/DoT/DNSCrypt hide DNS queries from your ISP; they do **not** by themselves change the IP address that websites or apps see.
* Optional **GeoHide WARP** (Tools tab) drives official Cloudflare WARP (`warp-cli`) so destinations see a Cloudflare exit IP. Install [Cloudflare WARP](https://one.one.one.one/) first. See [`Assets/Presets/README_WARP.md`](Assets/Presets/README_WARP.md).
* Smart DNS providers (e.g. Shecan) only affect domains they proxy; they are not a full IP hide.
* Open source (GPL-3.0). Antivirus alerts are often False-Positive â€” WinDivert (GoodbyeDPI) is commonly flagged as PUA; add exclusions if needed.
* After changing `Enable SSL Decryption` restart your browser for the change to take effect.

---

### Features
* Connect with built-in servers or use your own custom servers.
* Find fastest DNS Servers.
* Bypass any SNI/DNS based blocked websites by Fragment and Fake SNI.
* Create local Plain DNS and DoH Servers.
* Supports per domain rules (including Smart DNS and upstream proxy rules).
* **GeoHide WARP:** connect/disconnect Cloudflare WARP from Tools, with custom endpoints when defaults are blocked (inspired by [PyWarp](https://github.com/saeedmasoudie/pywarp)).
* Advanced DNS Scanner.
    - Detection of Google safe search.
    - Detection of Bing safe search.
    - Detection of blocked or restricted Youtube.
    - Detection of blocked Adult Content.
    - Export online servers based on condition.
* DNS Lookup.
* Cloudflare clean IP scanner.
* Can Read/Modify/Generate STAMP (sdns://) URLs.
* Run and connect on Windows Startup.
* Import servers from text files.
* Extract and import servers from URLs.
* Double-Click on a custom server to get info and status.
* Import/Export all settings.

---

### GeoHide quick start
1. Install [Cloudflare WARP](https://one.one.one.one/) (provides `warp-cli`).
2. Run DNSveil â†’ **Tools â†’ GeoHide WARP**.
3. Click **Connect** (or **Auto-find endpoint** if connect fails).
4. Confirm **Public IP** is Cloudflare, then use your apps.
5. Optional: import Shecan rules for sanctioned websites (same window).

More: [`Assets/Presets/README_GeoHide.md`](Assets/Presets/README_GeoHide.md) Â· [`Assets/Presets/README_WARP.md`](Assets/Presets/README_WARP.md)

---

### Supported Protocols
* **DNSCrypt**
    - Must be in STAMP format. e.g.
        - `sdns://AQcAAAAAAAAAETg5LjM4LjEzMS4zODo0MzQzIKWHS9r0FoKY--wcnJl1Ar5aOUb91xsufvPUjid3rNRaHzIuZG5zY3J5cHQtY2VydC5hbXMtZG5zY3J5cHQtbmw`
* **Anonymized DNSCrypt**
    - Pattern: `<DNSCrypt Server in STAMP format>` `<Space>` `<DNSCrypt Relay>`
    - `<DNSCrypt Relay>` can be in STAMP or IP:PORT format.
    - Example:
        - `sdns://AQcAAAAAAAAAETg5LjM4LjEzMS4zODo0MzQzIKWHS9r0FoKY--wcnJl1Ar5aOUb91xsufvPUjid3rNRaHzIuZG5zY3J5cHQtY2VydC5hbXMtZG5zY3J5cHQtbmw sdns://gQ4xNzcuNTQuMTQ1LjEzMQ`
        - `sdns://AQcAAAAAAAAAETg5LjM4LjEzMS4zODo0MzQzIKWHS9r0FoKY--wcnJl1Ar5aOUb91xsufvPUjid3rNRaHzIuZG5zY3J5cHQtY2VydC5hbXMtZG5zY3J5cHQtbmw 177.54.145.131:443`
* **DoH (DNS Over HTTPS)**
    - Example (HTTP/2):
        - `https://max.rethinkdns.com/dns-query`
    - Example (HTTP/3):
        - `h3://max.rethinkdns.com/dns-query`
* **DoT (DNS Over TLS)**
    - Example:
        - `tls://dns.quad9.net`
* **Plain DNS (UDP & TCP)**
    - Example:
        - `udp://8.8.8.8:53`
        - `tcp://1.1.1.1:53`

---

### Proxy Server
* Proxy server is used to bypass SNI/DNS based blocked websites.
* How to use:
    1. DNSveil DNS Server must be online and set to System.
    2. At least one of DPI Bypass options must be active.
        - Fragment
        - SSL Decryption (by installing self-signed root certificate authority)
            - Enable `Change SNI` and provide a fake SNI.
    3. Start Proxy Server.
    4. Set Proxy to System.

---

### DNSveil Text Based Rules
* Syntax (wildcard is supported for domain):
    - `Domain` `|` `Rules` `;`
    - `CIDR` `|` `Rules` `;`
    - `IPv4` `|` `Rules` `;`
    - `IPv6` `|` `Rules` `;`
* Rules:
    - Fake DNS (forward a domain to your desired IP address):\
    `example.com|127.0.0.1;`
    - Use a custom DNS for a domain:\
    `example.com|dns:https://max.rethinkdns.com/dns-query;`
    - Use a custom and blocked DNS by an upstream proxy:\
    `example.com|dns:https://max.rethinkdns.com/dns-query;dnsproxy:socks5://127.0.0.1:1080;`
    - DNS Domain (Get IP for a domain and use it for another domain):\
    `youtube.com|dnsdomain:google.com;`
    - Use upstream proxy for a domain (only socks5 and http are supported):\
    `example.com|proxy:socks5://127.0.0.1:1080;`\
    `example.com|proxy:http://127.0.0.1:1080;`
    - Use upstream proxy with user and pass:\
    `example.com|proxy:socks5://127.0.0.1:1080&user:UserName&pass:PassWord;`
    - Set a custom/fake SNI for a domain:\
    `*.googlevideo.com|sni:google.com;`
    - Direct: Don't apply DPI bypass and upstream proxy for a domain:\
    `example.com|--;`\
    `*.example.com|--;`
    - Block a domain and all its sub-domains:\
    `example.com|-;`\
    `*.example.com|-;`
    - Block CIDR (IP Range):\
    `224.0.0.0/3|-;`\
    `fe80::/10|-;`
<br><br>
* Example of Rules file:
<br>

```
// Variables
SmartDns1 = https://one.YourSmartDnsServer.net/dns-query;
SmartDns2 = https://two.YourSmartDnsServer.net/dns-query;
SmartDns3 = https://three.YourSmartDnsServer.net/dns-query;

// Defaults
blockport:53,80;

// YouTube
youtube.com|dnsdomain:google.com;sni:google.com;
ytimg.com|dnsdomain:google.com;
*.ytimg.com|dnsdomain:google.com;
ggpht.com|dnsdomain:google.com;
*.ggpht.com|dnsdomain:*.googleusercontent.com;
*.googleapis|dnsdomain:google.com;
*.googlevideo.com|dnsdomain:*.c.docs.google.com;sni:google.com;

// Use Smart DNS For These Domains
developers.google.com|--;dns:SmartDns1,SmartDns2,SmartDns3;
*.googleusercontent.com|--;dns:SmartDns1,SmartDns2,SmartDns3;
developer.android.com|--;dns:SmartDns1,SmartDns2,SmartDns3;
gemini.google.com|--;dns:SmartDns1,SmartDns2,SmartDns3;
*.openai.com|--;dns:SmartDns1;
claude.ai|--;dns:SmartDns1,SmartDns2,SmartDns3;
*.claude.ai|--;dns:SmartDns1,SmartDns2,SmartDns3;
spotify.com|--;dns:SmartDns1,SmartDns2,SmartDns3;
*.spotify.com|--;dns:SmartDns1,SmartDns2,SmartDns3;

// Don't Apply DPI Bypass To These Domains
google.com|--;
*.google.com|--;
github.com|--;
*.github.com|--;
githubusercontent.com|--;
*.githubusercontent.com|--;
stackoverflow.com|--;
*.stackoverflow.com|--;
*.sstatic.net|--;
*.cookielaw.org|--;
every1dns.com|--;
*.every1dns.com|--;
nslookup.io|--;
*.nslookup.io|--;
php.net|--;
save.tube|--;

// Apply Defaults To Other Domains
*|+;
```

---

### GeoHide (optional)
* **Goal:** make destinations see a non-ISP exit IP when DNS alone is not enough.
* **Tools â†’ GeoHide WARP:** requires [Cloudflare WARP](https://one.one.one.one/); uses `warp-cli` (connect, custom endpoints, WireGuard/MASQUE).
* **Rules presets** under `Assets/Presets/`: Shecan anti-sanction, gaming Smart DNS template, upstream-proxy template. Import from Settings â†’ Edit Rules.
* More detail: [`Assets/Presets/README_GeoHide.md`](Assets/Presets/README_GeoHide.md), [`Assets/Presets/README_WARP.md`](Assets/Presets/README_WARP.md).

---

### Credits
Upstream project by [MSasanMH](https://github.com/msasanmh/DNSveil). This repository is an independent fork with GeoHide and maintenance patches.

[Help videos (upstream)](https://github.com/msasanmh/DNSveil/tree/main/Help) Â· [Guide](https://rentry.co/SecureDNSClient)



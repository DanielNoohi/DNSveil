# Cloudflare WARP GeoHide (via DNSveil)

## Approach (from PyWarp + Iran DPI research)

[PyWarp](https://github.com/saeedmasoudie/pywarp) drives the **official Cloudflare WARP** app through `warp-cli`.

Under Iranian filtering we combine that with techniques from:

- [GFW-knocker/gfw_resist_tls_proxy](https://github.com/GFW-knocker/gfw_resist_tls_proxy) — **TLS ClientHello fragmentation** so DPI cannot reassemble blacklisted SNI on Cloudflare edges
- [patterniha/cf-scanner](https://github.com/patterniha/cf-scanner) — **TCP** reachability (not ICMP ping, which is unreliable in Iran)
- [IRCF endpoints](https://github.com/ircfspace/endpoint) — community-curated Warp/MASQUE `IP:port` lists

DNSveil’s **Tools → GeoHide WARP** window:

1. Optional **DPI assist** starts GoodbyeDPI (fragment) before `warp-cli connect`
2. Forces **MASQUE** with `h3-with-h2-fallback` (when QUIC/H3 is blocked, falls to HTTP/2 TCP — where fragment works)
3. Fetches IRCF endpoints + samples Cloudflare WARP CIDRs (`162.159.192–199`, `188.114.96–99`)
4. Parallel TCP probes, then connect attempts on the fastest hosts

## Why this changes what remotes see

Traffic leaves through Cloudflare’s network. Destinations see a **Cloudflare exit IP**, not your ISP address.

## Steps (Iran / heavy DPI)

1. Install [Cloudflare WARP](https://one.one.one.one/) (includes `warp-cli`). Open it once, accept ToS.
2. Run DNSveil **as Administrator** (needed for GoodbyeDPI / WinDivert).
3. **Tools → GeoHide WARP**
4. Leave **Censorship mode** and **DPI assist** checked.
5. Protocol = **MASQUE**. Click **Auto-find**.
6. Confirm Public IP shows `warp=on` and a non-Iran location when possible.
7. Optional: import Shecan anti-sanction rules for websites.

## Hard limits of official `warp-cli`

- Cannot change MASQUE SNI (tools like [usque](https://github.com/Diniboy1123/usque) / masque-plus can).
- Cannot add QUIC noise obfuscation (vwarp-style).
- If Cloudflare engage/MASQUE IPs are **fully IP-blocked** on your ISP, you need an alternate tunnel (VLESS/Reality, etc.) — GeoHide cannot invent a path that does not exist.

## Notes

- Low-latency/gaming sets `tunnel_only` **before** connect and does not re-apply mode after a proven tunnel (re-applying dropped sessions).
- Each Connect/Auto-find writes diagnostics under `UserData/GeoHideLogs/` (`session-*.log` + `session-*.jsonl`) for later debugging.
- Core DNSveil features (DoH, Share Fragment) still do **not** replace a tunnel for IP hiding; WARP is the GeoHide companion.

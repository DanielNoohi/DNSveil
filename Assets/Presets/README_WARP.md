# Cloudflare WARP GeoHide (via DNSveil)

## Approach (from PyWarp + Iran DPI research)

[PyWarp](https://github.com/saeedmasoudie/pywarp) drives the **official Cloudflare WARP** app through `warp-cli`.

Under Iranian filtering we combine that with techniques from:

- [GFW-knocker/gfw_resist_tls_proxy](https://github.com/GFW-knocker/gfw_resist_tls_proxy) — **TLS ClientHello fragmentation** so DPI cannot reassemble blacklisted SNI on Cloudflare edges
- [patterniha/cf-scanner](https://github.com/patterniha/cf-scanner) — **TCP** reachability (not ICMP ping, which is unreliable in Iran)
- [IRCF endpoints](https://github.com/ircfspace/endpoint) — community-curated Warp/MASQUE `IP:port` lists

DNSveil’s **Tools → GeoHide WARP** window:

1. Optional **DPI assist** starts a MASQUE GoodbyeDPI **ladder** before `warp-cli connect`:
   - **FakeTTL** — fake ClientHello with low TTL (DPI sees it, Cloudflare does not)
   - **WrongSeq** — fake packets with past TCP SEQ (desyncs stateful DPI that reassembles fragments)
   - **FakeSeqTTL** — both
   - **LightFrag** — TLS ClientHello split (older DPI)
   - **Mode9 / FakeSNI** — only if `goodbyedpi.exe` is new enough (`-q`, `--fake-with-sni`)
2. Under Iran mode: **MASQUE** with **`h2-only`** + high-timeouts (HTTP/2 TCP — where GoodbyeDPI works). Forced engage IPs are skipped on warp-cli 2026 (they go Unable).
3. If h2 fails: **h3-with-h2-fallback**, then **WireGuard** default.

## Why this changes what remotes see

Traffic leaves through Cloudflare’s network. Destinations see a **Cloudflare exit IP**, not your ISP address.

## Steps (Iran / heavy DPI)

1. Install [Cloudflare WARP](https://one.one.one.one/) (includes `warp-cli`). Open it once, accept ToS.
2. Run DNSveil **as Administrator** (needed for GoodbyeDPI / WinDivert).
3. **Tools → GeoHide WARP**
4. Leave **Iran mode** and **DPI assist** checked.
5. Protocol = **MASQUE** (or WireGuard if UDP works). Click **Connect**.
6. Confirm Public IP shows `warp=on` — remotes (including game servers) see a **Cloudflare** exit IP.

## Hard limits of official `warp-cli`

- Cannot change MASQUE SNI (tools like [usque](https://github.com/Diniboy1123/usque) / masque-plus can).
- Cannot add QUIC noise obfuscation (vwarp-style).
- If Cloudflare engage/MASQUE IPs are **fully IP-blocked** on your ISP, you need an alternate tunnel (VLESS/Reality, etc.) — GeoHide cannot invent a path that does not exist.

## Notes

- Low-latency/gaming keeps **WARP DNS** (not `tunnel_only`) so sites resolve through the tunnel.
- Iran split-tunnel excludes stay **off by default** (they often hurt stability under DPI).
- Successful endpoints are remembered for **24 hours** (`UserData/GeoHideSuccessCache.json`) and tried before a full scan.
- Success requires Cloudflare trace `warp=on`; under Iran mode the accept quality gate stays soft/off and health watch rotates weak links.
- Each Connect writes diagnostics under `UserData/GeoHideLogs/`.
- **No Smart DNS / Shecan / upstream-proxy presets** — GeoHide is WARP-only so remotes see Cloudflare IPs.

# GeoHide without your own VPS

## What changes the IP remotes see?

| Approach | Changes public IP? | Notes |
|---|---|---|
| Encrypted DNS only (DoH/DoT/DNSCrypt) | No | Hides DNS from ISP |
| Shecan / 403 Smart DNS | Only for domains they proxy | Web/dev anti-sanction |
| Shelter / Radar (gaming Smart DNS) | Only for games they list | Confirm coverage first |
| DNSveil Share + system HTTP proxy | Rarely for games/UDP | Browsers mainly |
| Upstream `proxy:` rules + Proxifier | Yes (proxy exit) | Needs a foreign SOCKS/HTTP |
| **Tools → GeoHide WARP** | **Yes (Cloudflare exit)** | No VPS; needs Cloudflare WARP |

DNS alone does not hide your IP. Remotes see the TCP/UDP source address.

## Path A — Smart DNS presets

1. **Anti-sanction (Shecan):** `Rules_ShecanShelter_AntiSanction.txt` — websites/devtools.
2. **Gaming Smart DNS:** `Rules_GamingSmartDns_ShelterRadar.txt` — edit in your game domains after checking Shelter/Radar coverage.
3. Import via **Settings → Edit Rules** (GeoHide import dialog) or Tools → GeoHide WARP (Shecan button).

## Path B — Cloudflare WARP (recommended, no VPS)

**Tools → GeoHide WARP** drives official `warp-cli` (same idea as [PyWarp](https://github.com/saeedmasoudie/pywarp)):

1. Install [Cloudflare WARP](https://one.one.one.one/).
2. Connect (or Auto-find endpoint if the ISP blocks defaults).
3. Confirm Public IP is Cloudflare, then use your apps.

See **`README_WARP.md`**.

## Path C — Your own upstream proxy

Import `Rules_ViaUpstreamProxy.txt`, set `GeoHideProxy=`, run Share proxy, force apps through local SOCKS if needed.

## Bottom line

Use **GeoHide WARP** when you need remotes to see a non-local IP and you have no VPS. Use Shecan/gaming Smart DNS only for domains those providers actually cover.

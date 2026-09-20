# GeoHide = Cloudflare WARP only

Game servers and websites should see a **Cloudflare exit IP**, not your ISP.

| Approach | Changes public IP? |
|---|---|
| Encrypted DNS only | No |
| Smart DNS (Shecan / Shelter / etc.) | Only for domains they proxy — **removed from DNSveil GeoHide** |
| **Tools → GeoHide WARP** | **Yes — Cloudflare exit** |

## How

1. Install [Cloudflare WARP](https://one.one.one.one/).
2. **Tools → GeoHide WARP** → Connect (**Iran mode** + **DPI assist** under Iranian DPI).
3. Confirm Public IP / `warp=on` (Cloudflare), then play.

Iran path uses **GoodbyeDPI Light** + MASQUE **h2-only** (proven). See **`README_WARP.md`**.

# Cloudflare WARP GeoHide (via DNSveil)

## Approach (from PyWarp)

[PyWarp](https://github.com/saeedmasoudie/pywarp) drives the **official Cloudflare WARP** app through `warp-cli` instead of reinventing WireGuard registration:

- `warp-cli connect` / `disconnect` / `status`
- `warp-cli tunnel endpoint set IP:port` (when ISPs block defaults)
- `warp-cli tunnel protocol set WireGuard|MASQUE`
- `warp-cli mode warp`
- `warp-cli registration new` + `accept-tos`

DNSveil’s **Tools → GeoHide WARP** window mirrors that flow.

## Why this changes what remotes see

Traffic leaves through Cloudflare’s network. Destinations see a **Cloudflare exit IP**, not your ISP address. Encrypted DNS or Shecan-style Smart DNS alone cannot do that for arbitrary apps.

## Steps

1. Install [Cloudflare WARP](https://one.one.one.one/) (includes `warp-cli`).
2. Close the official WARP UI if it conflicts (same tip as PyWarp).
3. Open DNSveil → **Tools → GeoHide WARP**.
4. Click **Connect**, or **Auto-find endpoint** if connect fails (tries CF anycast IPs + common ports).
5. Confirm **Public IP** is not your home ISP.
6. Optional: import Shecan anti-sanction rules for websites.
7. Use your applications while status stays Connected.

## Notes

- Full WARP mode is used (simplest reliable IP change). Consumer “exclude” split-tunnel lists *bypass* WARP — the opposite of hiding your IP.
- If every endpoint fails, the ISP may be blocking WARP — try MASQUE, another network, or a commercial VPN.
- Core DNSveil features (DoH, fragment, etc.) still do **not** replace a tunnel for IP hiding; WARP is an optional companion controlled from the Tools tab.

# Optional Xray WARP backend

DNSveil's profile generator and scanner are independently implemented, inspired by the GPL-3.0 [BPB Worker Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel) and [BPB Warp Scanner](https://github.com/bia-pain-bache/BPB-Warp-Scanner). Thank you to those projects for documenting two-account WARP chaining and real tunnel tests.

The portable x64 release includes unmodified upstream components:

- [Xray-core v26.3.27](https://github.com/XTLS/Xray-core/tree/v26.3.27), MPL-2.0. Its license accompanies the executable.
- [sing-box v1.14.1](https://github.com/SagerNet/sing-box/tree/v1.14.1), GPL-3.0-or-later; see the accompanying license. Corresponding source for this unmodified release is available at the linked tag and in the DNSveil release source archives.
- Signed Wintun DLL distributed with Xray, under its accompanying prebuilt-binary license. See [Wintun](https://www.wintun.net/).

`Scripts/Restore-XrayBackends.ps1` downloads exact release archives, verifies their pinned SHA-256 values, and extracts only named files. Runtime checks also verify executable and driver hashes. No upstream installers or remote scripts are executed.

WARP profiles use Cloudflare's registration service and require acceptance of Cloudflare's terms in the app. The registration API is not guaranteed stable. Keys are protected with Windows DPAPI for the current user; temporary process configuration files are restricted to that user and SYSTEM and deleted on cleanup. Profiles cannot be transferred by copying the encrypted file to another Windows account.

This is an experimental connection backend, not a guarantee of foreign-country assignment or service access. Full-device mode carries TCP and UDP through a TUN adapter and requests strict routing while active; it is not a persistent kill switch. Closing the advanced window stops its owned backend processes.

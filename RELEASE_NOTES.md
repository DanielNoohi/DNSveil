# DNSveil v3.6.9

## Latest bug fixes

- Correct WARP endpoint selection after fallback: if TCP port 443 fails but 8443 responds, retain 8443 for the connection attempt.
- Honor candidate and reachability result limits, including zero and negative limits.
- Keep the single-instance mutex alive throughout the app session, release it on shutdown, and handle abandoned mutex ownership after a crash.
- Add six local regression checks covering scanner limits and fallback selection.

## Previously unpublished changes since v3.5.11

This release also includes the local development changes documented as v3.5.12 through v3.6.8:

- Revised GeoHide WARP connection flows, MASQUE preferences, daemon readiness checks, and DPI-assist profiles.
- Updated GeoHide controls, application branding, dark styling, high-DPI layout, and tray messaging.
- Process timeout cleanup and startup connectivity handling updates.
- WARP-focused guides and removal of the bundled Smart DNS / upstream-proxy presets. Custom rules remain available.

## Validation and limitations

- Application build succeeds and all six local scanner regression checks pass.
- Release packaging targets Windows x64 and requires .NET Desktop 6 and ASP.NET Core 6 runtimes.
- Live WARP connectivity and the full interactive UI have not been tested for this release.
- Existing .NET 6 and dependency compatibility warnings remain.

## Download

Download `SecureDNSClientPortable_v3.6.9_x64.7z`, extract it, and run `SecureDNSClientPortable.exe`. Administrator privileges are required for DPI / WinDivert functionality. SHA-256 verification is provided in `SHA256SUMS.txt`.

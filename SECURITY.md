# Security Policy

## Reporting
This is an open-source forensic tool for lawful examiners. If you find a
security issue (e.g., the web studio's loopback binding, path handling in
keybag/escrow tools, or the warrant gate), report it privately:

- GitHub: create a private issue on xanstomper/coreprobe
- Do NOT include device data or case material in reports

## Web studio
- Binds 127.0.0.1 only by default (OPENSLEUTH_HOST override).
- No built-in auth: never expose on public interfaces.
- File-path endpoints (/api/escrow, /api/keybag, /api/appcatalog) are
  loopback-only by design; treat them as workstation-local.

## Acquisition ethics
- iCloud acquisition refuses to run without --warrant.
- Escrow tooling is for consented/warranted devices and their paired
  computers.
- Evidence integrity: use `opensleuth certify` for chain-of-custody.

## Supported
- Python 3.9+ (3.12 tested), CMake/g++ for the native core.
- Ubuntu/Debian primary; macOS usable.

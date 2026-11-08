# Changelog

## 0.2.0 — 2026-11-07

### Changed
- **Legacy AmneziaWG 2.0 replaced with classic WireGuard** (`amnezia-wireguard`
  container): the official client dropped AWG 2.0. The image is built locally
  from a vendored Dockerfile (no hub pull), exactly as the client does.
  An old `amnezia-awg` container stays visible in Info as unmanaged — remove it
  (`docker rm -f amnezia-awg`) and reinstall WireGuard from the panel; keys do
  not migrate.
- Key description now carries a geo suffix: `name | CC-CITY`
  (e.g. `phone-ivan | NL-AMS`), falling back to the protocol name when
  geolocation is unavailable.
- `syncconf` no longer calls `wg-quick strip` — the panel ships its own strip;
  `syncconf` uses the per-protocol binary (`wg` / `awg`), as the client does.

### Added
- Loading overlay for long-running actions (protocol/service deploy, key issue).
- WireGuard container start.sh fallback: if `wg-quick` is broken by the host
  AppArmor profile (Ubuntu 24.04+, bug #2123870), the interface is brought up
  with direct `ip`/`wg` commands.
- Config editor rejects AWG obfuscation keys in a classic WireGuard config
  (`wg-quick` would crash on them).

### Fixed
- Per-container key layout paths (clientsTable/server keys) — no longer
  hardcoded to the legacy AWG directory.

### Known issues
- The Amnezia app does not pick up panel-side changes: edits to server configs
  and protocol/service removal are not reflected in the client (it caches the
  server configuration locally). Under investigation.

## 0.1.0

- Info (containers, host geo), WireGuard/AWG keys with vpn:// + QR,
  MTProxy/Telemt/DNS pages, one-click deploy, config editor with
  backups/restore, session auth with anti-brute-force lockout.

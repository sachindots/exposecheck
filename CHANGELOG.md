# Changelog

All notable changes to exposecheck are documented in this file.

## [v0.1.2] - 2026-11-10

- Added `--version` flag to print build version and exit 0 (#11).
- Added `--only public` flag to filter text and JSON reports to public listeners and findings (#12).

## [v0.1.1] - 2026-11-09

- Added `bridge` address classification for `docker0`, `br-*`, and `virbr*` interfaces so bridge addresses raise no findings (#9).
- Updated showcase demo script and assets to run against a real throwaway container (#10).

## [v0.1.0] - 2026-11-09

- Initial release.
- Scanned `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6` for listening sockets (#1).
- Classified listener addresses into `public`, `local`, and `tailnet` (#1).
- Resolved owning process PID and command name from `/proc/*/fd` and `/proc/<pid>/comm` (#3).
- Audited host firewall rules in `ufw`, `iptables`, and `nft` for unblocked public ports (#4).
- Audited Docker published ports bound to `0.0.0.0` or `[::]` that bypass host firewalls (#5).
- Output reports in human-readable text and JSON (`--json`), with exit codes 0 (clean), 1 (findings), and 2 (error) (#6).
- Added project documentation and terminal demo showcase (#7, #8).
- Added CI workflow for tests, vet, and formatting (#2).

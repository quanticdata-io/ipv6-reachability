# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-18

### Added

- `sites`: follows each target's redirects and checks A and AAAA records of every host on the way; verdicts `ipv6-ready`, `partial`, `ipv4-only`, `unknown`; optional DNS-over-HTTPS, redirects through a proxy, direct IPv6 connection test; table, JSON and CSV; `--fail-on-ipv4-only`.
- `exits`: samples an IP echo through a proxy and counts IPv6 and IPv4 exits, distinct addresses, /64 and /48 prefixes; `--expect-ipv6` and `--min-64` checks.
- QuanticData IPv6 plans: proxy strings generated with `--qd-order`.

[Unreleased]: https://github.com/quanticdata-io/ipv6-reachability/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/quanticdata-io/ipv6-reachability/releases/tag/v0.1.0

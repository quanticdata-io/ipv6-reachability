# ipv6-reachability

[![CI](https://github.com/quanticdata-io/ipv6-reachability/actions/workflows/ci.yml/badge.svg)](https://github.com/quanticdata-io/ipv6-reachability/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

IPv6 proxies are cheap and plentiful, but they only reach sites that answer over IPv6. This tool answers the two questions to settle before you buy or route traffic through them:

1. **`sites`**: which of my targets can an IPv6-only client actually load? It follows each site's redirects and checks the AAAA records of **every host on the way**, because a site can have IPv6 on the bare domain and redirect to a `www` or regional host that has none (or the other way round).
2. **`exits`**: does my proxy really exit over IPv6, and from how many distinct addresses, **/64** and **/48** prefixes? Sites that rate-limit IPv6 usually do it per prefix, so the number of prefixes matters more than the number of addresses.

It is a single Go binary with no dependencies outside the standard library, and works with any HTTP, HTTPS or SOCKS5 proxy.

```text
$ ipv6-reachability sites --doh https://cloudflare-dns.com/dns-query google.com duckduckgo.com wikipedia.org
TARGET                             VERDICT     LANDS ON                                 NOTE
google.com                         ipv6-ready  https://www.google.com/
duckduckgo.com                     ipv4-only   https://duckduckgo.com/                  no AAAA: duckduckgo.com
wikipedia.org                      ipv6-ready  https://www.wikipedia.org/
(redirects followed directly)

3 targets: 2 ipv6-ready, 0 partial, 1 ipv4-only, 0 unknown
```

(Run on 18 November 2026. DNS records change; run it yourself on your own targets.)

## Install

```sh
go install github.com/quanticdata-io/ipv6-reachability/cmd/ipv6-reachability@latest
```

Go 1.22 or later. No binaries are published yet; `go install` builds from source.

## sites

```sh
ipv6-reachability sites [flags] TARGET...
ipv6-reachability sites -f targets.txt --csv > ipv6.csv
```

A target is a domain (`example.com`, checked as `https://example.com/`) or a URL. For each target the tool:

1. requests the URL and follows redirects (up to 10), reading at most 64 KB of each answer;
2. looks up A and AAAA records for every host in the chain;
3. gives a verdict:

| Verdict | Meaning |
|---|---|
| `ipv6-ready` | every host in the redirect chain has an AAAA record |
| `partial` | the page you land on has AAAA, but a host before it (usually the bare domain) does not; an IPv6-only client fails on the first hop unless it starts from the final URL |
| `ipv4-only` | the host you land on has no AAAA record: an IPv6-only proxy cannot load it |
| `unknown` | DNS failed for the landing host |

| Flag | Meaning |
|---|---|
| `-f FILE` | targets, one per line (`#` comments; `-` reads stdin) |
| `--doh URL` | resolve with a DNS-over-HTTPS JSON endpoint (`https://cloudflare-dns.com/dns-query`, `https://dns.google/resolve`) instead of the system resolver, for the same answers on every machine |
| `--via PROXY` | follow the redirects through a proxy, e.g. your IPv6 proxy: the chain is then the one that proxy's visitors get, and the note shows the final HTTP status through it |
| `--direct6` | also open a direct TCP connection over IPv6 to each landing host (needs IPv6 on this machine) |
| `-c N` | targets checked in parallel (8) |
| `--json`, `--csv` | machine-readable output (CSV columns: `target, verdict, final_url, hosts, hosts_without_aaaa, via_status, direct_ipv6, error`) |
| `--fail-on-ipv4-only` | exit 1 unless every target is `ipv6-ready`, for CI |
| `--timeout`, `--insecure` | per-request timeout (20s), skip TLS verification |

## exits

```sh
ipv6-reachability exits --via "http://user:pass@gw.example.net:8080" -n 50 --expect-ipv6 --min-64 20
```

```text
50 requests through http://user:xxxxx@gw.example.net:8080: 50 ok, 0 failed
exited over IPv6: 50, over IPv4: 0
distinct addresses: ..., distinct /64: ..., distinct /48: ...
     n  2001:db8:1:a::/64
```

Each request goes to an IP echo through the proxy on a new connection, so a rotating proxy shows its rotation. The default echo is `https://api.quanticdata.io/v1/public/ip-echo` (free, no account, never cached); change it with `--echo-url`. It reports how many requests left over IPv6 and over IPv4 (to catch a proxy that falls back to IPv4), distinct addresses, /64 and /48 prefixes, and the busiest /64s.

| Flag | Meaning |
|---|---|
| `--via PROXY` | the proxy (`http://`, `https://`, `socks5://`, with or without `user:pass@`) |
| `-n N` | requests (20) |
| `--expect-ipv6` | exit 1 if any request left over IPv4 |
| `--min-64 N` | exit 1 if fewer than N distinct /64 prefixes were seen |
| `--json` | the report and every sample |

Note that the echo host itself must answer over IPv6 for an IPv6-only proxy to reach it; the default echo does.

## QuanticData IPv6 plans

With a QuanticData IPv6 plan, both commands can create the proxy string themselves through the documented, free [`POST /public/proxies/generate`](https://quanticdata.io/docs/) endpoint, and use it as returned:

```sh
export QUANTICDATA_API_KEY=qd_live_...
ipv6-reachability exits --qd-order ORDER_ID --qd-country mix --qd-rotation rotating -n 50
ipv6-reachability sites --qd-order ORDER_ID --qd-rotation static -f targets.txt
```

`--qd-country` takes a country code or `mix` (any country), `--qd-rotation` takes `rotating`, `sticky` or `static` (a fixed session with no expiry, IPv6 only), `--qd-session-time` sets sticky minutes and `--qd-protocol` is `http` or `socks5`. `QUANTICDATA_API_BASE` overrides the API host. The [IPv6 proxies page](https://quanticdata.io/ipv6-proxies/) explains when IPv6 is the right network and when it is not; plans are on [quanticdata.io/pricing](https://quanticdata.io/pricing/).

## Limits

- An AAAA record says a host publishes an IPv6 address. It does not prove the server answers on it, or that the site serves IPv6 visitors the same content. `--direct6` and `--via` test real connections.
- Without `--via`, redirects are followed from your own connection. Some sites redirect by country or by IP family; follow them through the proxy you will use.
- Sites that need JavaScript to redirect, or that block automated requests, may stop the chain early: the verdict then rests on the hosts seen so far, and the error is reported.
- Reachable is not the same as unblocked: sites with anti-bot systems may still challenge or rate-limit IPv6 prefixes.
- DNS results depend on the resolver and change over time; use `--doh` for consistent answers and rerun before decisions.

## Develop

```sh
go vet ./... && go test ./...
```

Tests use a fake resolver, made-up `.test` hosts served by in-process servers and a fake echo proxy on 127.0.0.1; they never use the network. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)

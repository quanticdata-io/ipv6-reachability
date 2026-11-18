// Command ipv6-reachability checks which websites can be reached over IPv6
// and whether a proxy really exits over IPv6.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quanticdata-io/ipv6-reachability/internal/check"
	"github.com/quanticdata-io/ipv6-reachability/internal/quanticdata"
)

// Version is set at build time.
var Version = "dev"

const defaultEcho = "https://api.quanticdata.io/v1/public/ip-echo"

const usage = `usage:
  ipv6-reachability sites [flags] TARGET...      can these sites be loaded over IPv6?
  ipv6-reachability exits [flags] --via PROXY    does this proxy exit over IPv6, from how many /64 and /48?
  ipv6-reachability version

Run "ipv6-reachability sites -h" or "ipv6-reachability exits -h" for flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv, nil)
	stop()
	os.Exit(code)
}

// deps lets tests swap the network pieces.
type deps struct {
	resolver check.Resolver
	client   func(proxy *url.URL) *http.Client
	dial6    func(ctx context.Context, addr string) (net.Conn, error)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, d *deps) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "sites":
		return runSites(ctx, args[1:], stdout, stderr, getenv, d)
	case "exits":
		return runExits(ctx, args[1:], stdout, stderr, getenv, d)
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, "ipv6-reachability", Version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

type proxyFlags struct {
	via                                        string
	insecure                                   bool
	timeout                                    time.Duration
	qdOrder, qdCountry, qdRotation, qdProtocol string
	qdSessionTime                              int
}

func (p *proxyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&p.via, "via", "", "proxy URL to go through, e.g. http://user:pass@host:port or socks5://...")
	fs.BoolVar(&p.insecure, "insecure", false, "skip TLS verification of targets")
	fs.DurationVar(&p.timeout, "timeout", 20*time.Second, "timeout of one request")
	fs.StringVar(&p.qdOrder, "qd-order", "", "QuanticData IPv6 order id: generate the proxy string (needs QUANTICDATA_API_KEY)")
	fs.StringVar(&p.qdCountry, "qd-country", "", "QuanticData: country code, or mix")
	fs.StringVar(&p.qdRotation, "qd-rotation", "", "QuanticData: rotating, sticky or static")
	fs.IntVar(&p.qdSessionTime, "qd-session-time", 0, "QuanticData: sticky session minutes")
	fs.StringVar(&p.qdProtocol, "qd-protocol", "http", "QuanticData: http or socks5")
}

// proxyURL returns the proxy to use, if any (from --via or QuanticData).
func (p *proxyFlags) proxyURL(ctx context.Context, getenv func(string) string) (*url.URL, error) {
	raw := p.via
	if p.qdOrder != "" {
		client, err := quanticdata.NewFromEnvFunc(getenv)
		if err != nil {
			return nil, err
		}
		lines, err := client.Generate(ctx, quanticdata.GenerateRequest{
			OrderID: p.qdOrder, Protocol: p.qdProtocol, Quantity: 1, Country: p.qdCountry,
			Rotation: p.qdRotation, SessionTime: p.qdSessionTime,
		})
		if err != nil {
			return nil, err
		}
		raw = lines[0]
	}
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("--via must be a proxy URL such as http://user:pass@host:port")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (http, https, socks5)", u.Scheme)
	}
	return u, nil
}

func redacted(u *url.URL) string {
	if u == nil {
		return "direct"
	}
	return u.Redacted()
}

func readTargets(args []string, file string) ([]string, error) {
	targets := append([]string{}, args...)
	if file != "" {
		var r io.Reader = os.Stdin
		if file != "-" {
			f, err := os.Open(file)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			r = f
		}
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

func runSites(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, d *deps) int {
	fs := flag.NewFlagSet("sites", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var pf proxyFlags
	pf.register(fs)
	file := fs.String("f", "", "file with one target per line ('-' for stdin)")
	doh := fs.String("doh", "", "resolve through this DNS-over-HTTPS JSON endpoint, e.g. https://cloudflare-dns.com/dns-query")
	direct6 := fs.Bool("direct6", false, "also open a direct IPv6 TCP connection to each landing host (needs IPv6 on this machine)")
	concurrency := fs.Int("c", 8, "targets checked in parallel")
	asJSON := fs.Bool("json", false, "JSON output")
	asCSV := fs.Bool("csv", false, "CSV output")
	failOn := fs.Bool("fail-on-ipv4-only", false, "exit 1 when a target is not ipv6-ready")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	targets, err := readTargets(fs.Args(), *file)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "error: give targets as arguments or with -f FILE")
		return 2
	}
	proxy, err := pf.proxyURL(ctx, getenv)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	opts := check.SiteOptions{ViaProxy: proxy != nil, Direct6: *direct6}
	switch {
	case d != nil && d.resolver != nil:
		opts.Resolver = d.resolver
	case *doh != "":
		opts.Resolver = check.DoHResolver{URL: *doh}
	}
	opts.Client = check.ProxyClient(proxy, pf.timeout, pf.insecure) // a nil proxy means direct
	if d != nil && d.client != nil {
		opts.Client = d.client(proxy)
	}
	if d != nil && d.dial6 != nil {
		opts.Dial6 = d.dial6
	}
	if *concurrency < 1 {
		*concurrency = 1
	}
	results := make([]check.SiteResult, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, *concurrency)
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = check.Site(ctx, t, opts)
		}(i, t)
	}
	wg.Wait()

	counts := map[check.Verdict]int{}
	for _, r := range results {
		counts[r.Verdict]++
	}
	switch {
	case *asJSON:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"via": redacted(proxy), "summary": counts, "results": results})
	case *asCSV:
		w := csv.NewWriter(stdout)
		_ = w.Write([]string{"target", "verdict", "final_url", "hosts", "hosts_without_aaaa", "via_status", "direct_ipv6", "error"})
		for _, r := range results {
			hosts, missing := hostLists(r)
			via := ""
			if r.ViaProxy && r.ViaStatus != 0 {
				via = strconv.Itoa(r.ViaStatus)
			}
			_ = w.Write([]string{r.Target, string(r.Verdict), r.Final, hosts, missing, via, r.Direct6, r.FetchErr})
		}
		w.Flush()
	default:
		printSites(stdout, results, proxy)
		fmt.Fprintf(stdout, "\n%d targets: %d ipv6-ready, %d partial, %d ipv4-only, %d unknown\n",
			len(results), counts[check.Ready], counts[check.Partial], counts[check.IPv4Only], counts[check.Unknown])
	}
	if *failOn && counts[check.Ready] != len(results) {
		return 1
	}
	return 0
}

func hostLists(r check.SiteResult) (string, string) {
	var hosts, missing []string
	seen := map[string]bool{}
	for _, h := range r.Hops {
		if seen[h.Host] {
			continue
		}
		seen[h.Host] = true
		hosts = append(hosts, h.Host)
		if len(h.AAAA) == 0 {
			missing = append(missing, h.Host)
		}
	}
	return strings.Join(hosts, " "), strings.Join(missing, " ")
}

func printSites(w io.Writer, results []check.SiteResult, proxy *url.URL) {
	fmt.Fprintf(w, "%-34s %-11s %-40s %s\n", "TARGET", "VERDICT", "LANDS ON", "NOTE")
	for _, r := range results {
		land := r.Final
		if land == "" {
			land = "-"
		}
		var notes []string
		if _, missing := hostLists(r); missing != "" && r.Verdict != check.Unknown {
			notes = append(notes, "no AAAA: "+missing)
		}
		if r.ViaProxy && r.ViaStatus != 0 {
			notes = append(notes, fmt.Sprintf("via proxy: HTTP %d", r.ViaStatus))
		}
		if r.Direct6 != "" {
			notes = append(notes, "direct IPv6: "+r.Direct6)
		}
		if r.FetchErr != "" {
			notes = append(notes, "fetch: "+r.FetchErr)
		}
		fmt.Fprintf(w, "%-34s %-11s %-40s %s\n", trunc(r.Target, 34), r.Verdict, trunc(land, 40), strings.Join(notes, "; "))
	}
	fmt.Fprintf(w, "(redirects followed %s)\n", map[bool]string{true: "through " + redacted(proxy), false: "directly"}[proxy != nil])
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

func runExits(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, d *deps) int {
	fs := flag.NewFlagSet("exits", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var pf proxyFlags
	pf.register(fs)
	n := fs.Int("n", 20, "requests to send, each on a new connection")
	echo := fs.String("echo-url", defaultEcho, "IP echo requested through the proxy")
	asJSON := fs.Bool("json", false, "JSON output")
	expectV6 := fs.Bool("expect-ipv6", false, "exit 1 unless every successful sample exited over IPv6")
	min64 := fs.Int("min-64", 0, "exit 1 when fewer distinct /64 prefixes were seen")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	proxy, err := pf.proxyURL(ctx, getenv)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if proxy == nil {
		fmt.Fprintln(stderr, "error: exits needs --via PROXY or --qd-order")
		return 2
	}
	client := check.ProxyClient(proxy, pf.timeout, pf.insecure)
	if d != nil && d.client != nil {
		client = d.client(proxy)
	}
	rep := check.SampleExits(ctx, client, *echo, *n)
	var failures []string
	ok := rep.Samples - rep.Failed
	if ok == 0 {
		failures = append(failures, "no request succeeded")
	}
	if *expectV6 && rep.IPv4 > 0 {
		failures = append(failures, fmt.Sprintf("%d of %d samples exited over IPv4", rep.IPv4, ok))
	}
	if *min64 > 0 && rep.Prefixes64 < *min64 {
		failures = append(failures, fmt.Sprintf("%d distinct /64 prefixes, wanted at least %d", rep.Prefixes64, *min64))
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"via": redacted(proxy), "report": rep, "failures": failures})
	} else {
		fmt.Fprintf(stdout, "%d requests through %s: %d ok, %d failed\n", rep.Samples, redacted(proxy), ok, rep.Failed)
		fmt.Fprintf(stdout, "exited over IPv6: %d, over IPv4: %d\n", rep.IPv6, rep.IPv4)
		fmt.Fprintf(stdout, "distinct addresses: %d, distinct /64: %d, distinct /48: %d\n", rep.Distinct, rep.Prefixes64, rep.Prefixes48)
		prefixes := make([]string, 0, len(rep.PerPrefix64))
		for p := range rep.PerPrefix64 {
			prefixes = append(prefixes, p)
		}
		sort.Slice(prefixes, func(i, j int) bool {
			if rep.PerPrefix64[prefixes[i]] != rep.PerPrefix64[prefixes[j]] {
				return rep.PerPrefix64[prefixes[i]] > rep.PerPrefix64[prefixes[j]]
			}
			return prefixes[i] < prefixes[j]
		})
		for i, p := range prefixes {
			if i == 10 {
				fmt.Fprintf(stdout, "  ... %d more /64\n", len(prefixes)-10)
				break
			}
			fmt.Fprintf(stdout, "  %4d  %s\n", rep.PerPrefix64[p], p)
		}
		for _, f := range failures {
			fmt.Fprintln(stdout, "FAIL:", f)
		}
	}
	if len(failures) > 0 {
		return 1
	}
	return 0
}

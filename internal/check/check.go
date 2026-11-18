// Package check answers two questions for IPv6 proxy users: can a site be
// reached over IPv6 (on every host its redirects lead to), and does a proxy
// really exit over IPv6, from how many addresses and prefixes.
package check

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Resolver looks up addresses; *net.Resolver satisfies it.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Verdict of a site.
type Verdict string

// Verdicts.
const (
	Ready    Verdict = "ipv6-ready" // every host of the redirect chain has AAAA records
	Partial  Verdict = "partial"    // the first host has AAAA, a later one does not
	IPv4Only Verdict = "ipv4-only"  // the host the visitor lands on has no AAAA record
	Unknown  Verdict = "unknown"    // DNS failed for the landing host
)

// Hop is one host of the redirect chain.
type Hop struct {
	URL    string   `json:"url"`
	Status int      `json:"status,omitempty"`
	Host   string   `json:"host"`
	AAAA   []string `json:"aaaa"`
	A      []string `json:"a"`
	DNSErr string   `json:"dns_error,omitempty"`
}

// SiteResult is the report for one target.
type SiteResult struct {
	Target  string  `json:"target"`
	Verdict Verdict `json:"verdict"`
	Final   string  `json:"final_url"`
	Hops    []Hop   `json:"hops"`
	// FetchErr is set when the redirect chain could not be followed; the
	// verdict then rests on the first host only.
	FetchErr string `json:"fetch_error,omitempty"`
	// Via* are set when the chain was followed through a proxy.
	ViaProxy  bool `json:"via_proxy"`
	ViaStatus int  `json:"via_status,omitempty"`
	// Direct6 is the result of a direct TCP connection over IPv6 to the
	// landing host on its port (only with SiteOptions.Direct6).
	Direct6 string `json:"direct_ipv6,omitempty"`
}

// SiteOptions configure Site.
type SiteOptions struct {
	Resolver     Resolver
	Client       *http.Client // follows redirects; nil = a direct client
	ViaProxy     bool         // Client goes through a proxy (reported in the result)
	MaxRedirects int          // default 10
	Direct6      bool
	Dial6        func(ctx context.Context, addr string) (net.Conn, error) // for tests; default net.Dialer tcp6
}

// NormalizeTarget turns "example.com" into "https://example.com/".
func NormalizeTarget(t string) (*url.URL, error) {
	s := strings.TrimSpace(t)
	if s == "" {
		return nil, errors.New("empty target")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("not a URL or domain: %q", t)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("only http and https targets, got %q", u.Scheme)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func lookup(ctx context.Context, r Resolver, host string) (aaaa, a []string, err error) {
	if ip, perr := netip.ParseAddr(host); perr == nil {
		if ip.Is4() {
			return nil, []string{ip.String()}, nil
		}
		return []string{ip.String()}, nil, nil
	}
	v6, err6 := r.LookupIP(ctx, "ip6", host)
	v4, err4 := r.LookupIP(ctx, "ip4", host)
	for _, ip := range v6 {
		if ip.To4() == nil {
			aaaa = append(aaaa, ip.String())
		}
	}
	for _, ip := range v4 {
		if ip.To4() != nil {
			a = append(a, ip.String())
		}
	}
	sort.Strings(aaaa)
	sort.Strings(a)
	if len(aaaa) == 0 && len(a) == 0 {
		if err6 != nil {
			return nil, nil, err6
		}
		return nil, nil, err4
	}
	return aaaa, a, nil
}

// follow walks the redirect chain with HEAD-less GETs, reading no body.
func follow(ctx context.Context, client *http.Client, start *url.URL, maxRedirects int) ([]*url.URL, []int, error) {
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	urls := []*url.URL{start}
	var statuses []int
	cur := start
	for i := 0; i <= maxRedirects; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cur.String(), nil)
		if err != nil {
			return urls, statuses, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ipv6-reachability; +https://github.com/quanticdata-io/ipv6-reachability)")
		req.Header.Set("Accept", "text/html,*/*")
		resp, err := c.Do(req)
		if err != nil {
			return urls, statuses, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		statuses = append(statuses, resp.StatusCode)
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode > 399 || loc == "" {
			return urls, statuses, nil
		}
		next, err := cur.Parse(loc)
		if err != nil {
			return urls, statuses, fmt.Errorf("bad redirect %q: %w", loc, err)
		}
		cur = next
		urls = append(urls, cur)
	}
	return urls, statuses, fmt.Errorf("more than %d redirects", maxRedirects)
}

// Site resolves the target, follows its redirects and judges whether an
// IPv6-only client can load it.
func Site(ctx context.Context, target string, opts SiteOptions) SiteResult {
	res := SiteResult{Target: target, Verdict: Unknown, ViaProxy: opts.ViaProxy}
	start, err := NormalizeTarget(target)
	if err != nil {
		res.FetchErr = err.Error()
		return res
	}
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 10
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	urls, statuses, ferr := follow(ctx, client, start, opts.MaxRedirects)
	if ferr != nil {
		res.FetchErr = ferr.Error()
	}
	seen := map[string]bool{}
	for i, u := range urls {
		host := u.Hostname()
		hop := Hop{URL: u.String(), Host: host}
		if i < len(statuses) {
			hop.Status = statuses[i]
		}
		if !seen[host] {
			aaaa, a, err := lookup(ctx, opts.Resolver, host)
			hop.AAAA, hop.A = aaaa, a
			if err != nil {
				hop.DNSErr = err.Error()
			}
			seen[host] = true
		} else {
			for _, h := range res.Hops {
				if h.Host == host {
					hop.AAAA, hop.A, hop.DNSErr = h.AAAA, h.A, h.DNSErr
					break
				}
			}
		}
		res.Hops = append(res.Hops, hop)
	}
	last := res.Hops[len(res.Hops)-1]
	res.Final = last.URL
	if opts.ViaProxy && len(statuses) > 0 {
		res.ViaStatus = statuses[len(statuses)-1]
	}
	res.Verdict = verdict(res.Hops)
	if opts.Direct6 && len(last.AAAA) > 0 {
		res.Direct6 = direct6(ctx, opts, last)
	}
	return res
}

func verdict(hops []Hop) Verdict {
	last := hops[len(hops)-1]
	if len(last.AAAA) == 0 {
		if last.DNSErr != "" && len(last.A) == 0 {
			return Unknown
		}
		return IPv4Only
	}
	for _, h := range hops {
		if len(h.AAAA) == 0 {
			return Partial
		}
	}
	return Ready
}

func direct6(ctx context.Context, opts SiteOptions, hop Hop) string {
	u, err := url.Parse(hop.URL)
	if err != nil {
		return "error: " + err.Error()
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	dial := opts.Dial6
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = func(ctx context.Context, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp6", addr) }
	}
	conn, err := dial(ctx, net.JoinHostPort(hop.AAAA[0], port))
	if err != nil {
		return "failed: " + err.Error()
	}
	conn.Close()
	return "ok"
}

// ---- exits ------------------------------------------------------------

// Sample is one request to the IP echo.
type Sample struct {
	IP    string `json:"ip,omitempty"`
	Error string `json:"error,omitempty"`
}

// ExitReport counts what a proxy exited from.
type ExitReport struct {
	Samples     int            `json:"samples"`
	Failed      int            `json:"failed"`
	IPv6        int            `json:"ipv6"`
	IPv4        int            `json:"ipv4"`
	Distinct    int            `json:"distinct_addresses"`
	Prefixes64  int            `json:"distinct_64"`
	Prefixes48  int            `json:"distinct_48"`
	PerPrefix64 map[string]int `json:"per_64"`
	List        []Sample       `json:"list"`
}

// ParseEchoIP reads the IP of an echo answer (QuanticData envelope, flat JSON or plain text).
func ParseEchoIP(body []byte) (netip.Addr, error) {
	s := strings.TrimSpace(string(body))
	if strings.HasPrefix(s, "{") {
		var env map[string]any
		if err := json.Unmarshal([]byte(s), &env); err != nil {
			return netip.Addr{}, err
		}
		if p, ok := env["payload"].(map[string]any); ok {
			env = p
		}
		for _, k := range []string{"ip", "origin", "query"} {
			if v, ok := env[k].(string); ok && v != "" {
				return netip.ParseAddr(strings.TrimSpace(strings.Split(v, ",")[0]))
			}
		}
		return netip.Addr{}, errors.New("no IP field in the echo answer")
	}
	return netip.ParseAddr(s)
}

// SampleExits sends n requests to echoURL through client, each on a new
// connection, and counts addresses and prefixes.
func SampleExits(ctx context.Context, client *http.Client, echoURL string, n int) ExitReport {
	r := ExitReport{PerPrefix64: map[string]int{}}
	addrs := map[netip.Addr]bool{}
	p48 := map[netip.Prefix]bool{}
	for i := 0; i < n; i++ {
		r.Samples++
		ip, err := fetchEcho(ctx, client, echoURL)
		if err != nil {
			r.Failed++
			r.List = append(r.List, Sample{Error: err.Error()})
			continue
		}
		r.List = append(r.List, Sample{IP: ip.String()})
		addrs[ip] = true
		if ip.Is4() || ip.Is4In6() {
			r.IPv4++
			continue
		}
		r.IPv6++
		pre64, _ := ip.Prefix(64)
		pre48, _ := ip.Prefix(48)
		r.PerPrefix64[pre64.String()]++
		p48[pre48] = true
	}
	r.Distinct = len(addrs)
	r.Prefixes64 = len(r.PerPrefix64)
	r.Prefixes48 = len(p48)
	return r
}

func fetchEcho(ctx context.Context, client *http.Client, echoURL string) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, echoURL, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return netip.Addr{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("echo answered HTTP %d", resp.StatusCode)
	}
	return ParseEchoIP(body)
}

// ProxyClient is an HTTP client through proxyURL with no connection reuse,
// so each request can leave from a different exit.
func ProxyClient(proxyURL *url.URL, timeout time.Duration, insecure bool) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}, //nolint:gosec // opt-in flag
		},
	}
}

package check

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDNS answers from a map: host -> addresses (IPv4 and IPv6 mixed).
type fakeDNS map[string][]string

func (f fakeDNS) LookupIP(_ context.Context, network, host string) ([]net.IP, error) {
	addrs, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []net.IP
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if (network == "ip6") == (ip.To4() == nil) {
			out = append(out, ip)
		}
	}
	return out, nil
}

// lab serves made-up .test hosts from one httptest server; the client dials
// every host to it, so redirects between hosts work offline.
func lab(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}},
	}
}

func redirects(w http.ResponseWriter, r *http.Request) {
	switch r.Host {
	case "dual.test":
		fmt.Fprint(w, "ok")
	case "moves.test":
		http.Redirect(w, r, "http://www.moves.test/home", http.StatusMovedPermanently)
	case "www.moves.test":
		fmt.Fprint(w, "home")
	case "loop.test":
		http.Redirect(w, r, "/again", http.StatusFound)
	default:
		fmt.Fprint(w, "page")
	}
}

var dns = fakeDNS{
	"dual.test":      {"192.0.2.10", "2001:db8::10"},
	"moves.test":     {"192.0.2.20", "2001:db8::20"},
	"www.moves.test": {"192.0.2.21"},
	"v4only.test":    {"192.0.2.30"},
	"v6only.test":    {"2001:db8::40"},
	"loop.test":      {"2001:db8::50"},
}

func TestVerdicts(t *testing.T) {
	client := lab(t, redirects)
	cases := map[string]Verdict{
		"http://dual.test/":   Ready,
		"http://v6only.test/": Ready,
		"http://moves.test/":  IPv4Only, // lands on a host without AAAA
		"http://v4only.test/": IPv4Only,
		"http://gone.test/":   Unknown,
	}
	for target, want := range cases {
		r := Site(context.Background(), target, SiteOptions{Resolver: dns, Client: client})
		if r.Verdict != want {
			t.Errorf("%s: got %s, want %s (%+v)", target, r.Verdict, want, r)
		}
	}
	r := Site(context.Background(), "http://moves.test/", SiteOptions{Resolver: dns, Client: client})
	if r.Final != "http://www.moves.test/home" || len(r.Hops) != 2 || r.Hops[0].Status != 301 || r.Hops[1].Status != 200 {
		t.Fatalf("redirect chain: %+v", r)
	}
	if r.Hops[0].AAAA[0] != "2001:db8::20" || len(r.Hops[1].AAAA) != 0 {
		t.Fatalf("lookups: %+v", r.Hops)
	}
}

func TestPartialWhenLandingHostHasAAAAButFirstDoesNot(t *testing.T) {
	client := lab(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "old.test" {
			http.Redirect(w, r, "http://dual.test/", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	})
	d := fakeDNS{"old.test": {"192.0.2.1"}, "dual.test": {"192.0.2.2", "2001:db8::2"}}
	if r := Site(context.Background(), "http://old.test/", SiteOptions{Resolver: d, Client: client}); r.Verdict != Partial {
		t.Fatalf("got %s", r.Verdict)
	}
}

func TestRedirectLimitAndFetchErrors(t *testing.T) {
	client := lab(t, redirects)
	r := Site(context.Background(), "http://loop.test/", SiteOptions{Resolver: dns, Client: client, MaxRedirects: 3})
	if !strings.Contains(r.FetchErr, "more than 3 redirects") || r.Verdict != Ready {
		t.Fatalf("%+v", r)
	}
	dead := &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}}}
	r = Site(context.Background(), "http://dual.test/", SiteOptions{Resolver: dns, Client: dead})
	if r.FetchErr == "" || r.Verdict != Ready || r.Final != "http://dual.test/" {
		t.Fatalf("a failed fetch still judges the first host: %+v", r)
	}
	if r := Site(context.Background(), "ftp://x.test", SiteOptions{Resolver: dns}); r.FetchErr == "" {
		t.Fatal("want an error for ftp")
	}
}

func TestNormalizeTarget(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":              "https://example.com/",
		"http://example.com/a?b=1": "http://example.com/a?b=1",
		"https://[2001:db8::1]":    "https://[2001:db8::1]/",
	} {
		u, err := NormalizeTarget(in)
		if err != nil || u.String() != want {
			t.Errorf("%s: %v %v", in, u, err)
		}
	}
	if _, err := NormalizeTarget(" "); err == nil {
		t.Fatal("want an error")
	}
}

func TestLiteralAddressesNeedNoDNS(t *testing.T) {
	aaaa, a, err := lookup(context.Background(), fakeDNS{}, "2001:db8::1")
	if err != nil || len(aaaa) != 1 || len(a) != 0 {
		t.Fatal(aaaa, a, err)
	}
}

func TestDirect6(t *testing.T) {
	client := lab(t, redirects)
	var dialed string
	opts := SiteOptions{Resolver: dns, Client: client, Direct6: true, Dial6: func(_ context.Context, addr string) (net.Conn, error) {
		dialed = addr
		return nil, errors.New("network is unreachable")
	}}
	r := Site(context.Background(), "http://dual.test/", opts)
	if dialed != "[2001:db8::10]:80" || !strings.HasPrefix(r.Direct6, "failed: network is unreachable") {
		t.Fatalf("%q %q", dialed, r.Direct6)
	}
}

func TestDoHResolver(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/dns-json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Query().Get("name") + "/" + r.URL.Query().Get("type") {
		case "dual.test/AAAA":
			fmt.Fprint(w, `{"Status":0,"Answer":[{"type":5,"data":"cdn.test."},{"type":28,"data":"2001:db8::10"}]}`)
		case "dual.test/A":
			fmt.Fprint(w, `{"Status":0,"Answer":[{"type":1,"data":"192.0.2.10"}]}`)
		default:
			fmt.Fprint(w, `{"Status":3}`)
		}
	}))
	defer srv.Close()
	d := DoHResolver{URL: srv.URL + "/dns-query"}
	aaaa, a, err := lookup(context.Background(), d, "dual.test")
	if err != nil || fmt.Sprint(aaaa, a) != "[2001:db8::10] [192.0.2.10]" {
		t.Fatal(aaaa, a, err)
	}
	var dnsErr *net.DNSError
	if _, err := d.LookupIP(context.Background(), "ip6", "gone.test"); !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("want NXDOMAIN, got %v", err)
	}
}

// echoProxy is a forward proxy that answers absolute-form requests itself,
// returning the next address of ips as the exit.
func echoProxy(t *testing.T, ips []string) *url.URL {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		ip := ips[int(n.Add(1)-1)%len(ips)]
		fmt.Fprintf(w, `{"type":"response","payload":{"ip":%q,"countryCode":"DE"}}`, ip)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	u.User = url.UserPassword("user", "pw")
	return u
}

func TestSampleExits(t *testing.T) {
	proxy := echoProxy(t, []string{"2001:db8:1:a::1", "2001:db8:1:a::2", "2001:db8:1:b::1", "2001:db8:2:c::1", "192.0.2.9"})
	rep := SampleExits(context.Background(), ProxyClient(proxy, 5*time.Second, false), "http://echo.test/ip", 5)
	if rep.IPv6 != 4 || rep.IPv4 != 1 || rep.Distinct != 5 || rep.Prefixes64 != 3 || rep.Prefixes48 != 2 {
		t.Fatalf("%+v", rep)
	}
	if rep.PerPrefix64["2001:db8:1:a::/64"] != 2 {
		t.Fatalf("%v", rep.PerPrefix64)
	}
}

func TestParseEchoIP(t *testing.T) {
	for body, want := range map[string]string{
		`{"type":"response","payload":{"ip":"2001:db8::1"}}`: "2001:db8::1",
		`{"origin":"2001:db8::2, 192.0.2.1"}`:                "2001:db8::2",
		"2001:db8::3\n":                                      "2001:db8::3",
	} {
		ip, err := ParseEchoIP([]byte(body))
		if err != nil || ip.String() != want {
			t.Errorf("%s: %v %v", body, ip, err)
		}
	}
	if _, err := ParseEchoIP([]byte(`{"x":1}`)); err == nil {
		t.Fatal("want an error")
	}
}

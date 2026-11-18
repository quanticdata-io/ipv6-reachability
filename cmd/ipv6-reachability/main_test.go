package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

func testDeps(t *testing.T) *deps {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "moves.test" {
			http.Redirect(w, r, "http://www.moves.test/", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	return &deps{
		resolver: fakeDNS{"dual.test": {"192.0.2.1", "2001:db8::1"}, "moves.test": {"2001:db8::2"}, "www.moves.test": {"192.0.2.3"}},
		client: func(*url.URL) *http.Client {
			return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}}}
		},
	}
}

func TestSitesTableAndExitCodes(t *testing.T) {
	d := testDeps(t)
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"sites", "http://dual.test/", "http://moves.test/"}, &out, &errb, os.Getenv, d)
	if code != 0 {
		t.Fatalf("%d %s", code, errb.String())
	}
	s := out.String()
	if !strings.Contains(s, "ipv6-ready") || !strings.Contains(s, "no AAAA: www.moves.test") || !strings.Contains(s, "2 targets: 1 ipv6-ready, 0 partial, 1 ipv4-only") {
		t.Fatal(s)
	}
	out.Reset()
	if code := run(context.Background(), []string{"sites", "--fail-on-ipv4-only", "http://moves.test/"}, &out, &errb, os.Getenv, d); code != 1 {
		t.Fatalf("want 1, got %d", code)
	}
}

func TestSitesFromFileAsJSONAndCSV(t *testing.T) {
	d := testDeps(t)
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("# list\nhttp://dual.test/\n\nhttp://moves.test/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"sites", "-f", path, "-json"}, &out, &errb, os.Getenv, d); code != 0 {
		t.Fatal(errb.String())
	}
	var doc struct {
		Summary map[string]int `json:"summary"`
		Results []struct {
			Verdict string `json:"verdict"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.Summary["ipv6-ready"] != 1 || len(doc.Results) != 2 {
		t.Fatalf("%v %s", err, out.String())
	}
	out.Reset()
	run(context.Background(), []string{"sites", "-csv", "http://moves.test/"}, &out, &errb, os.Getenv, d)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "http://moves.test/,ipv4-only,http://www.moves.test/,moves.test www.moves.test,www.moves.test,") {
		t.Fatal(out.String())
	}
}

func TestExits(t *testing.T) {
	ips := []string{"2001:db8:1:a::1", "2001:db8:1:b::1", "2001:db8:1:b::2"}
	n := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"ip":%q}`, ips[n%len(ips)])
		n++
	}))
	defer proxy.Close()
	var out, errb bytes.Buffer
	args := []string{"exits", "--via", "user:pw@" + strings.TrimPrefix(proxy.URL, "http://"), "-n", "3", "--echo-url", "http://echo.test/", "--expect-ipv6", "--min-64", "2"}
	if code := run(context.Background(), args, &out, &errb, os.Getenv, nil); code != 0 {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "distinct addresses: 3, distinct /64: 2, distinct /48: 1") || strings.Contains(out.String(), "pw@") {
		t.Fatal(out.String())
	}
	out.Reset()
	args[len(args)-1] = "5"
	if code := run(context.Background(), args, &out, &errb, os.Getenv, nil); code != 1 || !strings.Contains(out.String(), "wanted at least 5") {
		t.Fatalf("%d %s", code, out.String())
	}
}

func TestQuanticDataProxy(t *testing.T) {
	var body map[string]any
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = io.WriteString(w, `{"type":"response","payload":{"proxies":["http://user-country-mix:pw@gw.example.net:9000"]}}`)
	}))
	defer api.Close()
	pf := proxyFlags{qdOrder: "ord_6", qdCountry: "mix", qdRotation: "static", qdProtocol: "http"}
	env := map[string]string{"QUANTICDATA_API_KEY": "qd_test_key", "QUANTICDATA_API_BASE": api.URL + "/v1"}
	u, err := pf.proxyURL(context.Background(), func(k string) string { return env[k] })
	if err != nil || u.Host != "gw.example.net:9000" || u.User.Username() != "user-country-mix" {
		t.Fatal(u, err)
	}
	if body["orderId"] != "ord_6" || body["rotation"] != "static" || body["country"] != "mix" || body["quantity"] != float64(1) {
		t.Fatal(body)
	}
}

func TestUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"nope"}, {"sites"}, {"exits"}, {"exits", "--via", "ftp://x:1"}} {
		if code := run(context.Background(), args, &out, &errb, os.Getenv, nil); code != 2 {
			t.Errorf("%v: want 2, got %d", args, code)
		}
	}
	out.Reset()
	if code := run(context.Background(), []string{"version"}, &out, &errb, os.Getenv, nil); code != 0 || !strings.HasPrefix(out.String(), "ipv6-reachability") {
		t.Fatal(out.String())
	}
}

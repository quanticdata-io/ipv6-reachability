package check

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DoHResolver asks a DNS-over-HTTPS server that speaks the JSON format
// (application/dns-json), such as https://cloudflare-dns.com/dns-query or
// https://dns.google/resolve. It gives the same answers on every machine,
// whatever the local resolver or network does with AAAA queries.
type DoHResolver struct {
	URL    string
	Client *http.Client
}

type dohAnswer struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// LookupIP implements Resolver. network is "ip4" or "ip6".
func (d DoHResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	qtype, want := "A", 1
	if network == "ip6" {
		qtype, want = "AAAA", 28
	}
	u, err := url.Parse(d.URL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("name", strings.TrimSuffix(host, "."))
	q.Set("type", qtype)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server answered HTTP %d", resp.StatusCode)
	}
	var ans dohAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ans); err != nil {
		return nil, fmt.Errorf("DoH answer: %w", err)
	}
	if ans.Status == 3 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if ans.Status != 0 {
		return nil, &net.DNSError{Err: fmt.Sprintf("DNS rcode %d", ans.Status), Name: host}
	}
	var out []net.IP
	for _, a := range ans.Answer {
		if a.Type != want {
			continue // CNAME records in the chain
		}
		if ip := net.ParseIP(a.Data); ip != nil {
			out = append(out, ip)
		}
	}
	return out, nil
}

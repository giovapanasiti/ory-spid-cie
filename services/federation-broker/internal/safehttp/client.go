// Package safehttp provides an outbound HTTP client hardened against SSRF for
// federation metadata retrieval: scheme allow-list, host allow-list, private
// address blocking (enforced at dial time to defeat DNS rebinding), bounded
// redirects, timeouts and response size limits. TLS verification is never
// disabled.
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Policy configures the client.
type Policy struct {
	// AllowHTTP permits plain http:// URLs (development only).
	AllowHTTP bool
	// AllowPrivateNetworks permits loopback / RFC1918 / link-local targets
	// (development only, e.g. docker compose networks).
	AllowPrivateNetworks bool
	// AllowedHostSuffixes, when not empty, restricts targets to hosts equal to
	// or ending with ".<suffix>".
	AllowedHostSuffixes []string
	Timeout             time.Duration
	MaxRedirects        int
	MaxBodyBytes        int64
	UserAgent           string
}

// Client is a hardened HTTP client.
type Client struct {
	policy Policy
	hc     *http.Client
}

// ErrBlocked is returned when a request target violates the policy.
var ErrBlocked = errors.New("outbound request blocked by policy")

// New creates a client.
func New(p Policy) *Client {
	if p.Timeout == 0 {
		p.Timeout = 10 * time.Second
	}
	if p.MaxBodyBytes == 0 {
		p.MaxBodyBytes = 512 * 1024
	}
	if p.MaxRedirects == 0 {
		p.MaxRedirects = 3
	}
	if p.UserAgent == "" {
		p.UserAgent = "iam-federation-broker/1.0"
	}
	c := &Client{policy: p}
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("%w: unresolved address %q", ErrBlocked, host)
			}
			if !p.AllowPrivateNetworks && isPrivate(ip) {
				return fmt.Errorf("%w: private address %s", ErrBlocked, ip)
			}
			return nil
		},
	}
	tr := &http.Transport{
		Proxy:                 nil, // never route federation traffic via env proxies implicitly
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: p.Timeout,
		MaxIdleConns:          50,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	c.hc = &http.Client{
		Timeout:   p.Timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= p.MaxRedirects {
				return fmt.Errorf("%w: too many redirects", ErrBlocked)
			}
			return c.CheckURL(req.URL)
		},
	}
	return c
}

func isPrivate(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		// 100.64.0.0/10 carrier-grade NAT, commonly used for cloud metadata adjacencies
		(ip.To4() != nil && ip.To4()[0] == 100 && ip.To4()[1]&0xC0 == 64)
}

// CheckURL validates a URL against the policy (scheme, host allow-list).
func (c *Client) CheckURL(u *url.URL) error {
	switch u.Scheme {
	case "https":
	case "http":
		if !c.policy.AllowHTTP {
			return fmt.Errorf("%w: http scheme not allowed", ErrBlocked)
		}
	default:
		return fmt.Errorf("%w: scheme %q", ErrBlocked, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo in URL", ErrBlocked)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrBlocked)
	}
	if len(c.policy.AllowedHostSuffixes) > 0 {
		ok := false
		for _, s := range c.policy.AllowedHostSuffixes {
			s = strings.ToLower(strings.TrimPrefix(s, "."))
			if host == s || strings.HasSuffix(host, "."+s) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: host %q not in allow-list", ErrBlocked, host)
		}
	}
	return nil
}

// Do executes a request after policy checks and returns the bounded body.
func (c *Client) Do(req *http.Request) (*http.Response, []byte, error) {
	if err := c.CheckURL(req.URL); err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", c.policy.UserAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.policy.MaxBodyBytes+1))
	if err != nil {
		return resp, nil, err
	}
	if int64(len(body)) > c.policy.MaxBodyBytes {
		return resp, nil, fmt.Errorf("%w: response exceeds %d bytes", ErrBlocked, c.policy.MaxBodyBytes)
	}
	return resp, body, nil
}

// Get performs a GET and requires a 200 response.
func (c *Client) Get(ctx context.Context, rawURL string, accept string) ([]byte, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, body, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("GET %s: status %d", u.Redacted(), resp.StatusCode)
	}
	return body, resp.Header.Get("Content-Type"), nil
}

package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http/httpproxy"
)

var relayProxyFromEnvironment = proxyURLFromEnvironment

type ProxyMode string

const (
	ProxyFromEnvironment ProxyMode = "environment"
	ProxyDisabled        ProxyMode = "disabled"
	ProxyExplicit        ProxyMode = "explicit"
)

func (m ProxyMode) normalized() ProxyMode {
	switch m {
	case ProxyFromEnvironment:
		return ProxyFromEnvironment
	case ProxyExplicit:
		return ProxyExplicit
	default:
		return ProxyDisabled
	}
}

func dialRelay(ctx context.Context, dialer *net.Dialer, relayAddr string, mode ProxyMode, explicitProxyURL *url.URL) (net.Conn, error) {
	switch mode.normalized() {
	case ProxyDisabled:
		return dialer.DialContext(ctx, "tcp", relayAddr)
	case ProxyExplicit:
		if explicitProxyURL == nil {
			return nil, fmt.Errorf("explicit relay proxy mode requires a proxy URL")
		}
		return dialRelayViaHTTPProxy(ctx, dialer, relayAddr, explicitProxyURL)
	default:
		proxyURL, err := relayProxyFromEnvironment(relayAddr)
		if err != nil {
			return nil, err
		}
		if proxyURL == nil {
			return dialer.DialContext(ctx, "tcp", relayAddr)
		}
		return dialRelayViaHTTPProxy(ctx, dialer, relayAddr, proxyURL)
	}
}

func proxyURLFromEnvironment(relayAddr string) (*url.URL, error) {
	proxyFunc := httpproxy.FromEnvironment().ProxyFunc()

	// Prefer HTTPS_PROXY for relay traffic because operators commonly expose
	// proxy-reachable relays on TCP/443. Fall back to HTTP_PROXY so nodes that
	// only provide a generic HTTP proxy can still tunnel relay TCP with CONNECT.
	proxyURL, err := proxyFunc(&url.URL{Scheme: "https", Host: relayAddr})
	if err != nil || proxyURL != nil {
		return proxyURL, err
	}
	return proxyFunc(&url.URL{Scheme: "http", Host: relayAddr})
}

func dialRelayViaHTTPProxy(ctx context.Context, dialer *net.Dialer, relayAddr string, proxyURL *url.URL) (net.Conn, error) {
	if _, _, err := net.SplitHostPort(relayAddr); err != nil {
		return nil, fmt.Errorf("relay address %q must be host:port for HTTP CONNECT: %w", relayAddr, err)
	}
	proxyAddr, err := proxyDialAddr(proxyURL)
	if err != nil {
		return nil, err
	}

	conn, err := dialProxy(ctx, dialer, proxyAddr, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to relay proxy %s: %w", redactedProxyURL(proxyURL), err)
	}

	clearDeadline, err := setConnDeadline(ctx, conn, dialTimeout)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer clearDeadline()

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	if err := writeConnectRequest(bw, relayAddr, proxyURL); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading proxy CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT %s via %s failed: %s", relayAddr, redactedProxyURL(proxyURL), resp.Status)
	}

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

func dialProxy(ctx context.Context, dialer *net.Dialer, proxyAddr string, proxyURL *url.URL) (net.Conn, error) {
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if proxyURL.Scheme != "https" {
		return conn, nil
	}
	tlsConn := tls.Client(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: proxyURL.Hostname(),
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func proxyDialAddr(proxyURL *url.URL) (string, error) {
	switch proxyURL.Scheme {
	case "http", "https":
	default:
		return "", fmt.Errorf("unsupported relay proxy scheme %q", proxyURL.Scheme)
	}
	host := proxyURL.Hostname()
	if host == "" {
		return "", fmt.Errorf("relay proxy URL %q has no host", redactedProxyURL(proxyURL))
	}
	port := proxyURL.Port()
	if port == "" {
		if proxyURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port), nil
}

func writeConnectRequest(w *bufio.Writer, relayAddr string, proxyURL *url.URL) error {
	if _, err := fmt.Fprintf(w, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: wirekube-agent\r\nProxy-Connection: Keep-Alive\r\n", relayAddr, relayAddr); err != nil {
		return err
	}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
		if _, err := fmt.Fprintf(w, "Proxy-Authorization: Basic %s\r\n", token); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, "\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

func setConnDeadline(ctx context.Context, conn net.Conn, timeout time.Duration) (func(), error) {
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("setting relay proxy deadline: %w", err)
	}
	return func() {
		_ = conn.SetDeadline(time.Time{})
	}, nil
}

func redactedProxyURL(proxyURL *url.URL) string {
	if proxyURL == nil {
		return ""
	}
	clone := *proxyURL
	if clone.User != nil {
		clone.User = url.User(clone.User.Username())
	}
	return clone.String()
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

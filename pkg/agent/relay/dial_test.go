package relay

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestProxyURLFromEnvironmentPrefersHTTPSProxy(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTP_PROXY", "http://http-proxy.example:3128")
	t.Setenv("HTTPS_PROXY", "http://https-proxy.example:3128")

	got, err := proxyURLFromEnvironment("relay.example.com:443")
	if err != nil {
		t.Fatalf("proxyURLFromEnvironment: %v", err)
	}
	if got == nil {
		t.Fatal("proxyURLFromEnvironment returned nil")
	}
	if got.String() != "http://https-proxy.example:3128" {
		t.Fatalf("proxy = %q, want HTTPS proxy", got.String())
	}
}

func TestProxyURLFromEnvironmentHonorsNoProxy(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	t.Setenv("NO_PROXY", "relay.example.com")

	got, err := proxyURLFromEnvironment("relay.example.com:443")
	if err != nil {
		t.Fatalf("proxyURLFromEnvironment: %v", err)
	}
	if got != nil {
		t.Fatalf("proxy = %q, want nil due to NO_PROXY", got.String())
	}
}

func TestProxyModeDefaultsToDisabled(t *testing.T) {
	if got := (ProxyMode("")).normalized(); got != ProxyDisabled {
		t.Fatalf("empty proxy mode = %q, want %q", got, ProxyDisabled)
	}

	var pubKey [32]byte
	if got := NewClient("relay.example.com:443", pubKey, 51820).proxyMode; got != ProxyDisabled {
		t.Fatalf("new client proxy mode = %q, want %q", got, ProxyDisabled)
	}
	if got := NewPool("relay.example.com:443", pubKey, 51820).proxyMode; got != ProxyDisabled {
		t.Fatalf("new pool proxy mode = %q, want %q", got, ProxyDisabled)
	}
}

func TestDialRelayViaHTTPProxyUsesConnectAndPreservesStream(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen proxy: %v", err)
	}
	defer proxy.Close()

	seen := make(chan *http.Request, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := proxy.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			errCh <- err
			return
		}
		seen <- req
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			errCh <- err
			return
		}
		if string(buf) != "ping" {
			errCh <- fmt.Errorf("tunnel payload = %q, want ping", string(buf))
			return
		}
		_, err = conn.Write([]byte("pong"))
		errCh <- err
	}()

	proxyURL := &url.URL{
		Scheme: "http",
		Host:   proxy.Addr().String(),
		User:   url.UserPassword("agent", "secret"),
	}
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialRelayViaHTTPProxy(context.Background(), dialer, "relay.example.com:443", proxyURL)
	if err != nil {
		t.Fatalf("dialRelayViaHTTPProxy: %v", err)
	}
	defer conn.Close()

	req := <-seen
	if req.Method != http.MethodConnect {
		t.Fatalf("CONNECT method = %q", req.Method)
	}
	if req.Host != "relay.example.com:443" {
		t.Fatalf("CONNECT host = %q", req.Host)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("agent:secret"))
	if got := req.Header.Get("Proxy-Authorization"); got != wantAuth {
		t.Fatalf("Proxy-Authorization = %q, want %q", got, wantAuth)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read tunnel payload: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("tunnel response = %q, want pong", string(buf))
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("proxy handler: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy handler did not finish")
	}
}

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "REQUEST_METHOD",
		"http_proxy", "https_proxy", "no_proxy", "all_proxy",
	} {
		t.Setenv(key, "")
	}
}

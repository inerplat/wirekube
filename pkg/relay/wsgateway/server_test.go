package wsgateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListenAndServeRequiresTLSCertificateAndKey(t *testing.T) {
	if err := ListenAndServe(context.Background(), "127.0.0.1:0", http.NewServeMux(), "cert.pem", ""); err == nil {
		t.Fatal("expected incomplete TLS configuration to fail")
	}
}

func TestReadyChecksRawRelayBackend(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	server := NewServer(nil, listener.Addr().String(), "/relay")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("ready status=%d", recorder.Code)
	}

	listener.Close()
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unready status=%d", recorder.Code)
	}
}

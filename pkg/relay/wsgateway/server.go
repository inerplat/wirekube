package wsgateway

import (
	"bufio"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	relayproto "github.com/wirekube/wirekube/pkg/relay"
)

type Server struct {
	Authenticator *Authenticator
	BackendAddr   string
	Path          string
	Dialer        net.Dialer
	Upgrader      websocket.Upgrader
}

func NewServer(authenticator *Authenticator, backendAddr, path string) *Server {
	return &Server{
		Authenticator: authenticator,
		BackendAddr:   backendAddr,
		Path:          path,
		Dialer:        net.Dialer{Timeout: 10 * time.Second},
		Upgrader: websocket.Upgrader{
			Subprotocols: []string{"wirekube.relay.v1"},
			CheckOrigin: func(r *http.Request) bool {
				return r.Header.Get("Origin") == ""
			},
		},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc(s.Path, s.handleRelay)
	return mux
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	backend, err := s.Dialer.DialContext(ctx, "tcp", s.BackendAddr)
	if err != nil {
		http.Error(w, "relay backend unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = backend.Close()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRelay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	expectedKey, peerName, err := s.Authenticator.Authenticate(r.Context(), token)
	if err != nil {
		log.Printf("relay-ws: authentication rejected: %v", err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ws, err := s.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(2 * relayproto.MaxFrameSize)
	conn := relayproto.NewWebSocketConn(ws)
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}

	reader := bufio.NewReader(conn)
	frame, err := relayproto.ReadFrame(reader)
	if err != nil {
		log.Printf("relay-ws: %s register read failed: %v", peerName, err)
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	if frame.Type != relayproto.MsgRegister || len(frame.Body) != relayproto.PubKeySize || subtle.ConstantTimeCompare(frame.Body, expectedKey[:]) != 1 {
		log.Printf("relay-ws: %s public key binding rejected", peerName)
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "public key does not match token identity"), time.Now().Add(time.Second))
		return
	}

	backend, err := s.Dialer.DialContext(r.Context(), "tcp", s.BackendAddr)
	if err != nil {
		log.Printf("relay-ws: %s backend dial failed: %v", peerName, err)
		return
	}
	defer backend.Close()
	if err := relayproto.WriteFrame(backend, frame); err != nil {
		log.Printf("relay-ws: %s backend register failed: %v", peerName, err)
		return
	}

	log.Printf("relay-ws: peer connected: %s", peerName)
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(backend, reader)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, backend)
		errCh <- err
	}()
	select {
	case <-r.Context().Done():
	case <-errCh:
	}
	log.Printf("relay-ws: peer disconnected: %s", peerName)
}

func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", false
	}
	return strings.TrimSpace(token), true
}

func ListenAndServe(ctx context.Context, addr string, handler http.Handler, certFile, keyFile string) error {
	if (certFile == "") != (keyFile == "") {
		return fmt.Errorf("relay-ws TLS certificate and private key must be configured together")
	}
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	var err error
	if certFile != "" {
		err = server.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("relay-ws listen: %w", err)
	}
	return nil
}

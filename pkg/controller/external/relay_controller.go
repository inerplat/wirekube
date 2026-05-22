// Package external implements the WireKubeExternalPeer reconciler and the
// RelayController abstraction it uses to publish relay endpoint information.
//
// The reconciler is platform-agnostic and runs as a sub-controller inside
// the agent binary. The RelayController interface lets it be wired with
// either a static endpoint controller or the legacy per-peer UDP forwarder
// control path kept for compatibility with older external-peer allocations.
package external

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/wirekube/wirekube/pkg/relay"
	"github.com/wirekube/wirekube/pkg/relay/portalloc"
)

// ErrNotImplemented is returned by the noop RelayController for legacy
// mutating calls when no control path is configured.
var ErrNotImplemented = errors.New("relay controller: not implemented")

// RelayController is the surface the reconciler uses to publish the relay
// endpoint and, for legacy allocations, register or tear down per-peer UDP
// forwarder mappings on the relay.
//
// All methods must be safe for concurrent calls — the reconciler may be
// invoked from multiple worker goroutines once integrated with
// controller-runtime.
type RelayController interface {
	// RegisterForwarder allocates a UDP port on the relay (or instructs a
	// remote relay to do so) and binds it to the given (ingress,
	// external) pubkey pair. Returns the allocated port so the
	// reconciler can write it into status.
	RegisterForwarder(ctx context.Context, ingressPubKey, externalPubKey [32]byte) (port uint16, err error)

	// UnregisterForwarder frees a previously allocated mapping. Idempotent:
	// calls for an unknown port return nil so cleanup paths can be safely
	// retried.
	UnregisterForwarder(ctx context.Context, port uint16) error

	// RelayEndpoint returns the public host:port advertised to external peers.
	RelayEndpoint() string
}

// RelayForwarderEnsurer is optionally implemented by RelayController
// implementations that can re-apply an already allocated mapping. The
// reconciler uses this for fanout controllers so newly discovered relay
// replicas receive mappings for existing Active external peers.
type RelayForwarderEnsurer interface {
	EnsureForwarder(ctx context.Context, port uint16, ingressPubKey, externalPubKey [32]byte) error
}

// IngressLatencyProber is optionally implemented by RelayController
// implementations that can ask the relay to measure application-level RTT to
// connected ingress peers.
type IngressLatencyProber interface {
	ProbeIngressLatency(ctx context.Context, ingressPubKeys [][32]byte) (map[[32]byte]time.Duration, error)
}

// ---------------------------------------------------------------------------
// LocalRelayController — wraps an in-process port allocator + forwarder.
// ---------------------------------------------------------------------------

// LocalRelayController is the in-process implementation. It is suitable
// when the reconciler runs alongside the relay (single-process e2e tests)
// and is the implementation exercised by the unit tests in this package.
//
// It owns no goroutines beyond the ones already spawned by the supplied
// *relay.Forwarder; allocation and bookkeeping are protected by a mutex
// so concurrent callers (controller workers) cannot race on the port→key
// mapping.
type LocalRelayController struct {
	alloc    *portalloc.Allocator
	fw       *relay.Forwarder
	endpoint string

	mu       sync.Mutex
	mappings map[uint16]struct{ ingress, external [32]byte }
}

// NewLocalRelayController constructs a LocalRelayController. The endpoint
// argument is the public host:port the reconciler will write into
// status.relayEndpoint.
//
// Both alloc and fw must be non-nil; the constructor does not validate
// (a nil dereference at call time is a clearer test failure than a silent
// stub).
func NewLocalRelayController(alloc *portalloc.Allocator, fw *relay.Forwarder, endpoint string) *LocalRelayController {
	return &LocalRelayController{
		alloc:    alloc,
		fw:       fw,
		endpoint: endpoint,
		mappings: make(map[uint16]struct{ ingress, external [32]byte }),
	}
}

// RegisterForwarder allocates a port and registers the forwarder mapping.
// On forwarder registration failure the port is released so the pool stays
// consistent.
func (c *LocalRelayController) RegisterForwarder(_ context.Context, ingress, external [32]byte) (uint16, error) {
	port, err := c.alloc.Allocate()
	if err != nil {
		return 0, err
	}
	if err := c.fw.Register(port, ingress, external); err != nil {
		c.alloc.Release(port)
		return 0, err
	}
	c.mu.Lock()
	c.mappings[port] = struct{ ingress, external [32]byte }{ingress, external}
	c.mu.Unlock()
	return port, nil
}

// UnregisterForwarder releases the port and removes the forwarder mapping.
// Returns nil for unknown ports so callers can safely retry cleanup.
func (c *LocalRelayController) UnregisterForwarder(_ context.Context, port uint16) error {
	c.mu.Lock()
	_, known := c.mappings[port]
	if known {
		delete(c.mappings, port)
	}
	c.mu.Unlock()
	if !known {
		return nil
	}
	// Forwarder may legitimately not know the port if the relay was
	// restarted between registration and now; that is treated as
	// idempotent cleanup.
	if err := c.fw.Unregister(port); err != nil && !errors.Is(err, relay.ErrUnknownPort) {
		// Even on dispatcher-unregister failure, release the port so the
		// pool does not leak. The error still propagates so the
		// reconciler can decide whether to retry.
		c.alloc.Release(port)
		return err
	}
	c.alloc.Release(port)
	return nil
}

// RelayEndpoint returns the configured public host string.
func (c *LocalRelayController) RelayEndpoint() string { return c.endpoint }

// ---------------------------------------------------------------------------
// noopRelayController — static endpoint controller.
// ---------------------------------------------------------------------------

// noopRelayController is used for the shared raw-WireGuard external listener.
// It publishes a static endpoint while making legacy forwarder mutation calls
// fail explicitly.
type noopRelayController struct {
	endpoint string
}

// NewNoopRelayController returns a RelayController whose mutating methods
// always return ErrNotImplemented. The endpoint argument is still
// honoured by RelayEndpoint so status.relayEndpoint is non-empty even in
// the stub state.
func NewNoopRelayController(endpoint string) RelayController {
	return &noopRelayController{endpoint: endpoint}
}

// RegisterForwarder always returns ErrNotImplemented.
func (n *noopRelayController) RegisterForwarder(_ context.Context, _, _ [32]byte) (uint16, error) {
	return 0, ErrNotImplemented
}

// UnregisterForwarder always returns ErrNotImplemented.
func (n *noopRelayController) UnregisterForwarder(_ context.Context, _ uint16) error {
	return ErrNotImplemented
}

// RelayEndpoint returns the configured public host string.
func (n *noopRelayController) RelayEndpoint() string { return n.endpoint }

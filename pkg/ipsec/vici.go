package ipsec

import (
	"errors"
	"fmt"
	"sort"

	"github.com/strongswan/govici/vici"
)

// ErrRejected marks a request charon answered with a failure, as opposed to
// one that did not reach it.
var ErrRejected = errors.New("charon refused the request")

// DefaultViciSocket is where charon listens unless strongswan.conf moves it.
const DefaultViciSocket = "/var/run/charon.vici"

// SAState is what the agent reports about one tunnel's IKE_SA.
type SAState struct {
	// IKEState is the IKE_SA state ("ESTABLISHED", "CONNECTING", ...) or ""
	// when charon holds no IKE_SA for the connection.
	IKEState string
	// InstalledChildSAs counts CHILD_SAs in state INSTALLED.
	InstalledChildSAs int
}

// Charon is the subset of the vici protocol the agent uses. It is an
// interface so the reconcile logic can be tested without a daemon.
//
// Connections, their CHILD_SAs and their shared secrets are all addressed
// by the connection name, Tunnel.ConnName.
type Charon interface {
	LoadShared(t *Tunnel) error
	UnloadShared(conn string) error
	LoadConn(t *Tunnel) error
	UnloadConn(conn string) error
	// ListConns returns the names of the WireKube connections charon has
	// loaded.
	ListConns() ([]string, error)
	SA(conn string) (SAState, error)
	// Initiate starts the connection's CHILD_SA (and IKE_SA) without
	// waiting for the outcome.
	Initiate(conn string) error
}

// ViciCharon talks to charon over its vici socket. Each call opens its own
// session: calls are infrequent (once per sync) and a fresh session survives
// charon restarts without reconnect logic.
type ViciCharon struct {
	Socket string
}

func (c *ViciCharon) session() (*vici.Session, error) {
	socket := c.Socket
	if socket == "" {
		socket = DefaultViciSocket
	}
	s, err := vici.NewSession(vici.WithSocketPath(socket))
	if err != nil {
		return nil, fmt.Errorf("connecting to charon at %s: %w", socket, err)
	}
	return s, nil
}

func (c *ViciCharon) command(cmd string, msg *vici.Message) error {
	s, err := c.session()
	if err != nil {
		return err
	}
	defer s.Close()
	if resp, err := s.CommandRequest(cmd, msg); err != nil {
		if resp != nil {
			return fmt.Errorf("vici %s: %w: %w", cmd, ErrRejected, err)
		}
		return fmt.Errorf("vici %s: %w", cmd, err)
	}
	return nil
}

func (c *ViciCharon) LoadShared(t *Tunnel) error {
	msg, err := t.LoadSharedMessage()
	if err != nil {
		return err
	}
	return c.command("load-shared", msg)
}

func (c *ViciCharon) UnloadShared(conn string) error {
	msg := vici.NewMessage()
	if err := msg.Set("id", conn); err != nil {
		return err
	}
	return c.command("unload-shared", msg)
}

func (c *ViciCharon) LoadConn(t *Tunnel) error {
	msg, err := t.LoadConnMessage()
	if err != nil {
		return err
	}
	return c.command("load-conn", msg)
}

// UnloadConn removes the connection definition and terminates its SAs.
// unload-conn alone keeps established SAs alive, which would leave a deleted
// tunnel forwarding traffic, so the IKE_SA is terminated explicitly first.
func (c *ViciCharon) UnloadConn(conn string) error {
	s, err := c.session()
	if err != nil {
		return err
	}
	defer s.Close()

	term := vici.NewMessage()
	if err := setAll(term, kv{"ike", conn}, kv{"force", "yes"}, kv{"timeout", "-1"}); err != nil {
		return err
	}
	// terminate reports failure when there is nothing to terminate; that is
	// the common case for a tunnel that never came up, so it is not an error.
	_, _ = s.StreamedCommandRequest("terminate", "control-log", term)

	unload := vici.NewMessage()
	if err := unload.Set("name", conn); err != nil {
		return err
	}
	if _, err := s.CommandRequest("unload-conn", unload); err != nil {
		return fmt.Errorf("vici unload-conn: %w", err)
	}
	return nil
}

// Initiate asks charon to bring the tunnel up and returns at once
// (timeout -1); the outcome shows up in the next SA query.
func (c *ViciCharon) Initiate(conn string) error {
	s, err := c.session()
	if err != nil {
		return err
	}
	defer s.Close()
	msg := vici.NewMessage()
	if err := setAll(msg, kv{"child", conn}, kv{"ike", conn}, kv{"timeout", "-1"}); err != nil {
		return err
	}
	if _, err := s.StreamedCommandRequest("initiate", "control-log", msg); err != nil {
		return fmt.Errorf("vici initiate: %w", err)
	}
	return nil
}

func (c *ViciCharon) ListConns() ([]string, error) {
	s, err := c.session()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	msgs, err := s.StreamedCommandRequest("list-conns", "list-conn", nil)
	if err != nil {
		return nil, fmt.Errorf("vici list-conns: %w", err)
	}
	return ownedNames(msgs), nil
}

// ownedNames extracts WireKube connection names from list-conn events. Each
// event is a message keyed by connection name.
func ownedNames(msgs []*vici.Message) []string {
	seen := map[string]bool{}
	for _, m := range msgs {
		if m == nil {
			continue
		}
		for _, k := range m.Keys() {
			if _, ok := KeyOfConn(k); ok {
				seen[k] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (c *ViciCharon) SA(conn string) (SAState, error) {
	s, err := c.session()
	if err != nil {
		return SAState{}, err
	}
	defer s.Close()
	req := vici.NewMessage()
	if err := setAll(req, kv{"ike", conn}, kv{"noblock", "yes"}); err != nil {
		return SAState{}, err
	}
	msgs, err := s.StreamedCommandRequest("list-sas", "list-sa", req)
	if err != nil {
		return SAState{}, fmt.Errorf("vici list-sas: %w", err)
	}
	return parseSAs(conn, msgs), nil
}

// parseSAs folds list-sa events into one state. charon may hold several
// IKE_SAs for one connection during a rekey or a simultaneous initiation; an
// ESTABLISHED one wins over any other state.
func parseSAs(conn string, msgs []*vici.Message) SAState {
	var out SAState
	for _, m := range msgs {
		if m == nil {
			continue
		}
		ike, ok := m.Get(conn).(*vici.Message)
		if !ok {
			continue
		}
		if st, _ := ike.Get("state").(string); st != "" && out.IKEState != "ESTABLISHED" {
			out.IKEState = st
		}
		children, ok := ike.Get("child-sas").(*vici.Message)
		if !ok {
			continue
		}
		for _, k := range children.Keys() {
			child, ok := children.Get(k).(*vici.Message)
			if !ok {
				continue
			}
			if st, _ := child.Get("state").(string); st == "INSTALLED" {
				out.InstalledChildSAs++
			}
		}
	}
	return out
}

// Package papertrail provides a stub implementation for audit trail logging.
package papertrail

// Event represents an auditable event in the mesh lifecycle.
type Event struct {
	Action   string
	Node     string
	PeerName string
	Detail   string
}

// Logger is a stub interface for structured audit logging.
type Logger interface {
	Log(event Event) error
}

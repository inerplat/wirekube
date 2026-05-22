//go:build !linux

package wireguard

import "errors"

var errUserspaceEngineUnsupported = errors.New("wirekube userspace engine is only supported on linux")

// UserspaceEngine is a non-Linux stub so packages that contain platform-neutral
// helper tests can compile on developer workstations. Running the agent still
// requires Linux because the real implementation needs TUN, netlink, fwmark,
// and routing-table support.
type UserspaceEngine struct{}

// NewUserspaceEngine returns a stub engine on unsupported platforms.
func NewUserspaceEngine(_ string, _, _ int, _ *KeyPair) *UserspaceEngine {
	return &UserspaceEngine{}
}

func (u *UserspaceEngine) EnsureInterface() error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) Configure() error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) DeleteInterface() error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) Close() error {
	return nil
}

func (u *UserspaceEngine) InterfaceName() string {
	return ""
}

func (u *UserspaceEngine) ListenPort() int {
	return 0
}

func (u *UserspaceEngine) InterfaceExists() bool {
	return false
}

func (u *UserspaceEngine) ConfigMatchesKey(_ *KeyPair) bool {
	return false
}

func (u *UserspaceEngine) SyncPeers(_ []PeerConfig) error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) ForceEndpoint(_, _ string) error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) PokeKeepalive(_ string) error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) GetStats() ([]PeerStats, error) {
	return nil, errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) SetAddress(_ string) error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) SetPreferredSrc(_ string) {}

func (u *UserspaceEngine) SyncRoutes(_ []string) error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) AddRoute(_ string) error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) DelRoute(_ string) error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) SetPeerPath(_ string, _ PathMode, _ string) error {
	return errUserspaceEngineUnsupported
}

func (u *UserspaceEngine) SetRelayTransport(_ RelayTransport) {}

func (u *UserspaceEngine) LastDirectReceive(_ string) int64 {
	return 0
}

func (u *UserspaceEngine) LastRelayReceive(_ string) int64 {
	return 0
}

func (u *UserspaceEngine) MarkBimodalHint(_ [32]byte) {}

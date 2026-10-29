//go:build !linux

package ipsec

import (
	"errors"
	"net"
)

var errUnsupported = errors.New("IPsec tunnels are supported on Linux only")

func EnsureRule(string) error                      { return errUnsupported }
func IsUnsupported(err error) bool                 { return errors.Is(err, errUnsupported) }
func RemoveRule()                                  {}
func EnsureInterface(string, uint32, int) error    { return errUnsupported }
func DeleteInterface(string) error                 { return nil }
func ListInterfaces() ([]string, error)            { return nil, nil }
func SyncRoutes(map[string][]string, net.IP) error { return errUnsupported }
func SyncGuard([]SelectorPair, []string) error     { return errUnsupported }
func RemoveGuard()                                 {}
func RemoveAll() error                             { return nil }
func RemoveTunnelState() error                     { return nil }
func GuardDrops() (map[SelectorPair]uint64, error) { return nil, errUnsupported }
func XFRMInterfaceBlocker() string                 { return errUnsupported.Error() }

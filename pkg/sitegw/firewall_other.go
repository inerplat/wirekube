//go:build !linux

package sitegw

import (
	"errors"
	"net/netip"
)

// EnsureFirewall is only available on Linux.
func EnsureFirewall(string, string) error { return errors.New("the site gateway firewall needs Linux") }

// UplinkAddresses is only available on Linux.
func UplinkAddresses(string) ([]netip.Addr, error) { return nil, errors.New("needs Linux") }

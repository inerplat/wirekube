// Package ipam provides IP address management for WireKube mesh IPs.
// It allocates IPs from a CIDR block, tracking allocations in WireKubeMesh.status.
package ipam

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IPAM manages IP allocation from a CIDR block.
type IPAM struct {
	network *net.IPNet
	base    uint32
	size    uint32
}

// New creates a new IPAM instance for the given CIDR.
func New(cidr string) (*IPAM, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	base := ipToUint32(network.IP)
	ones, bits := network.Mask.Size()
	size := uint32(1) << (bits - ones)
	return &IPAM{network: network, base: base, size: size}, nil
}

// Allocate finds the first available IP from the pool, excluding already-allocated IPs.
// Returns the IP in CIDR notation (e.g., "10.100.0.2/32").
func (m *IPAM) Allocate(allocated []string) (string, error) {
	used := make(map[uint32]bool)
	for _, a := range allocated {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			// Try plain IP
			ip = net.ParseIP(a)
		}
		if ip != nil {
			used[ipToUint32(ip.To4())] = true
		}
	}

	// Skip network address (base+0) and broadcast (base+size-1)
	for i := uint32(1); i < m.size-1; i++ {
		candidate := m.base + i
		if !used[candidate] {
			ip := uint32ToIP(candidate)
			return ip.String() + "/32", nil
		}
	}
	return "", fmt.Errorf("CIDR %s is exhausted (all %d addresses allocated)", m.network.String(), m.size-2)
}

// Contains checks whether the given IP (plain or CIDR notation) falls within this IPAM's network.
func (m *IPAM) Contains(ipOrCIDR string) bool {
	ip, _, err := net.ParseCIDR(ipOrCIDR)
	if err != nil {
		ip = net.ParseIP(ipOrCIDR)
	}
	if ip == nil {
		return false
	}
	return m.network.Contains(ip)
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

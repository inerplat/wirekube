package connect

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// ErrDNSUnsupported reports that the host offers no per-interface resolver
// the dataplane knows how to program. The tunnel still works by IP.
var ErrDNSUnsupported = errors.New("per-interface DNS is not supported on this host")

// DNSConfig routes queries for the cluster domain to the cluster resolver.
type DNSConfig struct {
	Server netip.Addr
	// Domain is the cluster domain, e.g. "cluster.local". Only names under
	// it are sent to Server.
	Domain string
	// Search lists suffixes tried for short names, most specific first.
	Search []string
}

// Dataplane is the host side of a connect session: a WireGuard tunnel plus
// the address, routes and DNS that steer traffic into it.
type Dataplane interface {
	// Name is the OS interface name, which may differ from the requested one.
	Name() string
	// Apply programs the tunnel peer, interface address and routes. It is
	// idempotent and replaces whatever a previous Apply installed. The
	// returned warnings name ranges left to routes the host already had.
	Apply(cfg TunnelConfig, endpoint netip.AddrPort) ([]string, error)
	SetDNS(DNSConfig) error
	// LastHandshake is the most recent completed handshake with the ingress,
	// zero when none has completed yet.
	LastHandshake() time.Time
	// Close removes everything the dataplane installed on the host.
	Close() error
}

// hostNetwork configures the OS around an existing tunnel interface. Each
// supported platform provides one through newHostNetwork.
type hostNetwork interface {
	SetAddress(netip.Prefix) error
	// SyncRoutes routes each prefix into the tunnel unless the host already
	// routes exactly that prefix elsewhere, which it leaves alone and
	// reports: replacing it would lose it for good when the tunnel goes.
	SyncRoutes(routes []netip.Prefix, src netip.Addr) ([]string, error)
	SetDNS(DNSConfig) error
	Close() error
}

type wgDataplane struct {
	privateKey [32]byte
	tun        tun.Device
	dev        *device.Device
	host       hostNetwork
	name       string
	up         bool
}

// OpenDataplane creates the tunnel interface and an in-process wireguard-go
// device on it. Nothing is routed until Apply.
func OpenDataplane(ifName string, mtu int, privateKey [32]byte) (Dataplane, error) {
	if err := Supported(); err != nil {
		return nil, err
	}
	tdev, err := tun.CreateTUN(ifName, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tunnel interface %s (is another connect session using it? pass --interface): %w", ifName, err)
	}
	name, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return nil, fmt.Errorf("read tunnel interface name: %w", err)
	}
	host, err := newHostNetwork(name)
	if err != nil {
		tdev.Close()
		return nil, err
	}
	logger := device.NewLogger(device.LogLevelError, "[wirekube-connect] ")
	return &wgDataplane{
		privateKey: privateKey,
		tun:        tdev,
		dev:        device.NewDevice(tdev, conn.NewDefaultBind(), logger),
		host:       host,
		name:       name,
	}, nil
}

func (d *wgDataplane) Name() string { return d.name }

func (d *wgDataplane) Apply(cfg TunnelConfig, endpoint netip.AddrPort) ([]string, error) {
	uapi, err := uapiConfig(d.privateKey, cfg, endpoint)
	if err != nil {
		return nil, err
	}
	if err := d.dev.IpcSet(uapi); err != nil {
		return nil, fmt.Errorf("configure WireGuard device: %w", err)
	}
	if err := d.host.SetAddress(cfg.Address); err != nil {
		return nil, err
	}
	warnings, err := d.host.SyncRoutes(cfg.Routes, cfg.Address.Addr())
	if err != nil {
		return warnings, err
	}
	// wireguard-go follows the interface's up/down events, and the one for its
	// initial down state can land after an early Up and take the device down again,
	// so the device comes up only after the interface has.
	if !d.up {
		if err := d.dev.Up(); err != nil {
			return warnings, fmt.Errorf("bring WireGuard device up: %w", err)
		}
		d.up = true
	}
	return warnings, nil
}

func (d *wgDataplane) SetDNS(cfg DNSConfig) error { return d.host.SetDNS(cfg) }

func (d *wgDataplane) LastHandshake() time.Time {
	out, err := d.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	return parseLastHandshake(out)
}

func (d *wgDataplane) Close() error {
	hostErr := d.host.Close()
	// Closing the device closes the TUN, which takes the interface and every
	// route through it with it.
	d.dev.Close()
	return hostErr
}

// parseLastHandshake extracts the newest handshake time from a UAPI dump.
func parseLastHandshake(uapi string) time.Time {
	var latest time.Time
	var sec int64
	sc := bufio.NewScanner(strings.NewReader(uapi))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ := strconv.ParseInt(v, 10, 64)
			if sec == 0 && nsec == 0 {
				continue
			}
			if t := time.Unix(sec, nsec); t.After(latest) {
				latest = t
			}
		}
	}
	return latest
}

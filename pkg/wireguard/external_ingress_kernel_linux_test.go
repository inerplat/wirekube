//go:build linux

package wireguard

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// TestExternalIngressKernelRoundTrip pings the kernel through the shared device
// on a real TUN, exercising both the decrypt-into-TUN and the divert-from-TUN
// paths. It needs root and /dev/net/tun.
func TestExternalIngressKernelRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("needs /dev/net/tun")
	}
	const ifName = "wkext-test"
	real, err := tun.CreateTUN(ifName, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer real.Close()
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := netlink.ParseAddr("10.199.0.1/32")
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	_, client32, _ := net.ParseCIDR("100.64.0.9/32")
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: client32, Scope: netlink.SCOPE_LINK}); err != nil {
		t.Fatal(err)
	}
	setRpFilterForIface(ifName)

	// Stand in for the mesh device: drain what the split leaves it.
	split := newSplitTUN(real)
	go func() {
		bs := real.BatchSize()
		bufs := make([][]byte, bs)
		for i := range bufs {
			bufs[i] = make([]byte, 65535+device.MessageTransportHeaderSize)
		}
		sizes := make([]int, bs)
		for {
			if _, err := split.Read(bufs, sizes, device.MessageTransportHeaderSize); err != nil {
				return
			}
		}
	}()

	shared, _ := GenerateKeyPair()
	clientKey, _ := GenerateKeyPair()
	relay := &loopRelay{toClient: make(chan []byte, 64)}
	ext, err := newExternalIngress(split, func() RelayTransport { return relay }, shared.Private)
	if err != nil {
		t.Fatal(err)
	}
	defer ext.Close()
	if err := ext.SyncPeers([]ExternalPeerConfig{{PublicKeyB64: clientKey.PublicKeyBase64(), AllowedIP: "100.64.0.9/32"}}); err != nil {
		t.Fatal(err)
	}

	clientTUN := newMemTUN()
	client := device.NewDevice(clientTUN, &clientBind{deliver: ext.Deliver, fromNode: relay.toClient}, device.NewLogger(device.LogLevelError, "[client] "))
	defer client.Close()
	if err := client.IpcSet("private_key=" + hex.EncodeToString(clientKey.Private[:]) + "\n" +
		"public_key=" + hex.EncodeToString(shared.Public[:]) + "\n" +
		"endpoint=relay:1\nallowed_ip=10.199.0.0/16\n"); err != nil {
		t.Fatal(err)
	}
	if err := client.Up(); err != nil {
		t.Fatal(err)
	}

	clientTUN.fromKernel <- icmpEcho("100.64.0.9", "10.199.0.1", 0x77)
	deadline := time.After(10 * time.Second)
	for {
		select {
		case pkt := <-clientTUN.toKernel:
			if len(pkt) >= 28 && pkt[9] == 1 && pkt[20] == 0 &&
				netip.AddrFrom4([4]byte(pkt[12:16])) == netip.MustParseAddr("10.199.0.1") &&
				binary.BigEndian.Uint16(pkt[24:26]) == 0x77 {
				return
			}
		case <-deadline:
			t.Fatal("no echo reply from the kernel reached the client")
		}
	}
}

// icmpEcho builds an IPv4 ICMP echo request with valid checksums.
func icmpEcho(src, dst string, id uint16) []byte {
	p := make([]byte, 28)
	p[0], p[8], p[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(p[2:4], 28)
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	p[20] = 8
	binary.BigEndian.PutUint16(p[24:26], id)
	binary.BigEndian.PutUint16(p[26:28], 1)
	binary.BigEndian.PutUint16(p[22:24], checksum(p[20:]))
	return p
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

package nat

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// BirthdayMagic is the 4-byte prefix for hole-punch probe packets.
var BirthdayMagic = [4]byte{'W', 'K', 0x00, 0x01}

const (
	probePacketSize = 4 + 32 + 8 // magic + pubkey + nonce
	birthdayTimeout = 20 * time.Second
	probeInterval   = 2 * time.Millisecond
	numLocalSockets = 256
)

// HolePunchResult describes a successfully hole-punched UDP path.
type HolePunchResult struct {
	LocalConn  *net.UDPConn
	PeerAddr   *net.UDPAddr
	LocalAddr  string // local listener address for WG endpoint
}

// BirthdayAttack attempts NAT traversal via the birthday attack technique.
// Both peers must run this simultaneously — they each send probes from multiple
// local sockets to multiple candidate ports on the peer's public IP.
// With N sockets on each side and M candidate ports, the collision probability
// follows the birthday paradox: P ≈ 1 - e^(-N*M / 65536).
//
// When a probe is received, the receiver knows the sender's NAT-mapped source port,
// enabling a bidirectional UDP path to be established.
func BirthdayAttack(ctx context.Context, myPubKey [32]byte, peerPubKey [32]byte,
	peerPublicIP string, peerCandidatePorts []int) (*HolePunchResult, error) {

	if len(peerCandidatePorts) == 0 {
		return nil, fmt.Errorf("no candidate ports")
	}

	ctx, cancel := context.WithTimeout(ctx, birthdayTimeout)
	defer cancel()

	var nonce [8]byte
	rand.Read(nonce[:])

	// Open multiple local sockets for sending probes.
	sockets := make([]*net.UDPConn, 0, numLocalSockets)
	for i := 0; i < numLocalSockets; i++ {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
		if err != nil {
			continue
		}
		sockets = append(sockets, conn)
	}
	if len(sockets) == 0 {
		return nil, fmt.Errorf("failed to open any probe sockets")
	}
	defer func() {
		for _, s := range sockets {
			s.Close()
		}
	}()

	fmt.Printf("[birthday] opened %d probe sockets, targeting %d candidate ports on %s\n",
		len(sockets), len(peerCandidatePorts), peerPublicIP)

	// Build probe packet: magic + our pubkey + nonce
	probe := make([]byte, probePacketSize)
	copy(probe[0:4], BirthdayMagic[:])
	copy(probe[4:36], myPubKey[:])
	copy(probe[36:44], nonce[:])

	var result atomic.Pointer[HolePunchResult]
	var wg sync.WaitGroup

	// Listener goroutines: one per socket, listening for incoming probes.
	for idx, sock := range sockets {
		wg.Add(1)
		go func(conn *net.UDPConn, sockIdx int) {
			defer wg.Done()
			buf := make([]byte, 1500)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				if n < probePacketSize {
					continue
				}
				// Verify magic
				if buf[0] != BirthdayMagic[0] || buf[1] != BirthdayMagic[1] ||
					buf[2] != BirthdayMagic[2] || buf[3] != BirthdayMagic[3] {
					continue
				}
				// Verify it's from the expected peer
				var senderKey [32]byte
				copy(senderKey[:], buf[4:36])
				if senderKey != peerPubKey {
					continue
				}
				// Found a probe from our peer.
				fmt.Printf("[birthday] received probe from %s on local socket %d\n", addr, sockIdx)
				res := &HolePunchResult{
					LocalConn: conn,
					PeerAddr:  addr,
					LocalAddr: conn.LocalAddr().String(),
				}
				result.Store(res)
				cancel()
				return
			}
		}(sock, idx)
	}

	// Sender goroutine: cycle through sockets and candidate ports.
	wg.Add(1)
	go func() {
		defer wg.Done()
		peerIP := net.ParseIP(peerPublicIP)
		if peerIP == nil {
			return
		}
		packetsSent := 0
		for {
			for _, port := range peerCandidatePorts {
				for _, sock := range sockets {
					select {
					case <-ctx.Done():
						return
					default:
					}
					dest := &net.UDPAddr{IP: peerIP, Port: port}
					sock.WriteToUDP(probe, dest)
					packetsSent++
					if packetsSent%1000 == 0 {
						time.Sleep(probeInterval)
					}
				}
			}
			// One full round done; re-randomize nonce and repeat.
			rand.Read(nonce[:])
			copy(probe[36:44], nonce[:])
			time.Sleep(100 * time.Millisecond)
		}
	}()

	wg.Wait()

	if r := result.Load(); r != nil {
		// Detach the successful socket from the cleanup list.
		for i, s := range sockets {
			if s == r.LocalConn {
				sockets[i] = sockets[len(sockets)-1]
				sockets = sockets[:len(sockets)-1]
				break
			}
		}
		return r, nil
	}

	return nil, fmt.Errorf("birthday attack timed out after %s", birthdayTimeout)
}

// ProbeToken generates a deterministic token from two public keys (sorted).
// Both peers compute the same token to identify their probing session.
func ProbeToken(keyA, keyB [32]byte) uint64 {
	var first, second [32]byte
	if keyLess(keyA, keyB) {
		first, second = keyA, keyB
	} else {
		first, second = keyB, keyA
	}
	h := make([]byte, 64)
	copy(h[:32], first[:])
	copy(h[32:], second[:])
	return binary.LittleEndian.Uint64(h[:8]) ^ binary.LittleEndian.Uint64(h[32:40])
}

func keyLess(a, b [32]byte) bool {
	for i := range a {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}

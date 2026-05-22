package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/wirekube/wirekube/pkg/relay"
)

func main() {
	addr := flag.String("addr", ":3478", "TCP listen address")
	fwLow := flag.Int("forwarder-port-low", 0, "lowest UDP port the legacy per-peer forwarder may allocate (inclusive); 0 disables it")
	fwHigh := flag.Int("forwarder-port-high", 0, "highest UDP port the legacy per-peer forwarder may allocate (inclusive); 0 disables it")
	externalWGAddr := flag.String("external-wg-addr", "", "optional UDP listen address for shared raw-WireGuard external peers")
	externalWGIngress := flag.String("external-wg-ingress-pubkey", "", "optional base64 WireGuard public key of a fixed in-cluster ingress peer for --external-wg-addr; empty enables dynamic ingress fanout")
	flag.Parse()

	if envAddr := os.Getenv("WIREKUBE_RELAY_ADDR"); envAddr != "" {
		*addr = envAddr
	}
	if v := os.Getenv("WIREKUBE_FORWARDER_PORT_LOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*fwLow = n
		}
	}
	if v := os.Getenv("WIREKUBE_FORWARDER_PORT_HIGH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*fwHigh = n
		}
	}
	if v := os.Getenv("WIREKUBE_EXTERNAL_WG_ADDR"); v != "" {
		*externalWGAddr = v
	}
	if v := os.Getenv("WIREKUBE_EXTERNAL_WG_INGRESS_PUBKEY"); v != "" {
		*externalWGIngress = v
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("wirekube-relay starting on %s", *addr)

	srv := relay.NewServer()
	if *fwHigh > 0 && *fwLow > 0 && *fwHigh >= *fwLow {
		if err := srv.EnableForwarder(uint16(*fwLow), uint16(*fwHigh)); err != nil {
			log.Fatalf("enable forwarder: %v", err)
		}
		log.Printf("wirekube-relay forwarder pool: %d-%d", *fwLow, *fwHigh)
	} else {
		log.Printf("wirekube-relay legacy per-peer forwarder disabled")
	}
	if *externalWGAddr != "" {
		var ingress [relay.PubKeySize]byte
		if *externalWGIngress != "" {
			parsed, err := parsePubKey(*externalWGIngress)
			if err != nil {
				log.Fatalf("external WG ingress pubkey: %v", err)
			}
			ingress = parsed
		}
		if err := srv.EnableExternalWGListener(*externalWGAddr, ingress); err != nil {
			log.Fatalf("enable external WG listener: %v", err)
		}
	}
	if err := srv.ListenAndServe(*addr); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func parsePubKey(s string) ([relay.PubKeySize]byte, error) {
	var key [relay.PubKeySize]byte
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, err
	}
	if len(raw) != relay.PubKeySize {
		return key, fmt.Errorf("decoded key length = %d, want %d", len(raw), relay.PubKeySize)
	}
	copy(key[:], raw)
	return key, nil
}

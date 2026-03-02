package main

import (
	"flag"
	"log"
	"os"

	"github.com/wirekube/wirekube/pkg/relay"
)

func main() {
	addr := flag.String("addr", ":3478", "TCP listen address")
	flag.Parse()

	if envAddr := os.Getenv("WIREKUBE_RELAY_ADDR"); envAddr != "" {
		*addr = envAddr
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("wirekube-relay starting on %s", *addr)

	srv := relay.NewServer()
	if err := srv.ListenAndServe(*addr); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

// Command sitegw terminates the site-to-site IPsec tunnels of one connection
// in its own network namespace, without the WireKube mesh and without
// Kubernetes credentials. It reads the tunnels from a file, drives a charon
// that shares its namespace, and serves its state over HTTP for whoever runs
// it to read.
//
//	sitegw firewall --tenant-interface net1 --uplink-interface eth0
//	sitegw run --config /etc/sitegw/config.json --key-dir /etc/sitegw/keys --listen [$(POD_IP)]:8443
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/inerplat/wirekube/pkg/ipsec"
	"github.com/inerplat/wirekube/pkg/sitegw"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	log := zap.New().WithName("sitegw")
	var err error
	switch os.Args[1] {
	case "firewall":
		err = firewall(os.Args[2:])
	case "run":
		err = run(log, os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		log.Error(err, "sitegw")
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sitegw firewall|run [flags]")
	os.Exit(2)
}

func firewall(args []string) error {
	fs := flag.NewFlagSet("firewall", flag.ExitOnError)
	tenant := fs.String("tenant-interface", "net1", "interface on the network behind the gateway")
	uplink := fs.String("uplink-interface", "eth0", "interface toward the remote gateways")
	_ = fs.Parse(args)
	return sitegw.EnsureFirewall(*tenant, *uplink)
}

func run(log logr.Logger, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	config := fs.String("config", "/etc/sitegw/config.json", "tunnel config file")
	keyDir := fs.String("key-dir", "/etc/sitegw/keys", "directory holding one file per pre-shared key")
	socket := fs.String("vici-socket", "/run/wirekube-ipsec/charon.vici", "charon vici socket")
	listen := fs.String("listen", "", "address of the status, health and metrics server; must be a specific IP, e.g. [$(POD_IP)]:8443, which also fits an IPv6 pod IP")
	interval := fs.Duration("interval", 10*time.Second, "time between syncs")
	tenant := fs.String("tenant-interface", "net1", "interface on the network behind the gateway")
	uplink := fs.String("uplink-interface", "eth0", "interface toward the remote gateways")
	noFirewall := fs.Bool("no-firewall", false, "do not check the namespace firewall (tests only)")
	_ = fs.Parse(args)

	if *interval <= 0 {
		return fmt.Errorf("--interval %s must be positive", *interval)
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("--listen %q: %w", *listen, err)
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		// The tenant side must never reach this server; binding every
		// address would rely on the firewall alone.
		return fmt.Errorf("--listen %q must name one IP address", *listen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	failures := &ipsec.FailureWatcher{Socket: *socket}
	go failures.Run(ctx)
	// Only tenant traffic is routed into XFRM interfaces and guarded: the
	// pod's own replies on the uplink are left alone even when a remote
	// selector covers their destination.
	engine := sitegw.NewEngine(&ipsec.ViciCharon{Socket: *socket}, sitegw.KernelDataplane{InputInterface: *tenant}, failures, log)
	engine.CharonHint = "check the charon container of this pod and the vici socket " + *socket
	reg := prometheus.NewRegistry()
	metrics := sitegw.NewMetrics(reg)
	engine.OnGuard = metrics.RecordGuard

	runner := &sitegw.Runner{
		Engine:     engine,
		Publisher:  sitegw.NewPublisher(os.Getenv("POD_UID"), ""),
		ConfigPath: *config,
		KeyDir:     *keyDir,
		Interval:   *interval,
		Log:        log,
		Metrics:    metrics,
	}
	runner.OwnAddresses = func() ([]netip.Addr, error) { return sitegw.UplinkAddresses(*uplink) }
	if !*noFirewall {
		ensure := func() error { return sitegw.EnsureFirewall(*tenant, *uplink) }
		// The tenant side must not reach the server before the firewall
		// drops what it sends to the pod.
		for err := ensure(); err != nil; err = ensure() {
			log.Error(err, "namespace firewall not in place; not serving yet")
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(*interval):
			}
		}
	}
	runner.Publisher.Stale = runner.Stale

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", runner.Publisher.ServeStatus)
	mux.HandleFunc("/healthz", runner.ServeHealth)
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      sitegw.MaxWait + 10*time.Second,
		IdleTimeout:       2 * sitegw.MaxWait,
		// Requests end with the process: a long poll answers at once with
		// the current snapshot instead of holding the shutdown.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go runner.Run(ctx)
	shutDown := make(chan struct{})
	go func() {
		defer close(shutDown)
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	log.Info("site gateway serving", "listen", *listen, "config", *config)
	err = srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-shutDown
	return nil
}

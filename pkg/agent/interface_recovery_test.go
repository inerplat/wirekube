package agent

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
)

// A second agent sharing the interface name deletes the device on its own
// SIGTERM, and the survivor used to loop on "device closed" forever because
// EnsureInterface was only ever called from setup().
func TestEnsureInterfaceAliveRecreatesVanishedDevice(t *testing.T) {
	fake := &fakeWGEngine{ifaceGone: true}
	a := &Agent{wgMgr: fake, log: logr.Discard()}

	if err := a.ensureInterfaceAlive(); err != nil {
		t.Fatalf("ensureInterfaceAlive: %v", err)
	}
	if fake.ensureCalls != 1 {
		t.Errorf("EnsureInterface called %d times, want 1", fake.ensureCalls)
	}
	// A recreated device has no private key or listen port until Configure runs.
	if fake.configureCalls != 1 {
		t.Errorf("Configure called %d times, want 1", fake.configureCalls)
	}
	if !fake.InterfaceExists() {
		t.Error("interface still missing after recovery")
	}
}

func TestEnsureInterfaceAliveNoopWhenPresent(t *testing.T) {
	fake := &fakeWGEngine{}
	a := &Agent{wgMgr: fake, log: logr.Discard()}

	for i := 0; i < 3; i++ {
		if err := a.ensureInterfaceAlive(); err != nil {
			t.Fatalf("ensureInterfaceAlive: %v", err)
		}
	}
	// Runs on every sync tick, so a healthy device must not be touched.
	if fake.ensureCalls != 0 || fake.configureCalls != 0 {
		t.Errorf("healthy interface was reconfigured: ensure=%d configure=%d",
			fake.ensureCalls, fake.configureCalls)
	}
}

// Recreation can legitimately fail (a foreign link now holds the name). The
// error has to reach the caller so sync reports it instead of proceeding
// against a device that is not there.
func TestEnsureInterfaceAliveSurfacesFailure(t *testing.T) {
	wantErr := errors.New("refusing to touch foreign link")
	fake := &fakeWGEngine{ifaceGone: true, ensureErr: wantErr}
	a := &Agent{wgMgr: fake, log: logr.Discard()}

	err := a.ensureInterfaceAlive()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error %v does not wrap %v", err, wantErr)
	}
	if fake.configureCalls != 0 {
		t.Error("Configure ran despite EnsureInterface failing")
	}
}

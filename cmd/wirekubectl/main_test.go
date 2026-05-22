package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

func TestRenderConfIncludesExternalPeerMTU(t *testing.T) {
	conf := renderConf("private", &wirekubev1alpha1.WireKubeExternalPeer{
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			AssignedMeshIP:      "100.102.23.169/32",
			IngressPublicKey:    "ingress",
			RelayEndpoint:       "relay.example.com:3478",
			AllowedDestinations: []string{"100.64.0.0/10"},
		},
	})
	if !strings.Contains(conf, "MTU = 1248\n") {
		t.Fatalf("rendered config missing external peer MTU:\n%s", conf)
	}
}

func TestRenderConfUsesStatusMTU(t *testing.T) {
	conf := renderConf("private", &wirekubev1alpha1.WireKubeExternalPeer{
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			MTU: 1200,
		},
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			AssignedMeshIP:      "100.102.23.169/32",
			IngressPublicKey:    "ingress",
			RelayEndpoint:       "relay.example.com:3478",
			AllowedDestinations: []string{"100.64.0.0/10"},
			MTU:                 1248,
		},
	})
	if !strings.Contains(conf, "MTU = 1248\n") {
		t.Fatalf("rendered config did not prefer status MTU:\n%s", conf)
	}
}

func TestWriteExternalPeerTable(t *testing.T) {
	now := time.Date(2026, 5, 21, 15, 0, 0, 0, time.UTC)
	created := metav1.NewTime(now.Add(-1 * time.Hour))
	var out bytes.Buffer
	err := writeExternalPeerTable(&out, []wirekubev1alpha1.WireKubeExternalPeer{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "alice",
				CreationTimestamp: created,
			},
			Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
				DisplayName: "Alice",
			},
			Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
				Phase:           wirekubev1alpha1.ExternalPeerPhaseActive,
				AssignedMeshIP:  "100.102.23.169/32",
				RelayEndpoint:   "vpn.example.com:3478",
				IngressPeerName: "worker1",
				MTU:             1248,
			},
		},
	}, now)
	if err != nil {
		t.Fatalf("writeExternalPeerTable: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"NAME",
		"alice",
		"Active",
		"100.102.23.169/32",
		"vpn.example.com:3478",
		"worker1",
		"1248",
		"1h",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("external peer table missing %q:\n%s", want, got)
		}
	}
}

func TestExternalPeerMTUFallsBackToDefault(t *testing.T) {
	got := externalPeerMTU(&wirekubev1alpha1.WireKubeExternalPeer{})
	if got != wirekubev1alpha1.DefaultExternalPeerMTU {
		t.Fatalf("externalPeerMTU = %d, want %d", got, wirekubev1alpha1.DefaultExternalPeerMTU)
	}
}

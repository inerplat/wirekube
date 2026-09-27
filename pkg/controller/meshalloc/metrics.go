package meshalloc

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The occupancy gauges answer the one question the allocator cannot answer for
// itself: when does the mesh CIDR need widening? Exhaustion is terminal —
// nothing frees up on its own — so it has to be visible well before it
// arrives, and the birthday bound means collisions (and so renumbering) start
// long before the pool is actually full.
//
// They are gauges recomputed from a list on every sweep rather than counters
// incremented at allocation and decremented at release. A counter would need
// a decrement on the reclaim path, and the reclaim path exists precisely for
// claims whose holder is gone and therefore cannot decrement anything; the
// count would drift downward-blind and quietly stop meaning what it says.
var (
	meshAddressCapacity = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wirekube_mesh_addresses_capacity",
		Help: "Usable host addresses in the mesh CIDR.",
	}, []string{"mesh"})

	meshAddressAllocated = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wirekube_mesh_addresses_allocated",
		Help: "Mesh addresses currently claimed.",
	}, []string{"mesh"})

	meshAddressFree = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wirekube_mesh_addresses_free",
		Help: "Mesh addresses still available to claim.",
	}, []string{"mesh"})
)

// setOccupancy publishes one mesh's pool occupancy.
func setOccupancy(mesh string, capacity, allocated int) {
	free := capacity - allocated
	if free < 0 {
		free = 0
	}
	meshAddressCapacity.WithLabelValues(mesh).Set(float64(capacity))
	meshAddressAllocated.WithLabelValues(mesh).Set(float64(allocated))
	meshAddressFree.WithLabelValues(mesh).Set(float64(free))
}

// clearOccupancy drops a mesh's series. A mesh that has been deleted, or whose
// CIDR no longer parses, has no pool — leaving the last known values behind
// would be reported as a healthy pool forever.
func clearOccupancy(mesh string) {
	meshAddressCapacity.DeleteLabelValues(mesh)
	meshAddressAllocated.DeleteLabelValues(mesh)
	meshAddressFree.DeleteLabelValues(mesh)
}

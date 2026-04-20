//go:build !linux

package agent

func (a *Agent) ensureAPIServerRoute() {}

func (a *Agent) isAPIServerCIDR(cidr string) bool { return false }

# Cloud Provider Notes

WireKube is cloud-agnostic. This page documents provider-specific behaviors
relevant to NAT traversal and relay deployment.

---

## NAT Behavior Summary

All major cloud NAT gateways use Symmetric NAT (Endpoint-Dependent Mapping).
Cross-VPC direct P2P is impossible; relay is required.

| Provider | NAT Product | NAT Type | Direct P2P (cross-VPC) |
|----------|------------|----------|------------------------|
| AWS | NAT Gateway | Symmetric | No — relay required |
| GCP | Cloud NAT | Symmetric | No — relay required |
| Azure | Azure NAT Gateway | Symmetric | No — relay required |
| OCI | NAT Gateway | Symmetric | No — relay required |
| Home/ISP Router | Varies | Usually Cone | Yes — STUN works |

Nodes with public IPs (Elastic IP, External IP, etc.) behave like 1:1 NAT and
support direct P2P regardless of the cloud provider.

---

## AWS

### NAT Gateway

- **NAT Type:** Symmetric (per-destination port allocation)
- **Impact:** Direct P2P fails between nodes behind NAT Gateway
- **Solution:** Relay fallback

### Elastic IP

Nodes with EIPs support direct P2P. The agent detects EIPs via IMDSv2:

```
http://169.254.169.254/latest/meta-data/public-ipv4
```

### Security Groups

| Direction | Protocol | Port | Source | Purpose |
|-----------|----------|------|--------|---------|
| Inbound | UDP | 51820 | Mesh peers | WireGuard (direct P2P) |
| Inbound | TCP | 3478 | Mesh peers | Relay (if hosted here) |
| Outbound | UDP | 51820 | 0.0.0.0/0 | WireGuard |
| Outbound | TCP | 3478 | Relay IP | Relay connection |

### Network Load Balancer

- **UDP NLB:** Supported — can expose WireGuard or relay directly
- **TCP NLB:** Supported — for relay server

---

## GCP

### Cloud NAT

- **NAT Type:** Symmetric (per unique destination 3-tuple)
- **Solution:** Relay fallback for cross-VPC

### External IP

VMs with external IPs support direct P2P.

### Firewall Rules

```bash
gcloud compute firewall-rules create wirekube-wg \
  --allow udp:51820 \
  --source-ranges 0.0.0.0/0 \
  --target-tags wirekube

gcloud compute firewall-rules create wirekube-relay \
  --allow tcp:3478 \
  --source-ranges 0.0.0.0/0 \
  --target-tags wirekube-relay
```

---

## Azure

### Azure NAT Gateway

- **NAT Type:** Symmetric (five-tuple hash for SNAT)
- **Solution:** Relay fallback

### Network Security Group

```bash
az network nsg rule create \
  --resource-group myRG \
  --nsg-name myNSG \
  --name AllowWireGuard \
  --protocol Udp \
  --destination-port-ranges 51820 \
  --priority 100
```

---

## OCI (Oracle Cloud Infrastructure)

### NAT Gateway

- **NAT Type:** Symmetric
- **Solution:** Relay fallback for cross-VCN traffic

### Security Lists / NSGs

| Direction | Protocol | Port | Purpose |
|-----------|----------|------|---------|
| Ingress | UDP | 51820 | WireGuard |
| Ingress | TCP | 3478 | Relay |
| Egress | All | All | Allow outbound |

---

## Bare Metal / On-Premises

### Typical NAT

Most enterprise firewalls and residential routers use Cone NAT.
STUN-based P2P usually works.

### Port Forwarding

If UPnP/NAT-PMP is available, the agent can request port mappings automatically.
Otherwise, use manual annotation:

```bash
kubectl annotate node <node-name> wirekube.io/endpoint="203.0.113.5:51820"
```

### Firewall Requirements

| Direction | Protocol | Port | Purpose |
|-----------|----------|------|---------|
| Inbound | UDP | 51820 | WireGuard |
| Outbound | TCP | 3478 | Relay (if needed) |
| Outbound | UDP | 3478 | STUN |

---

## Expected Transport Modes by Topology

| Path | Expected Mode | Why |
|------|--------------|-----|
| Same VPC (private ↔ private) | Direct | Same subnet, no NAT |
| Same VPC (private ↔ public) | Direct | Same subnet |
| Cross VPC (Symmetric ↔ Symmetric) | Relay | Both behind Symmetric NAT |
| Cross VPC (one has public IP) | Direct P2P | Public IP reachable |
| On-premises (Cone) ↔ Cloud (public IP) | Direct P2P | Public IP reachable |
| On-premises (Cone) ↔ Cloud (Symmetric NAT) | Relay | Symmetric side proactively uses relay |
| On-premises (Cone) ↔ On-premises (Cone) | Direct P2P | Both Cone, STUN stable |
| On-premises ↔ On-premises (same LAN) | Direct | Same network |

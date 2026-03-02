# Cloud Provider Notes

WireKube is cloud-agnostic. This page documents provider-specific behaviors
and configurations discovered during testing.

---

## AWS

### NAT Gateway

- **NAT Type:** Symmetric (Endpoint-Dependent Mapping)
- **Impact:** Direct P2P impossible between nodes behind NAT Gateway
- **Solution:** Relay fallback

### Elastic IP

Nodes with EIPs support direct P2P. The agent detects EIPs via IMDSv2:

```
http://169.254.169.254/latest/meta-data/public-ipv4
```

### Security Groups

Required rules:

| Direction | Protocol | Port | Source | Purpose |
|-----------|----------|------|--------|---------|
| Inbound | UDP | 51820 | Mesh peers | WireGuard (direct P2P) |
| Inbound | TCP | 3478 | Mesh peers | Relay (if relay on this node) |
| Outbound | UDP | 51820 | 0.0.0.0/0 | WireGuard |
| Outbound | TCP | 3478 | Relay IP | Relay connection |

### Network Load Balancer

- **UDP NLB:** Supported — can expose WireGuard directly
- **TCP NLB:** Supported — for relay server

---

## GCP

### Cloud NAT

- **NAT Type:** Symmetric
- **Impact:** Same as AWS NAT Gateway
- **Solution:** Relay fallback

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

## NCloud (Naver Cloud)

### NAT Gateway

- **NAT Type:** Symmetric (verified via STUN testing)
- **Impact:** Direct P2P impossible between private subnet nodes

### Load Balancer Limitations

!!! warning "UDP Load Balancer"
    **NCloud JPN region does not support UDP Load Balancers.**
    API returns error code `1200053: The protocol type is invalid.`
    
    TCP NLB works correctly for the relay server.

### Public IP

- Public IPs can only be assigned to servers in **public subnets**
- Private subnet servers cannot have public IPs
- Use TCP NLB for relay access

### Access Control Group (ACG)

Required rules:

| Direction | Protocol | Port | Source | Purpose |
|-----------|----------|------|--------|---------|
| Inbound | UDP | 51820 | Mesh peers | WireGuard |
| Inbound | TCP | 3478 | 0.0.0.0/0 | Relay |
| Inbound | TCP | 6443 | 0.0.0.0/0 | Kubernetes API |

### Tested Configuration

Successfully tested with:

- VPC1: CP (private) + W1 (private) + W2 (public subnet, direct IP)
- VPC3: W3 (private, separate VPC with own NAT GW)
- Local: Multipass VM (macOS ARM64)
- All 20 paths: 100% success (direct + relay mix)

---

## Azure

### Azure NAT Gateway

- **NAT Type:** Symmetric
- **Impact:** Same as other cloud providers
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

## Bare Metal / On-Premises

### Typical NAT

Most enterprise firewalls and residential routers use Cone NAT (Full or Restricted).
STUN-based P2P usually works.

### Port Forwarding

If UPnP/NAT-PMP is available, the agent can request port mappings automatically.
Otherwise, use manual annotation:

```bash
kubectl annotate node on-prem-node wirekube.io/endpoint="203.0.113.5:51820"
```

### Firewall Requirements

| Direction | Protocol | Port | Purpose |
|-----------|----------|------|---------|
| Inbound | UDP | 51820 | WireGuard |
| Outbound | TCP | 3478 | Relay (if needed) |
| Outbound | UDP | 3478 | STUN |

---

## Home Lab / Multipass

### Multipass VMs (macOS)

Multipass VMs on macOS use a shared NAT network:

```
macOS host --- NAT --- Multipass VM (192.168.x.x)
```

This is typically **Cone NAT**, so STUN-based direct P2P works to public IP
peers. For reaching peers behind Symmetric NAT (cloud), relay is needed.

### Mixed Home + Cloud

| Path | Expected Mode |
|------|--------------|
| Home ↔ Cloud (public IP node) | Direct P2P |
| Home ↔ Cloud (private, Symmetric NAT) | Relay |
| Home ↔ Home (same LAN) | Direct |

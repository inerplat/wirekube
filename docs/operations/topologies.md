# Deployment Topologies

WireKube adapts to various network topologies automatically. This page
describes common deployment patterns and their expected behavior.

## Topology 1: All Private (Cloud NAT)

All nodes are in private subnets behind NAT gateways.

```mermaid
flowchart TB
    subgraph VPC1["VPC-1 (Private)"]
        CP[CP]
        W1[W1]
        NAT1[NAT GW]
    end
    subgraph VPC2["VPC-2 (Private)"]
        W3[W3]
        NAT2[NAT GW]
    end
    subgraph Relay["Relay Server (TCP 3478)"]
        R[Relay]
    end
    VPC1 --> Relay
    VPC2 --> Relay
```

| Path | Mode | Why |
|------|------|-----|
| CP ↔ W1 (same VPC) | Direct | Same subnet, no NAT |
| CP ↔ W3 (cross VPC) | Relay | Both behind Symmetric NAT |
| W1 ↔ W3 (cross VPC) | Relay | Both behind Symmetric NAT |

**Relay is essential.** Without it, cross-VPC communication is impossible
when both sides are behind Symmetric NAT.

## Topology 2: Mixed (Private + Public)

Some nodes have public IPs, others are behind NAT.

```mermaid
flowchart LR
    subgraph VPC1["VPC-1"]
        CP[CP priv]
        W2[W2 public]
        NAT1[NAT GW]
    end
    subgraph VPC2["VPC-2 (Private)"]
        W3[W3 priv]
        NAT2[NAT GW]
    end
```

| Path | Mode | Why |
|------|------|-----|
| CP ↔ W2 (same VPC) | Direct | Same subnet |
| W2 ↔ W3 (cross VPC) | Direct | W2 has public IP, W3 can reach it directly |
| CP ↔ W3 (cross VPC) | Relay | Both behind Symmetric NAT |

**Public IP nodes act as anchor points.** Any peer can reach them directly
via their public endpoint. This reduces relay dependency.

## Topology 3: Multi-Cloud

Nodes span multiple cloud providers.

```mermaid
flowchart LR
    AWS[AWS VPC NAT GW] <--> R1[Relay]
    R1 <--> GCP[GCP VPC Cloud NAT]
    GCP <--> R2[Relay]
    R2 <--> OP[On-Prem Firewall]
```

| Path | Mode | Why |
|------|------|-----|
| AWS ↔ GCP | Relay | Both behind Symmetric NAT (cloud NAT) |
| AWS ↔ On-Prem (public) | Direct | On-prem has public IP |
| GCP ↔ On-Prem (public) | Direct | On-prem has public IP |

WireKube works identically across clouds. The relay server can be deployed
anywhere with TCP reachability from all nodes.

## Topology 4: Home Lab + Cloud

Mix of home network nodes and cloud nodes.

```mermaid
flowchart LR
    subgraph Home["Home Lab"]
        N1[node-1 Cone NAT]
        UPnP[Router: UPnP enabled]
    end
    subgraph Cloud["Cloud VPC"]
        N2[node-2 Symmetric NAT]
        NAT[NAT GW]
    end
```

| Path | Mode | Why |
|------|------|-----|
| Home ↔ Cloud (private) | Relay | Cloud node is Symmetric NAT |
| Home ↔ Cloud (public IP) | Direct | Cloud node has public IP |
| Home ↔ Home (same LAN) | Direct | Same network |

Home routers typically use Cone NAT, which supports STUN-based endpoint
discovery. However, if the remote peer is behind Symmetric NAT, direct
P2P still fails — relay is needed.

## Topology 5: Air-Gapped with Bastion

Nodes behind a strict firewall with only outbound TCP allowed.

```mermaid
flowchart LR
    subgraph Secure["Secure Zone"]
        N1[node-1]
        N2[node-2]
        FW[Firewall: TCP out only]
    end
    subgraph DMZ["Relay (DMZ)"]
        R[Relay]
    end
    Secure <-->|TCP 3478| DMZ
```

WireKube's TCP relay works through firewalls that allow outbound TCP.
Agents initiate outbound TCP connections to the relay — no inbound
ports need to be opened on the node's firewall.

## Choosing the Right Topology

```mermaid
graph TD
    A[All nodes have<br/>public IPs?] -->|Yes| B[No relay needed<br/>mode: never]
    A -->|No| C[Any nodes behind<br/>Symmetric NAT?]
    C -->|No| D[STUN P2P works<br/>mode: auto, relay unlikely]
    C -->|Yes| E[Deploy relay<br/>mode: auto]
    E --> F{Where to deploy relay?}
    F -->|Public server| G[External relay]
    F -->|In-cluster| H[Managed relay<br/>+ LoadBalancer]
```

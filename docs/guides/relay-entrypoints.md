# Relay Entry Points

WireKube recommends a public `LoadBalancer` Service for the relay. It gives agents one stable address and lets the cloud provider manage node replacement. When that is not available, the same relay can be exposed through NodePort or reached through an HTTP CONNECT forward proxy.

## Choose an entry point

| Environment | Relay endpoint | Agent proxy setting |
|-------------|----------------|---------------------|
| Cloud LB available | `<load-balancer-host>:3478` | Disabled |
| No LB, public cluster node available | `<public-node-ip>:30478` | Disabled |
| Node using an HTTP CONNECT proxy | Either endpoint above | `WIREKUBE_RELAY_PROXY=environment` |
| HTTP-aware LB or Ingress | `wss://<host>/relay` | Kubernetes-issued bearer token |

The base relay protocol is raw TCP, not HTTP. A TCP load balancer such as AWS NLB is compatible. A typical HTTP application load balancer or Kubernetes Ingress cannot forward the raw endpoint, so deploy the optional [WebSocket Relay Endpoint](../architecture/websocket-relay.md) when the entry point must use HTTPS/WSS.

## Recommended: public LoadBalancer

The default relay manifest creates the recommended public entry point:

Before applying it outside the EKS example environment, remove or replace the hard-coded `eks.amazonaws.com/nodegroup: relay-ng` selector in `config/relay/deployment.yaml`.

```bash
kubectl apply -f config/relay/deployment.yaml
kubectl -n wirekube-system get service wirekube-relay
```

Keep the mesh on `provider: managed` when every agent can resolve and reach the cluster-local `wirekube-relay-control` Service. For nodes that bootstrap outside cluster networking, use `provider: external` and set the public LB address:

```yaml
relay:
  mode: auto
  provider: external
  external:
    endpoint: "relay.example.com:3478"
    transport: tcp
```

## Alternative: NodePort

Deploy the relay, then change its public Service to NodePort:

```bash
kubectl apply -f config/relay/deployment.yaml
kubectl apply -f config/examples/relay-nodeport/service.yaml
kubectl -n wirekube-system get service wirekube-relay
```

The second apply updates the existing TCP Service and creates a separate UDP Service; both select the same relay Deployment. A cloud provider may briefly start provisioning the original load balancer between the two commands, then removes it after the TCP Service type changes.

The example fixes TCP to NodePort `30478` and UDP to NodePort `30479`. TCP carries agent relay connections. UDP is used by external WireGuard peers; it can remain blocked if that feature is not used.

Choose a stable, reachable node address and configure it as an external relay:

```bash
sed 's/REPLACE_WITH_PUBLIC_NODE_IP/203.0.113.10/' \
  config/examples/relay-nodeport/wirekubemesh-external.yaml | kubectl apply -f -
```

Before deploying agents, verify the path from the same network as the node:

```bash
nc -vz 203.0.113.10 30478
```

NodePort does not provide address failover by itself. Keep the selected node IP stable, or place a DNS record or external TCP load balancer in front of multiple NodePort-capable nodes.

## Through an HTTP(S) forward proxy

WireKube uses the standard `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables. The agent sends an HTTP `CONNECT` request to the proxy, then carries the relay's raw TCP stream through the tunnel.

Label only the nodes that require the proxy and deploy the dedicated DaemonSet:

```bash
kubectl label node <node> wirekube.io/proxy-node=true
kubectl apply -f config/agent/rbac.yaml
kubectl apply -f config/examples/http-proxy-node/daemonset.yaml
```

In that manifest, configure:

```yaml
- name: WIREKUBE_RELAY_PROXY
  value: "environment"
- name: HTTPS_PROXY
  value: "http://proxy.example.com:3128"
- name: HTTP_PROXY
  value: "http://proxy.example.com:3128"
```

The relay endpoint may be either form:

```yaml
# Public LB / TCP LB
endpoint: "relay.example.com:3478"

# NodePort reached through the same forward proxy
endpoint: "203.0.113.10:30478"
```

The proxy must allow CONNECT to the selected destination port. Do not add the relay host to `NO_PROXY`, or the agent will bypass the proxy. Proxying applies to the TCP relay control/data stream only; external-peer UDP cannot traverse an HTTP CONNECT proxy.

This forward-proxy flow is distinct from the WSS relay endpoint. CONNECT tunnels the existing raw TCP protocol through another proxy; WSS makes the relay itself an authenticated HTTP Upgrade endpoint.

## Through an HTTPS/WSS entry point

With easy install, create the trusted TLS Gateway or Ingress route to Service `wirekube-relay-ws` port `8081`, then select WSS explicitly:

```bash
wirekubectl install --relay load-balancer --relay-transport wss --relay-endpoint wss://relay.your-domain.example/relay --mesh-cidr 100.96.0.0/11 --yes
```

This installs the raw relay, the TokenReview-authenticated WebSocket gateway, and a separate UDP LoadBalancer for external WireGuard peers. The WebSocket Service remains ClusterIP because the existing HTTPS Gateway or Ingress owns the public hostname and certificate. `--relay-udp=false` disables the UDP LoadBalancer when external peers are not required.

For a TLS terminator that forwards to node addresses instead of a ClusterIP Service, use `--relay node-port --relay-transport wss`; the installer exposes plain HTTP/WebSocket on NodePort `30478`. Add `--relay-udp --relay-udp-endpoint HOST:30479` only when external WireGuard peers also need the UDP NodePort.

Deploy the WSS gateway separately from the raw relay, expose it through an HTTPS Gateway or Ingress, and keep at least two gateway replicas on different nodes:

```bash
kubectl apply -f config/relay/websocket.yaml
sed 's/relay.example.com/relay.your-domain.example/' config/examples/relay-wss/httproute.yaml | kubectl apply -f -
```

Select WSS in the WireKubeMesh. This is the only production transport selector; do not force an endpoint through the agent DaemonSet environment:

```yaml
relay:
  mode: auto
  provider: external
  external:
    endpoint: "203.0.113.10:3478"
    controlEndpoint: "wss://relay.your-domain.example/relay"
    transport: wss
```

`transport: tcp` uses the raw endpoint and does not open a WebSocket session. `transport: wss` uses only `controlEndpoint` for the agent session and keeps `endpoint` for NAT probing and external WireGuard peers when one is configured. Running both Services is safe because they are entry points to the same relay, but one agent public key must not connect through both transports simultaneously.

## Verify the selected path

```bash
kubectl -n wirekube-system logs daemonset/wirekube-agent-proxy \
  | grep -E 'relay connected|relay initial connect failed|proxy'
kubectl get wirekubepeers -o wide
```

If the direct path is unavailable, peer connection status should converge to `relay`. See [Troubleshooting](../operations/troubleshooting.md) when CONNECT is rejected or the NodePort is unreachable.

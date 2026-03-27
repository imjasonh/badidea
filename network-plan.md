# Plan: Networks

## Goal

Implement enough of the Docker network API that `docker network create`, `docker run --network`, and basic compose networking work. The scope is deliberately limited -- Docker's network model doesn't map cleanly to K8s, and trying to fully replicate it isn't worth the complexity.

## Background: why this is hard

Docker networking gives each container its own network namespace and connects them via virtual bridges. Containers on the same network can reach each other by name. Docker manages DNS, IP allocation, port mapping, and bridge interfaces.

K8s networking is fundamentally different:
- Every pod gets a cluster-routable IP by default (no bridges, no NAT between pods)
- DNS is handled by CoreDNS at the cluster level, not per-network
- There's no concept of "networks" as isolation boundaries -- NetworkPolicy is the closest analog
- Port mapping (`-p`) in Docker means iptables DNAT on the host; in K8s it means creating a Service

## What we can implement

### Network CRUD (cosmetic)

| Endpoint | Implementation |
|----------|---------------|
| `GET /networks` | Return list of "networks" (stored as ConfigMaps with a label) |
| `POST /networks/create` | Create a ConfigMap representing the network |
| `GET /networks/{id}` | Get the ConfigMap |
| `DELETE /networks/{id}` | Delete the ConfigMap |
| `POST /networks/prune` | Delete ConfigMaps not referenced by any running pod |
| `POST /networks/{id}/connect` | Add network label to pod |
| `POST /networks/{id}/disconnect` | Remove network label from pod |

ConfigMaps are used as the storage mechanism because networks are just metadata -- they don't correspond to any real K8s networking primitive. Labels on pods track which "network" they belong to.

A default `bridge` network always exists (just like Docker). All containers are on it unless specified otherwise.

### Container-to-container DNS

This is the most useful part of Docker networking: `docker run --name db --network mynet postgres` followed by `docker run --network mynet myapp` where `myapp` connects to `db` by hostname.

Implementation: for each pod on a "network", create a headless Service (ClusterIP: None) with the pod's name as the service name. This makes `db.default.svc.cluster.local` resolve to the pod's IP. The short name `db` will resolve from within the same namespace thanks to the default search domains.

When a container is created with `--network mynet`:
1. Add label `badidea.network/mynet: "true"` to the pod
2. Create a headless Service named after the pod, selecting that specific pod

When the pod is deleted, also delete its headless Service.

### Network aliases

Docker supports `--network-alias` to give a container additional DNS names on a network. Implement by creating additional headless Services for each alias, all selecting the same pod.

### Port mapping (`-p`)

Docker's `-p 8080:80` maps host port 8080 to container port 80.

Implementation: create a K8s Service of type `LoadBalancer` (or `ClusterIP` for internal-only access) with the specified port mapping. This is slow compared to Docker (GKE provisions a real load balancer), but it works.

For the initial implementation, only support `ClusterIP` services. This means ports are reachable from within the cluster but not from outside. External access can be added later via LoadBalancer or Ingress.

## What we will NOT implement

### Bridge/overlay/macvlan drivers
Docker network drivers manage actual network plumbing (veth pairs, bridges, VXLAN tunnels). K8s handles all of this via the CNI plugin. We won't pretend to support driver selection. All networks are effectively "bridge" from the Docker perspective.

**Limitation:** `docker network create --driver overlay` will be accepted but ignored. The driver field is stored but has no effect.

### Network isolation
In Docker, containers on different networks can't reach each other by default. In K8s, all pods can reach all other pods unless you use NetworkPolicy.

**Limitation:** Creating separate networks does NOT provide isolation. Any pod can reach any other pod regardless of network membership. We could use NetworkPolicy to enforce isolation, but this adds significant complexity and may conflict with cluster-level policies. Documenting this as a known difference is better than a partial implementation.

### Host networking (`--network host`)
In Docker this shares the host's network namespace. In K8s this is `hostNetwork: true`, which GKE Autopilot does not allow.

**Limitation:** `--network host` returns an error.

### IPv6, dual-stack
Not worth the complexity for a PoC.

### Subnet/gateway configuration
`docker network create --subnet 10.0.0.0/24 --gateway 10.0.0.1` configures IP allocation. K8s manages pod CIDR ranges at the cluster level.

**Limitation:** Subnet/gateway options are accepted but ignored.

### Internal networks (`--internal`)
Docker internal networks have no outbound connectivity. Could be implemented via NetworkPolicy egress rules, but not worth it initially.

**Limitation:** `--internal` is accepted but ignored.

## Implementation order

1. Network CRUD endpoints (ConfigMap-based storage, purely metadata)
2. Default `bridge` network (always present, all containers are members)
3. `--network` flag in `containerCreate` -- add labels, create headless Service for DNS
4. Network aliases -- additional headless Services
5. Port mapping via ClusterIP Services
6. Clean up Services on pod deletion
7. `networks/connect` and `networks/disconnect`
8. Tests

Steps 1-3 are the minimum viable feature. Steps 4-7 are nice-to-haves.

## Open questions

- Should we use NetworkPolicy for isolation? It would make the behavior more Docker-like but adds complexity and requires the cluster's CNI to support it (GKE Autopilot does). Leaning no for now.
  - Answer: No. Just document this shortcoming.
- Should port mapping use LoadBalancer services for external access? This is slow (30-60s provisioning) and costs money per service. Leaning no -- ClusterIP only for now, with a note that external access is possible via `kubectl port-forward` or by adding LoadBalancer support later.
  - Answer: Agree with your assessment: ClusterIP, document this shortcoming.

## Known limitations (implemented)

These are inherent to the K8s-backed approach and documented here for users:

### No network isolation
Creating separate Docker networks does **not** provide isolation. Any pod can reach any other pod regardless of network membership. In real Docker, containers on different networks are isolated by default. We could enforce this with NetworkPolicy, but that adds significant complexity and may conflict with cluster-level policies.

### DNS is cluster-wide, not per-network
Docker scopes DNS names to a network: container `db` on `mynet` is only resolvable by other containers on `mynet`. Our implementation creates a headless Service for the container name, making it resolvable by **any** pod in the namespace, regardless of network membership. This is a fundamental difference from Docker networking.

### Subnet/gateway/IP configuration is ignored
`docker network create --subnet 10.0.0.0/24 --gateway 10.0.0.1` and similar options are accepted but have no effect. Kubernetes manages pod CIDR ranges at the cluster level.

### `--internal` is accepted but ignored
Docker internal networks have no outbound connectivity. We store the flag but do not create NetworkPolicy egress rules to enforce it.

### Driver selection has no effect
`--driver overlay`, `--driver macvlan`, etc. are accepted and stored in the ConfigMap, but all networks behave identically. There are no actual bridges, VXLAN tunnels, or macvlan interfaces.

### Port mapping creates ClusterIP only
`-p 8080:80` creates a ClusterIP Service, making the port reachable from within the cluster but **not** from outside. For external access, use `kubectl port-forward` or add LoadBalancer support later. Docker's port mapping makes ports reachable on the host immediately.

### ConfigMap name collisions
Network names occupy the ConfigMap namespace in the `default` namespace. If a ConfigMap with the same name already exists for a non-network purpose, `network create` will fail with a conflict error.

### Service name collisions
Headless Services for DNS use the container name as the Service name. If a Kubernetes Service with that name already exists (e.g., `kubernetes`), the headless Service creation silently fails and DNS won't work for that container. Network aliases have the same limitation.

### Single namespace
All networks, pods, and services are in the `default` namespace. Cross-namespace networking is not supported.

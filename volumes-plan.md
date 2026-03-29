# Plan: Volumes

## Goal

Implement Docker volume API endpoints and wire volume mounts into pod creation, so that `docker volume create`, `docker run -v`, and compose-style named volumes work.

## Docker API Endpoints

| Endpoint | K8s mapping |
|----------|-------------|
| `GET /volumes` | List PVCs in default namespace |
| `POST /volumes/create` | Create a PVC |
| `GET /volumes/{name}` | Get PVC |
| `DELETE /volumes/{name}` | Delete PVC |
| `POST /volumes/prune` | Delete unbound PVCs |

## Volume types and how they map

Docker has three volume concepts. Here's how each maps to K8s:

### Named volumes (`docker volume create foo`, `docker run -v foo:/data`)

Create a PVC with the cluster's default StorageClass. On GKE Autopilot, this is `standard-rwo` (pd-balanced). The PVC name maps directly to the Docker volume name.

When a container is created with `-v foo:/data`, add a `persistentVolumeClaim` volume to the pod spec and a corresponding `volumeMount` to the container.

### Anonymous volumes (`docker run -v /data`)

Create an `emptyDir` volume on the pod spec. These are ephemeral and disappear when the pod is deleted, which matches Docker's behavior (anonymous volumes are GC'd on `docker rm -v`).

### Bind mounts (`docker run -v /host/path:/container/path`)

Not implementable. The "host" is Cloud Run, not a machine the user controls. Return a clear error: `"bind mounts are not supported; use named volumes instead"`.

## Changes to `containerCreate`

The Docker create request includes volume info in two places:
- `Config.Volumes` -- map of anonymous mount points (keys are container paths, values are empty structs)
- `HostConfig.Binds` -- list of `"source:dest[:options]"` strings
- `HostConfig.Mounts` -- structured mount list (newer API)

Parsing logic:
1. For each entry in `HostConfig.Binds`:
   - If source starts with `/`, reject as bind mount
   - Otherwise, treat source as a named volume: look up or create a PVC, add PVC volume + mount to pod spec
2. For each entry in `HostConfig.Mounts`:
   - Type `volume`: same as named volume above
   - Type `bind`: reject
   - Type `tmpfs`: use `emptyDir` with `medium: Memory`
3. For each key in `Config.Volumes` not already covered by a Bind/Mount: add an `emptyDir`

## Changes to `containerInspect`

Return `Mounts` in the inspect response, derived from the pod's volume mounts.

## PVC details

- Namespace: `default` (same as pods)
- AccessMode: `ReadWriteOnce` (sufficient; pods run one at a time per volume in typical usage)
- Storage request: 1Gi default. Docker volumes don't have a size concept, so we pick a reasonable default. Could be overridable via a label or env var later.
- Labels: `app=badidea` for prune/list filtering
- StorageClassName: omit (use cluster default, which is `standard-rwo` on GKE Autopilot)

## Volume lifecycle

- `docker volume rm` deletes the PVC. If a pod is still using it, K8s will block deletion until the pod is gone (PVC protection finalizer). Return 409 Conflict in that case.
- `docker volume prune` deletes PVCs with `app=badidea` label that are not currently bound to a running pod.
- `docker rm -v` (force-remove volumes with container): delete the pod, then delete any PVCs that were created alongside it. Track this with a pod annotation listing volume names.

## Implementation order

1. Volume CRUD endpoints (create/list/inspect/delete/prune) -- all straightforward PVC operations
2. Wire `HostConfig.Binds` parsing into `containerCreate` -- named volumes become PVC mounts
3. Wire `HostConfig.Mounts` parsing into `containerCreate` -- structured mount API
4. Wire `Config.Volumes` into `containerCreate` -- anonymous emptyDir mounts
5. Update `containerInspect` to return Mounts
6. Tests for each step using the fake clientset

## Limitations

- No bind mounts (by design -- there's no host filesystem to bind)
- PVC resize not supported (would require StorageClass with `allowVolumeExpansion`)
- `ReadWriteMany` not supported (would need a different StorageClass like Filestore)
- Volume driver plugins not supported
- `docker cp` implemented via exec tar in the main container, like `kubectl cp` (see `archive.go`)

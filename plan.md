# Plan: Draw the Rest of the Owl

## Problem

The current code imports `github.com/docker/docker` server internals to implement
the Docker API via Go interfaces. The moby/moby v2 module makes those interfaces
unimplementable externally (`filters.Args` is in an `internal` package). The old
`docker/docker` dep also pulls in a massive transitive dependency tree (buildkit,
libnetwork, containerd daemon code) that causes platform-specific build failures.

## Approach

Replace the docker server routing with a thin HTTP server using:
- `gorilla/mux` for routing
- `github.com/moby/moby/api` types module for JSON request/response types
- Our own HTTP handlers that call the same K8s backend logic

The Docker HTTP API is versioned, stable, and well-documented. We pin to API
version 1.45. The wire format changes far less frequently than Go interfaces.

## What to port (existing functionality)

- `GET /_ping`
- `GET /version`, `GET /info`
- `POST /containers/create`
- `POST /containers/{id}/start`
- `POST /containers/{id}/stop`
- `POST /containers/{id}/kill`
- `DELETE /containers/{id}` (rm)
- `GET /containers/json` (list / `docker ps`)
- `GET /containers/{id}/json` (inspect)
- `GET /containers/{id}/logs`

## What to implement (the rest of the owl)

- `POST /containers/{id}/wait` -- watch pod phase, return exit code
- `POST /containers/{id}/attach` -- hijack connection, stream logs in stdcopy format
- `POST /containers/{id}/exec` -- store exec config, return exec ID
- `POST /exec/{id}/start` -- exec into pod using stored config
- `GET /exec/{id}/json` -- inspect exec
- `POST /containers/prune` -- delete completed pods

## Bug fixes during port

- `ContainerLogs`: `break` inside `select` doesn't exit `for` loop (spins on EOF)
- `ContainerExecStart`: stdin check is inverted (`if options.Stdin != nil { opt.Stdin = false }`)
- `Containers` (list): panics if pod has no container statuses yet

## Non-goals

- `docker build` / buildkit API
- Networks, volumes, images, swarm
- `docker run --privileged`
- Full `docker cp` (archive endpoints)

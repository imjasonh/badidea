# `badidea`

Proof-of-concept running Docker without priviledge, in Kubernetes.

This implements the [Docker TCP API](https://docs.docker.com/engine/api/v1.44/) by creating Pods on a cluster, instead of containers locally.

This is the API that your Docker client uses to talk to your local Docker daemon. It's a JSON REST API that listens on a Unix socket or a TCP port. When run locally, the Daemon creates isolated containers on your host machine. Creating isolated containers requires privilege, which means that unless you take a lot of care to secure your Docker daemon, you're giving anyone who can talk to the Docker API full control of your host machine.

This makes it difficult to run Docker in a multi-tenant environment, like a Kubernetes cluster, where you don't want to give every user full control of the host machine.

This project is a proof-of-concept that shows how you can run Docker in a Kubernetes cluster without giving users full control of host machines. It does this by implementing the same Docker API, but instead of creating containers on the host machine, it creates Pods in the Kubernetes cluster. The Pods that are created are _not privileged_ -- `docker run --privileged` will not be supported -- and can't run Docker themselves, but they can run containers.

If this works (big if), it could be a way to implement autoscaling Docker workloads in unprivileged Kubernetes clusters (like GKE Autopilot), where it looks and acts similar to running Docker locally.

At least, that's the idea.

## Status: lol

The service is stubbed out and doesn't do much of anything yet. The Docker API is huge and I'm not going to implement all of it. I'm going to start with the parts that I need to run a container and see how far I get.

The IaC deploys the API service to Cloud Run and connects to a GKE Autopilot cluster, also set up by IaC.

## Running

```
terraform init
terraform apply
```

This will prompt for GCP project and region, and eventually (if all goes well) will output the URL of the Cloud Run service:

```
Outputs:

url = "https://badidea-nd2blahc7a-uk.a.run.app"
```

You can use this URL to talk to the Docker API. For example:

```
DOCKER_HOST=tcp://badidea-nd2blahc7a-uk.a.run.app:80 docker version
...
EOF
```

So, this doesn't currently work, but that's the idea.

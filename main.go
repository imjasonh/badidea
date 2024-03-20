package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/docker/docker/api/server"
	"github.com/docker/docker/api/server/middleware"
	"github.com/docker/docker/api/server/router/container"
	"github.com/docker/docker/api/server/router/system"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/registry"
	systypes "github.com/docker/docker/api/types/system"
	"github.com/docker/docker/runconfig"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	// use the current context in kubeconfig
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	b := backend{clientset: clientset}
	decoder := runconfig.ContainerDecoder{}

	s := &server.Server{}
	s.UseMiddleware(middleware.NewVersionMiddleware("v1.44", "v1.44", "v1.44"))
	r := s.CreateMux(
		system.NewRouter(b, b, nil, nil),
		container.NewRouter(b, decoder, false /* cgroup2 */),
	)
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("RESPONDING 404 to " + r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})
	if err := http.ListenAndServe(":8080", r); err != nil {
		panic(err)
	}
}

type backend struct {
	system.Backend
	system.ClusterBackend

	clientset *kubernetes.Clientset
}

func (b backend) SystemInfo(context.Context) (*systypes.Info, error) { return &systypes.Info{}, nil }
func (b backend) SystemVersion(context.Context) (types.Version, error) {
	return types.Version{APIVersion: "v1.44"}, nil
}
func (b backend) SystemDiskUsage(ctx context.Context, opts system.DiskUsageOptions) (*types.DiskUsage, error) {
	return &types.DiskUsage{}, nil
}
func (b backend) SubscribeToEvents(since, until time.Time, ef filters.Args) ([]events.Message, chan interface{}) {
	return nil, nil
}
func (b backend) UnsubscribeFromEvents(chan interface{}) {}
func (b backend) AuthenticateToRegistry(ctx context.Context, authConfig *registry.AuthConfig) (string, string, error)

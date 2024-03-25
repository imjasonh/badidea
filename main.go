package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	gke "cloud.google.com/go/container/apiv1"
	gkepb "cloud.google.com/go/container/apiv1/containerpb"
	"github.com/chainguard-dev/clog"
	_ "github.com/chainguard-dev/clog/gcp/init"
	contlog "github.com/containerd/log"
	"github.com/docker/docker/api/server"
	"github.com/docker/docker/api/server/middleware"
	"github.com/docker/docker/api/server/router/container"
	"github.com/docker/docker/api/server/router/debug"
	"github.com/docker/docker/api/server/router/system"
	"github.com/docker/docker/api/types"
	backtypes "github.com/docker/docker/api/types/backend"
	contypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/registry"
	systypes "github.com/docker/docker/api/types/system"
	containerpkg "github.com/docker/docker/container"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/runconfig"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	var env struct {
		ClusterName string `envconfig:"CLUSTER_NAME"`
	}
	if err := envconfig.Process("", &env); err != nil {
		log.Fatalf("failed to process env: %v", err)
	}
	ctx := context.Background()
	log := clog.FromContext(ctx)

	// Find our project and region.
	region, err := metadata.Get("instance/region")
	if err != nil {
		log.Fatalf("failed to get region: %v", err)
	}
	region = region[strings.LastIndex(region, "/")+1:] // chop off the last bit of "projects/149343123456/regions/us-east4"
	project, err := metadata.ProjectID()
	if err != nil {
		log.Fatalf("failed to get project: %v", err)
	}
	log.Infof("project: %s, region: %s, cluster: %s", project, region, env.ClusterName)

	// Find the cluster endpoint and CA cert.
	gkeclient, err := gke.NewClusterManagerClient(ctx)
	if err != nil {
		log.Fatalf("failed to create cluster client: %v", err)
	}
	cluster, err := gkeclient.GetCluster(ctx, &gkepb.GetClusterRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, region, env.ClusterName),
	})
	if err != nil {
		log.Fatalf("failed to create cluster client: %v", err)
	}
	endpoint := cluster.Endpoint
	cacert, err := base64.StdEncoding.DecodeString(cluster.MasterAuth.ClusterCaCertificate)
	if err != nil {
		log.Fatalf("failed to decode ca cert: %v", err)
	}

	// Get SA credentials, and create a K8s client.
	cred, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		log.Fatalf("failed to get credentials: %v", err)
	}
	cfg := &rest.Config{
		Host:            endpoint,
		TLSClientConfig: rest.TLSClientConfig{CAData: cacert},
	}
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return &oauth2.Transport{Source: cred.TokenSource, Base: rt}
	})
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("failed to create clientset: %v", err)
	}
	// Check we can use it.
	if _, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		log.Fatalf("failed to list namespaces: %v", err)
	}

	// Start the Docker API server.
	b := backend{clientset: clientset}
	s := &server.Server{}
	contlog.SetLevel("debug")
	vm, err := middleware.NewVersionMiddleware("1.44", "1.44", "1.44")
	if err != nil {
		log.Fatalf("failed to create version middleware: %v", err)
	}
	s.UseMiddleware(vm)
	r := s.CreateMux(
		system.NewRouter(b, b, nil, func() map[string]bool { return map[string]bool{} }),
		debug.NewRouter(),
		container.NewRouter(b, runconfig.ContainerDecoder{}, false /* cgroup2 */),
	)
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("listen and serve: %v", err)
	}
}

type backend struct {
	system.Backend
	system.ClusterBackend

	clientset *kubernetes.Clientset
}

func (b backend) SystemInfo(context.Context) (*systypes.Info, error) { return &systypes.Info{}, nil }

func (b backend) SystemVersion(context.Context) (types.Version, error) {
	return types.Version{
		Platform:     struct{ Name string }{Name: "badidea"},
		APIVersion:   "1.45",
		Arch:         "amd64",
		Os:           "linux",
		Experimental: true,
		GoVersion:    runtime.Version(),
		GitCommit:    "You're not going to believe this...",
	}, nil
}

func (b backend) SystemDiskUsage(ctx context.Context, opts system.DiskUsageOptions) (*types.DiskUsage, error) {
	return &types.DiskUsage{}, nil
}

func (b backend) SubscribeToEvents(since, until time.Time, ef filters.Args) ([]events.Message, chan interface{}) {
	return nil, nil
}

func (b backend) UnsubscribeFromEvents(chan interface{}) {}

func (b backend) AuthenticateToRegistry(ctx context.Context, authConfig *registry.AuthConfig) (string, string, error) {
	return "", "", errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) waitForStart(ctx context.Context, name string) error {
	// TODO: watch
	for {
		pod, err := b.clientset.CoreV1().Pods("default").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if pod.Status.Phase == corev1.PodRunning {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
}

func (b backend) delete(ctx context.Context, name string) error {
	return b.clientset.CoreV1().Pods("default").Delete(ctx, name, metav1.DeleteOptions{})
}

func (b backend) ContainerCreate(ctx context.Context, config backtypes.ContainerCreateConfig) (contypes.CreateResponse, error) {
	name := config.Name

	env := make([]corev1.EnvVar, 0, len(config.Config.Env))
	for _, e := range config.Config.Env {
		k, v, _ := strings.Cut(e, "=")
		env = append(env, corev1.EnvVar{Name: k, Value: v})
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:       "main",
				Image:      config.Config.Image,
				WorkingDir: config.Config.WorkingDir,
				Command:    config.Config.Entrypoint,
				Args:       config.Config.Cmd,
				Env:        env,
			}},
		},
	}
	if name == "" {
		pod.GenerateName = "badidea-"
	}
	pod, err := b.clientset.CoreV1().Pods("default").Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return contypes.CreateResponse{}, err
	}
	return contypes.CreateResponse{ID: pod.Name}, nil
}

func (b backend) ContainerKill(name, _ string) error {
	return b.delete(context.TODO(), name)
}

func (b backend) ContainerPause(name string) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerRename(oldName, newName string) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerResize(name string, height, width int) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerRestart(ctx context.Context, name string, options contypes.StopOptions) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerRm(name string, config *backtypes.ContainerRmConfig) error {
	return b.delete(context.TODO(), name)
}

func (b backend) ContainerStart(ctx context.Context, name string, checkpoint string, checkpointDir string) error {
	return b.waitForStart(ctx, name)
}

func (b backend) ContainerStop(ctx context.Context, name string, _ contypes.StopOptions) error {
	return b.delete(ctx, name)
}

func (b backend) ContainerUnpause(name string) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerUpdate(name string, hostConfig *contypes.HostConfig) (contypes.ContainerUpdateOKBody, error) {
	return contypes.ContainerUpdateOKBody{}, nil
}

func (b backend) ContainerWait(ctx context.Context, name string, condition containerpkg.WaitCondition) (<-chan containerpkg.StateStatus, error) {
	return nil, errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerAttach(name string, c *backtypes.ContainerAttachConfig) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerChanges(ctx context.Context, name string) ([]archive.Change, error) {
	return nil, nil
}

func (b backend) ContainerInspect(ctx context.Context, name string, size bool, version string) (interface{}, error) {
	return nil, errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerLogs(ctx context.Context, name string, config *contypes.LogsOptions) (<-chan *backtypes.LogMessage, bool, error) {
	ch := make(chan *backtypes.LogMessage) // TODO: buffer?

	go func() {
		defer close(ch)
		logs, err := b.clientset.CoreV1().Pods("default").GetLogs(name, &corev1.PodLogOptions{Container: "main"}).Stream(ctx)
		if err != nil {
			ch <- &backtypes.LogMessage{Err: err}
			return
		}
		defer logs.Close()
		buf := bufio.NewReader(logs)
		for {
			select {
			case <-ctx.Done():
				break
			default:
				line, _, err := buf.ReadLine()
				if err != nil {
					if err != io.EOF {
						ch <- &backtypes.LogMessage{Err: err}
					}
					break
				}
				ch <- &backtypes.LogMessage{Line: line}
			}
		}
	}()

	return ch, false, nil
}

func (b backend) ContainerStats(ctx context.Context, name string, config *backtypes.ContainerStatsConfig) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerTop(name string, psArgs string) (*contypes.ContainerTopOKBody, error) {
	return &contypes.ContainerTopOKBody{}, nil
}

func (b backend) Containers(ctx context.Context, config *contypes.ListOptions) ([]*types.Container, error) {
	return nil, errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerExecCreate(name string, config *types.ExecConfig) (string, error) {
	return "", errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerExecInspect(id string) (*backtypes.ExecInspect, error) {
	return &backtypes.ExecInspect{Running: true}, nil
}

func (b backend) ContainerExecResize(name string, height, width int) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerExecStart(ctx context.Context, name string, options contypes.ExecStartOptions) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ExecExists(name string) (bool, error) { return true, nil }

func (b backend) ContainerArchivePath(name string, path string) (io.ReadCloser, *types.ContainerPathStat, error) {
	return nil, nil, errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerExport(ctx context.Context, name string, out io.Writer) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerExtractToDir(name, path string, copyUIDGID, noOverwriteDirNonDir bool, content io.Reader) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerStatPath(name string, path string) (stat *types.ContainerPathStat, err error) {
	return nil, errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainersPrune(ctx context.Context, pruneFilters filters.Args) (*types.ContainersPruneReport, error) {
	return &types.ContainersPruneReport{}, nil
}

func (b backend) CreateImageFromContainer(ctx context.Context, name string, config *backtypes.CreateImageConfig) (string, error) {
	return "", errdefs.NotImplemented(errors.New("not implemented"))
}

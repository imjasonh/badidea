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
	"github.com/docker/docker/api/server"
	"github.com/docker/docker/api/server/middleware"
	"github.com/docker/docker/api/server/router/container"
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
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"
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
	b := backend{clientset: clientset, restConfig: *cfg}
	s := &server.Server{}
	vm, err := middleware.NewVersionMiddleware("1.45", "1.45", "1.45")
	if err != nil {
		log.Fatalf("failed to create version middleware: %v", err)
	}
	s.UseMiddleware(vm)
	s.UseMiddleware(mw{})
	r := s.CreateMux(
		system.NewRouter(b, b, nil, func() map[string]bool { return map[string]bool{} }),
		container.NewRouter(b, runconfig.ContainerDecoder{}, false /* cgroup2 */),
	)
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("listen and serve: %v", err)
	}
}

// mw is a middleware that checks for the header. It's also useful if you want to log something.
type mw struct{}

func (mw) WrapHandler(handler func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error) func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
		if r.Header.Get("x-badidea") != "true" {
			http.Error(w, "bad idea", http.StatusForbidden)
		}
		return handler(ctx, w, r, vars)
	}
}

type backend struct {
	system.Backend
	system.ClusterBackend

	clientset  *kubernetes.Clientset
	restConfig rest.Config
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
	clog.FromContext(ctx).With("name", name).Info("waiting for pod to start")

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
	clog.FromContext(ctx).With("name", name).Info("deleting pod")
	return b.clientset.CoreV1().Pods("default").Delete(ctx, name, metav1.DeleteOptions{})
}

func (b backend) ContainerCreate(ctx context.Context, config backtypes.ContainerCreateConfig) (contypes.CreateResponse, error) {
	log := clog.FromContext(ctx)

	name := config.Name

	env := make([]corev1.EnvVar, 0, len(config.Config.Env))
	for _, e := range config.Config.Env {
		k, v, _ := strings.Cut(e, "=")
		env = append(env, corev1.EnvVar{Name: k, Value: v})
	}

	cpus := config.HostConfig.Resources.CPUQuota
	if cpus == 0 {
		cpus = 1
	}
	mem := config.HostConfig.Resources.Memory // bytes
	if mem == 0 {
		mem = 2000000000 // 2 GB
	}
	log.Infof("creating pod with requests: cpus=%d, mem=%d", cpus, mem)
	res := corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse(fmt.Sprintf("%d", cpus)),
		corev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%d", mem)),
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:       "main",
				Image:      config.Config.Image,
				WorkingDir: config.Config.WorkingDir,
				Command:    config.Config.Entrypoint,
				Args:       config.Config.Cmd,
				Env:        env,
				Resources:  corev1.ResourceRequirements{Requests: res},
			}},
		},
	}
	if name == "" {
		// The docker client truncates names by default to 12 characters, so make
		// this <7 characters so it doesn't get truncated when K8s appends 5 random chars.
		pod.GenerateName = "bad-"
	}
	pod, err := b.clientset.CoreV1().Pods("default").Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return contypes.CreateResponse{}, k8serr(err)
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
	clog.FromContext(ctx).With("name", name).Info("inspecting pod")

	pod, err := b.clientset.CoreV1().Pods("default").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, k8serr(err)
	}
	env := make([]string, 0, len(pod.Spec.Containers[0].Env))
	for _, e := range pod.Spec.Containers[0].Env {
		env = append(env, fmt.Sprintf("%s=%s", e.Name, e.Value))
	}
	return &types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:    pod.Name,
			Image: pod.Spec.Containers[0].Image,
		},
		Config: &contypes.Config{
			Env:        env,
			Entrypoint: pod.Spec.Containers[0].Command,
			Cmd:        pod.Spec.Containers[0].Args,
			Image:      pod.Spec.Containers[0].Image,
		},
	}, nil
}

func (b backend) ContainerLogs(ctx context.Context, name string, config *contypes.LogsOptions) (<-chan *backtypes.LogMessage, bool, error) {
	log := clog.FromContext(ctx).With("name", name)
	log.Info("getting logs")

	ch := make(chan *backtypes.LogMessage, 1000) // TODO: buffer?

	go func() {
		defer close(ch)
		logs, err := b.clientset.CoreV1().Pods("default").GetLogs(name, &corev1.PodLogOptions{
			Container:  "main",
			Follow:     config.Follow,
			Timestamps: config.Timestamps,
			// TODO: since
		}).Stream(ctx)
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

				log.Infof("log: %s", line)
				ch <- &backtypes.LogMessage{
					Attrs: []backtypes.LogAttr{{
						Key:   "container",
						Value: "main",
					}},
					Timestamp: time.Now(),
					Line:      line,
				}
			}
		}
	}()

	return ch, false, nil
}

func (b backend) ContainerStats(ctx context.Context, name string, config *backtypes.ContainerStatsConfig) error {
	return errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) ContainerTop(name string, psArgs string) (*contypes.ContainerTopOKBody, error) {
	return nil, errdefs.NotImplemented(errors.New("not implemented"))
}

func (b backend) Containers(ctx context.Context, config *contypes.ListOptions) ([]*types.Container, error) {
	clog.FromContext(ctx).Info("listing pods")

	r, err := b.clientset.CoreV1().Pods("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, k8serr(err)
	}
	containers := make([]*types.Container, 0, len(r.Items))
	for _, pod := range r.Items {
		c := &types.Container{
			ID:      pod.Name,
			Image:   pod.Spec.Containers[0].Image,
			ImageID: pod.Status.ContainerStatuses[0].ImageID,
			Command: strings.Join(pod.Spec.Containers[0].Command, " "),
			State:   string(pod.Status.Phase),
			Status:  string(pod.Status.Phase),
		}
		if pod.Status.StartTime != nil {
			c.Created = pod.Status.StartTime.Time.Unix()
		}

		containers = append(containers, c)
	}
	return containers, nil
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
	clog.FromContext(ctx).With("name", name).Info("exec start")

	req := b.clientset.CoreV1().RESTClient().Post().Resource("pods").Name(name).Namespace("default").SubResource("exec")
	opt := &v1.PodExecOptions{
		Container: "main",
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
		TTY:       true,
	}
	if options.Stdin != nil {
		opt.Stdin = false
	}
	req.VersionedParams(opt, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(&b.restConfig, http.MethodPost, req.URL())
	if err != nil {
		return err
	}
	return k8serr(exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  options.Stdin,
		Stdout: options.Stdout,
		Stderr: options.Stderr,
	}))
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

// Translate Kubernetes errors to Docker errors.
func k8serr(err error) error {
	switch {
	case err == nil:
		return nil
	case k8serrors.IsNotFound(err):
		return errdefs.NotFound(err)
	case k8serrors.IsAlreadyExists(err):
		return errdefs.Conflict(err)
	case k8serrors.IsBadRequest(err):
		return errdefs.InvalidParameter(err)
	case k8serrors.IsForbidden(err):
		return errdefs.Forbidden(err)
	case k8serrors.IsUnauthorized(err):
		return errdefs.Unauthorized(err)
	default:
		return errdefs.System(err)
	}
}

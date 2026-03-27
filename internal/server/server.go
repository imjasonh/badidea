package server

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Server implements the Docker Engine API backed by Kubernetes pods.
type Server struct {
	clientset  kubernetes.Interface
	restConfig rest.Config

	mu    sync.Mutex
	execs map[string]*execConfig
}

// New creates a new Server.
func New(clientset kubernetes.Interface, restConfig rest.Config) *Server {
	return &Server{
		clientset:  clientset,
		restConfig: restConfig,
		execs:      make(map[string]*execConfig),
	}
}

// Handler returns an http.Handler with all routes and middleware registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// System
	mux.HandleFunc("GET /_ping", s.ping)
	mux.HandleFunc("HEAD /_ping", s.ping)
	mux.HandleFunc("GET /version", s.version)
	mux.HandleFunc("GET /info", s.info)
	mux.HandleFunc("GET /system/df", s.diskUsage)

	// Containers (order matters: /create and /prune before /{name} wildcard)
	mux.HandleFunc("GET /containers/json", s.containerList)
	mux.HandleFunc("POST /containers/create", s.containerCreate)
	mux.HandleFunc("POST /containers/prune", s.containerPrune)
	mux.HandleFunc("GET /containers/{name}/json", s.containerInspect)
	mux.HandleFunc("GET /containers/{name}/logs", s.containerLogs)
	mux.HandleFunc("POST /containers/{name}/start", s.containerStart)
	mux.HandleFunc("POST /containers/{name}/stop", s.containerStop)
	mux.HandleFunc("POST /containers/{name}/kill", s.containerKill)
	mux.HandleFunc("POST /containers/{name}/restart", s.containerRestart)
	mux.HandleFunc("POST /containers/{name}/wait", s.containerWait)
	mux.HandleFunc("POST /containers/{name}/attach", s.containerAttach)
	mux.HandleFunc("POST /containers/{name}/resize", s.containerResize)
	mux.HandleFunc("POST /containers/{name}/exec", s.execCreate)
	mux.HandleFunc("DELETE /containers/{name}", s.containerRm)

	// Exec
	mux.HandleFunc("POST /exec/{id}/start", s.execStart)
	mux.HandleFunc("GET /exec/{id}/json", s.execInspect)
	mux.HandleFunc("POST /exec/{id}/resize", s.execResize)

	// The Docker client may prefix requests with /v1.45/ etc.
	return s.middleware(stripVersionPrefix(mux))
}

type execConfig struct {
	containerName string
	cmd           []string
	tty           bool
	attachStdin   bool
	attachStdout  bool
	attachStderr  bool
	env           []string
	workingDir    string
	running       bool
}

type errorResponse struct {
	Message string `json:"message"`
}

// stripVersionPrefix removes /v1.45 (or any /vN.N) prefix from the URL path
// so the inner mux sees clean paths.
func stripVersionPrefix(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v") {
			if idx := strings.Index(r.URL.Path[1:], "/"); idx > 0 {
				prefix := r.URL.Path[:idx+1]
				// Only strip if it looks like /v<digits.digits>
				ver := prefix[2:] // strip "/v"
				if len(ver) > 0 && (ver[0] >= '0' && ver[0] <= '9') {
					r2 := r.Clone(r.Context())
					r2.URL.Path = r.URL.Path[idx+1:]
					r2.RequestURI = r2.URL.RequestURI()
					next.ServeHTTP(w, r2)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-badidea") != "true" {
			http.Error(w, "bad idea", http.StatusForbidden)
			return
		}
		w.Header().Set("Api-Version", "1.45")
		w.Header().Set("Server", "badidea")
		w.Header().Set("Ostype", "linux")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	code := http.StatusInternalServerError
	switch {
	case k8serrors.IsNotFound(err):
		code = http.StatusNotFound
	case k8serrors.IsAlreadyExists(err):
		code = http.StatusConflict
	case k8serrors.IsBadRequest(err):
		code = http.StatusBadRequest
	case k8serrors.IsForbidden(err):
		code = http.StatusForbidden
	case k8serrors.IsUnauthorized(err):
		code = http.StatusUnauthorized
	}
	writeJSON(w, code, errorResponse{err.Error()})
}

// writeStdcopyFrame writes a Docker multiplexed stream frame.
// Stream type: 0=stdin, 1=stdout, 2=stderr.
func writeStdcopyFrame(w io.Writer, streamType byte, data []byte) {
	header := [8]byte{}
	header[0] = streamType
	binary.BigEndian.PutUint32(header[4:], uint32(len(data)))
	w.Write(header[:])
	w.Write(data)
}

func podExitCode(pod *corev1.Pod) int {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == "main" && cs.State.Terminated != nil {
			return int(cs.State.Terminated.ExitCode)
		}
	}
	if pod.Status.Phase == corev1.PodSucceeded {
		return 0
	}
	return 1
}

func podToState(pod *corev1.Pod) *container.State {
	state := &container.State{}
	switch pod.Status.Phase {
	case corev1.PodRunning:
		state.Status = "running"
		state.Running = true
	case corev1.PodSucceeded:
		state.Status = "exited"
		state.ExitCode = podExitCode(pod)
	case corev1.PodFailed:
		state.Status = "exited"
		state.ExitCode = podExitCode(pod)
	case corev1.PodPending:
		state.Status = "created"
	default:
		state.Status = container.ContainerState(strings.ToLower(string(pod.Status.Phase)))
	}
	if pod.Status.StartTime != nil {
		state.StartedAt = pod.Status.StartTime.Time.Format(time.RFC3339Nano)
	}
	return state
}

func podToSummary(pod *corev1.Pod) container.Summary {
	c := container.Summary{
		ID:      pod.Name,
		Image:   pod.Spec.Containers[0].Image,
		Command: strings.Join(pod.Spec.Containers[0].Command, " "),
		State:   container.ContainerState(strings.ToLower(string(pod.Status.Phase))),
		Status:  string(pod.Status.Phase),
		Names:   []string{"/" + pod.Name},
	}
	if len(pod.Status.ContainerStatuses) > 0 {
		c.ImageID = pod.Status.ContainerStatuses[0].ImageID
	}
	if pod.Status.StartTime != nil {
		c.Created = pod.Status.StartTime.Time.Unix()
	}
	return c
}

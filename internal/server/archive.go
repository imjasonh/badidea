package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"
)

const (
	// cpHelperImage is the Chainguard image used for ephemeral cp-helper containers.
	// It provides tar, stat, and sh — everything needed for archive operations.
	cpHelperImage = "cgr.dev/chainguard/busybox:latest"

	// mainContainerRoot is the path to the main container's root filesystem
	// as seen from the ephemeral container via the shared PID namespace
	// (provided by targetContainerName). PID 1 is the main container's process.
	mainContainerRoot = "/proc/1/root"

	// cpHelperTimeout is the maximum seconds a cp-helper stays alive.
	// The helper is terminated immediately after use; this timeout is a
	// safety net in case the cleanup signal fails.
	cpHelperTimeout = "300"
)

// containerPathStat holds stat info for archive HEAD/GET responses.
// Matches the Docker API's X-Docker-Container-Path-Stat header format.
type containerPathStat struct {
	Name       string      `json:"name"`
	Size       int64       `json:"size"`
	Mode       os.FileMode `json:"mode"`
	Mtime      time.Time   `json:"mtime"`
	LinkTarget string      `json:"linkTarget"`
}

// --- Archive endpoints ---

// archiveGet handles GET /containers/{name}/archive?path=<path>.
// Returns a tar archive of the resource at the given path.
func (s *Server) archiveGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	archivePath := r.URL.Query().Get("path")
	log := clog.FromContext(ctx).With("name", name, "path", archivePath)

	if archivePath == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"missing required query parameter: path"})
		return
	}
	log.Info("archive get")

	helperName, err := s.ensureCpHelper(ctx, name)
	if err != nil {
		log.Errorf("failed to ensure cp-helper: %v", err)
		writeError(w, err)
		return
	}
	defer s.cleanupCpHelper(name, helperName)

	// Stat the path for the response header.
	stat, err := s.execStat(ctx, name, helperName, archivePath)
	if err != nil {
		log.Errorf("stat failed: %v", err)
		writeJSON(w, http.StatusNotFound, errorResponse{fmt.Sprintf("path %q not found in container: %v", archivePath, err)})
		return
	}

	statJSON, _ := json.Marshal(stat)
	w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(statJSON))
	w.Header().Set("Content-Type", "application/x-tar")
	w.WriteHeader(http.StatusOK)

	// Tar up the path from the main container's filesystem.
	targetPath := path.Join(mainContainerRoot, archivePath)
	parent := path.Dir(targetPath)
	base := path.Base(targetPath)

	if err := s.execInHelper(ctx, name, helperName,
		[]string{"tar", "cf", "-", "-C", parent, base},
		nil, w); err != nil {
		log.Errorf("tar stream error: %v", err)
	}
}

// archivePut handles PUT /containers/{name}/archive?path=<path>.
// Extracts a tar archive from the request body into the container.
func (s *Server) archivePut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	archivePath := r.URL.Query().Get("path")
	log := clog.FromContext(ctx).With("name", name, "path", archivePath)

	if archivePath == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"missing required query parameter: path"})
		return
	}
	log.Info("archive put")

	helperName, err := s.ensureCpHelper(ctx, name)
	if err != nil {
		log.Errorf("failed to ensure cp-helper: %v", err)
		writeError(w, err)
		return
	}
	defer s.cleanupCpHelper(name, helperName)

	// Extract the tar stream into the main container's filesystem.
	targetPath := path.Join(mainContainerRoot, archivePath)

	if err := s.execInHelper(ctx, name, helperName,
		[]string{"tar", "xf", "-", "-C", targetPath},
		r.Body, io.Discard); err != nil {
		log.Errorf("tar extract error: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
}

// archiveHead handles HEAD /containers/{name}/archive?path=<path>.
// Returns stat info about a path via the X-Docker-Container-Path-Stat header.
func (s *Server) archiveHead(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	archivePath := r.URL.Query().Get("path")
	log := clog.FromContext(ctx).With("name", name, "path", archivePath)

	if archivePath == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"missing required query parameter: path"})
		return
	}
	log.Info("archive head")

	helperName, err := s.ensureCpHelper(ctx, name)
	if err != nil {
		log.Errorf("failed to ensure cp-helper: %v", err)
		writeError(w, err)
		return
	}
	defer s.cleanupCpHelper(name, helperName)

	stat, err := s.execStat(ctx, name, helperName, archivePath)
	if err != nil {
		log.Errorf("stat failed: %v", err)
		writeJSON(w, http.StatusNotFound, errorResponse{fmt.Sprintf("path %q not found in container: %v", archivePath, err)})
		return
	}

	statJSON, _ := json.Marshal(stat)
	w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(statJSON))
	w.WriteHeader(http.StatusOK)
}

// --- Ephemeral container helpers ---

// ensureCpHelper ensures a cp-helper ephemeral container is running on the pod.
// If one already exists and is running, it's reused. Otherwise a new one is created.
// The helper writes its PID to /tmp/.cp-pid so cleanupCpHelper can terminate it.
func (s *Server) ensureCpHelper(ctx context.Context, podName string) (string, error) {
	pod, err := s.clientset.CoreV1().Pods("default").Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	// Reuse an already-running helper if one exists.
	for _, ec := range pod.Spec.EphemeralContainers {
		if !strings.HasPrefix(ec.Name, "cp-") {
			continue
		}
		for _, cs := range pod.Status.EphemeralContainerStatuses {
			if cs.Name == ec.Name && cs.State.Running != nil {
				return ec.Name, nil
			}
		}
	}

	// Create a new helper. The command writes its PID to a file then
	// replaces the shell with sleep so the PID stays the same.
	// The helper must run as root with SYS_PTRACE to access /proc/1/root.
	helperName := "cp-" + uuid.New().String()[:8]
	rootUser := int64(0)
	ec := corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:    helperName,
			Image:   cpHelperImage,
			Command: []string{"sh", "-c", "echo $$ > /tmp/.cp-pid && exec sleep " + cpHelperTimeout},
			SecurityContext: &corev1.SecurityContext{
				RunAsUser: &rootUser,
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"SYS_PTRACE"},
				},
			},
		},
		TargetContainerName: "main",
	}

	pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, ec)
	if _, err := s.clientset.CoreV1().Pods("default").UpdateEphemeralContainers(
		ctx, podName, pod, metav1.UpdateOptions{}); err != nil {
		return "", fmt.Errorf("failed to add cp-helper: %w", err)
	}

	if err := s.waitForEphemeralRunning(ctx, podName, helperName); err != nil {
		return "", err
	}

	return helperName, nil
}

// cleanupCpHelper terminates the cp-helper by killing its sleep process
// using the PID saved at startup. This is best-effort; the helper will
// auto-terminate after cpHelperTimeout seconds regardless.
func (s *Server) cleanupCpHelper(podName, helperName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = s.execInHelper(ctx, podName, helperName,
		[]string{"sh", "-c", "kill $(cat /tmp/.cp-pid) 2>/dev/null; true"},
		nil, io.Discard)
}

// waitForEphemeralRunning watches the pod until the named ephemeral container is running.
func (s *Server) waitForEphemeralRunning(ctx context.Context, podName, containerName string) error {
	pod, err := s.clientset.CoreV1().Pods("default").Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	for _, cs := range pod.Status.EphemeralContainerStatuses {
		if cs.Name == containerName && cs.State.Running != nil {
			return nil
		}
	}

	watcher, err := s.clientset.CoreV1().Pods("default").Watch(ctx, metav1.ListOptions{
		FieldSelector:   "metadata.name=" + podName,
		ResourceVersion: pod.ResourceVersion,
	})
	if err != nil {
		return err
	}
	defer watcher.Stop()

	for event := range watcher.ResultChan() {
		pod, ok := event.Object.(*corev1.Pod)
		if !ok {
			continue
		}
		for _, cs := range pod.Status.EphemeralContainerStatuses {
			if cs.Name == containerName {
				if cs.State.Running != nil {
					return nil
				}
				if cs.State.Terminated != nil {
					return fmt.Errorf("ephemeral container %s terminated: %s",
						containerName, cs.State.Terminated.Reason)
				}
			}
		}
	}
	return fmt.Errorf("watch closed before ephemeral container %s started", containerName)
}

// --- Exec helpers ---

// execInHelper runs a command in the cp-helper container via exec.
// If stdin is non-nil it is piped to the command. stdout receives the
// command's standard output (pass io.Discard if unneeded).
func (s *Server) execInHelper(ctx context.Context, podName, helperName string, cmd []string, stdin io.Reader, stdout io.Writer) error {
	execOpt := &corev1.PodExecOptions{
		Container: helperName,
		Command:   cmd,
		Stdin:     stdin != nil,
		Stdout:    true,
		Stderr:    true,
	}

	req := s.clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(podName).Namespace("default").
		SubResource("exec")
	req.VersionedParams(execOpt, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(&s.restConfig, http.MethodPost, req.URL())
	if err != nil {
		return err
	}

	var stderrBuf bytes.Buffer
	opts := remotecommand.StreamOptions{
		Stderr: &stderrBuf,
	}
	if stdin != nil {
		opts.Stdin = stdin
	}
	if stdout != nil {
		opts.Stdout = stdout
	} else {
		opts.Stdout = io.Discard
	}

	if err := executor.StreamWithContext(ctx, opts); err != nil {
		if stderrBuf.Len() > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderrBuf.String()))
		}
		return err
	}
	return nil
}

// execStat runs stat in the helper container and returns path metadata.
func (s *Server) execStat(ctx context.Context, podName, helperName, archivePath string) (*containerPathStat, error) {
	targetPath := path.Join(mainContainerRoot, archivePath)

	// BusyBox stat format: %n=name, %s=size, %f=mode(hex), %Y=mtime(epoch)
	var stdout bytes.Buffer
	if err := s.execInHelper(ctx, podName, helperName,
		[]string{"stat", "-c", "%n\n%s\n%f\n%Y", targetPath},
		nil, &stdout); err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) < 4 {
		return nil, fmt.Errorf("unexpected stat output: %s", stdout.String())
	}

	size, _ := strconv.ParseInt(lines[1], 10, 64)
	modeHex, _ := strconv.ParseUint(lines[2], 16, 32)
	mtimeEpoch, _ := strconv.ParseInt(lines[3], 10, 64)

	return &containerPathStat{
		Name:  path.Base(archivePath),
		Size:  size,
		Mode:  os.FileMode(modeHex),
		Mtime: time.Unix(mtimeEpoch, 0),
	}, nil
}

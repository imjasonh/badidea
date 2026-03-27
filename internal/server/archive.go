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
	// It contains tar and basic utilities needed for archive operations.
	cpHelperImage = "cgr.dev/chainguard/busybox:latest"

	// mainContainerRoot is the path to the main container's root filesystem
	// as seen from the ephemeral container via shared PID namespace.
	mainContainerRoot = "/proc/1/root"
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

// archiveGet handles GET /containers/{name}/archive?path=<path>
// Returns a tar archive of the file or directory at the given path.
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

	// Ensure the ephemeral helper container exists and is running.
	helperName, err := s.ensureCpHelper(ctx, name)
	if err != nil {
		log.Errorf("failed to ensure cp-helper: %v", err)
		writeError(w, err)
		return
	}

	// First, stat the path to get metadata for the header.
	stat, err := s.statInHelper(ctx, name, helperName, archivePath)
	if err != nil {
		log.Errorf("stat failed: %v", err)
		writeJSON(w, http.StatusNotFound, errorResponse{fmt.Sprintf("path %q not found in container: %v", archivePath, err)})
		return
	}

	statJSON, _ := json.Marshal(stat)
	statEncoded := base64.StdEncoding.EncodeToString(statJSON)

	w.Header().Set("X-Docker-Container-Path-Stat", statEncoded)
	w.Header().Set("Content-Type", "application/x-tar")
	w.WriteHeader(http.StatusOK)

	// Tar up the path from the main container's filesystem.
	targetPath := path.Join(mainContainerRoot, archivePath)
	parent := path.Dir(targetPath)
	base := path.Base(targetPath)

	execOpt := &corev1.PodExecOptions{
		Container: helperName,
		Command:   []string{"tar", "cf", "-", "-C", parent, base},
		Stdout:    true,
		Stderr:    true,
	}

	req := s.clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(name).Namespace("default").
		SubResource("exec")
	req.VersionedParams(execOpt, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(&s.restConfig, http.MethodPost, req.URL())
	if err != nil {
		log.Errorf("exec error: %v", err)
		return
	}

	if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: w,
		Stderr: io.Discard,
	}); err != nil {
		log.Errorf("tar stream error: %v", err)
	}
}

// archivePut handles PUT /containers/{name}/archive?path=<path>
// Extracts a tar archive from the request body into the container at the given path.
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

	// Extract the tar stream into the main container's filesystem.
	targetPath := path.Join(mainContainerRoot, archivePath)

	execOpt := &corev1.PodExecOptions{
		Container: helperName,
		Command:   []string{"tar", "xf", "-", "-C", targetPath},
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
	}

	req := s.clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(name).Namespace("default").
		SubResource("exec")
	req.VersionedParams(execOpt, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(&s.restConfig, http.MethodPost, req.URL())
	if err != nil {
		log.Errorf("exec error: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{err.Error()})
		return
	}

	if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  r.Body,
		Stdout: io.Discard,
		Stderr: io.Discard,
	}); err != nil {
		log.Errorf("tar extract error: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
}

// archiveHead handles HEAD /containers/{name}/archive?path=<path>
// Returns stat info about a path in the container via the X-Docker-Container-Path-Stat header.
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

	stat, err := s.statInHelper(ctx, name, helperName, archivePath)
	if err != nil {
		log.Errorf("stat failed: %v", err)
		writeJSON(w, http.StatusNotFound, errorResponse{fmt.Sprintf("path %q not found in container: %v", archivePath, err)})
		return
	}

	statJSON, _ := json.Marshal(stat)
	statEncoded := base64.StdEncoding.EncodeToString(statJSON)
	w.Header().Set("X-Docker-Container-Path-Stat", statEncoded)
	w.WriteHeader(http.StatusOK)
}

// ensureCpHelper adds an ephemeral cp-helper container to the pod if one
// isn't already running, then waits for it to be ready. Returns the name
// of the running helper container.
func (s *Server) ensureCpHelper(ctx context.Context, podName string) (string, error) {
	pod, err := s.clientset.CoreV1().Pods("default").Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	// Check if a cp-helper is already running.
	for _, ec := range pod.Spec.EphemeralContainers {
		if strings.HasPrefix(ec.Name, "cp-") {
			// Check if it's running.
			for _, cs := range pod.Status.EphemeralContainerStatuses {
				if cs.Name == ec.Name && cs.State.Running != nil {
					return ec.Name, nil
				}
			}
		}
	}

	// Add a new ephemeral container.
	helperName := "cp-" + uuid.New().String()[:8]
	ec := corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:    helperName,
			Image:   cpHelperImage,
			Command: []string{"sleep", "3600"},
		},
		TargetContainerName: "main",
	}

	pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, ec)

	_, err = s.clientset.CoreV1().Pods("default").UpdateEphemeralContainers(ctx, podName, pod, metav1.UpdateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to add ephemeral container: %w", err)
	}

	// Wait for the ephemeral container to be running.
	if err := s.waitForEphemeralContainer(ctx, podName, helperName); err != nil {
		return "", err
	}

	return helperName, nil
}

// waitForEphemeralContainer watches the pod until the named ephemeral container is running.
func (s *Server) waitForEphemeralContainer(ctx context.Context, podName, containerName string) error {
	// First check current state.
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
					return fmt.Errorf("ephemeral container %s terminated: %s", containerName, cs.State.Terminated.Reason)
				}
			}
		}
	}
	return fmt.Errorf("watch closed before ephemeral container %s started", containerName)
}

// statInHelper runs stat in the cp-helper container and returns path metadata.
func (s *Server) statInHelper(ctx context.Context, podName, helperName, archivePath string) (*containerPathStat, error) {
	targetPath := path.Join(mainContainerRoot, archivePath)

	// Use stat to get file info. BusyBox stat output format:
	// %n=name, %s=size, %f=mode(hex), %Y=mtime(epoch), %N=symlink target
	execOpt := &corev1.PodExecOptions{
		Container: helperName,
		Command:   []string{"stat", "-c", "%n\n%s\n%f\n%Y", targetPath},
		Stdout:    true,
		Stderr:    true,
	}

	req := s.clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(podName).Namespace("default").
		SubResource("exec")
	req.VersionedParams(execOpt, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(&s.restConfig, http.MethodPost, req.URL())
	if err != nil {
		return nil, err
	}

	var stdout, stderr bytes.Buffer
	if err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	}); err != nil {
		return nil, fmt.Errorf("stat failed: %s: %w", stderr.String(), err)
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

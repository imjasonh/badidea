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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"
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
//
// These implement the Docker archive API by exec-ing tar/stat directly in
// the main container, the same approach kubectl cp uses. This requires the
// container image to include tar (busybox, alpine, most distros do).
// No ephemeral containers or elevated privileges are needed, so this works
// on restrictive clusters like GKE Autopilot.

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

	if _, err := s.clientset.CoreV1().Pods("default").Get(ctx, name, metav1.GetOptions{}); err != nil {
		writeError(w, err)
		return
	}

	// Stat the path for the response header.
	stat, err := s.execStat(ctx, name, archivePath)
	if err != nil {
		log.Errorf("stat failed: %v", err)
		writeJSON(w, http.StatusNotFound, errorResponse{fmt.Sprintf("path %q not found in container: %v", archivePath, err)})
		return
	}

	statJSON, _ := json.Marshal(stat)
	w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(statJSON))
	w.Header().Set("Content-Type", "application/x-tar")
	w.WriteHeader(http.StatusOK)

	// Tar up the path inside the container.
	parent := path.Dir(archivePath)
	base := path.Base(archivePath)

	if err := s.execInContainer(ctx, name,
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

	if _, err := s.clientset.CoreV1().Pods("default").Get(ctx, name, metav1.GetOptions{}); err != nil {
		writeError(w, err)
		return
	}

	if err := s.execInContainer(ctx, name,
		[]string{"tar", "xf", "-", "-C", archivePath},
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

	if _, err := s.clientset.CoreV1().Pods("default").Get(ctx, name, metav1.GetOptions{}); err != nil {
		writeError(w, err)
		return
	}

	stat, err := s.execStat(ctx, name, archivePath)
	if err != nil {
		log.Errorf("stat failed: %v", err)
		writeJSON(w, http.StatusNotFound, errorResponse{fmt.Sprintf("path %q not found in container: %v", archivePath, err)})
		return
	}

	statJSON, _ := json.Marshal(stat)
	w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(statJSON))
	w.WriteHeader(http.StatusOK)
}

// --- Exec helpers ---

// execInContainer runs a command in the main container via Kubernetes exec.
// If stdin is non-nil it is piped to the command. stdout receives the
// command's standard output (pass io.Discard if unneeded).
func (s *Server) execInContainer(ctx context.Context, podName string, cmd []string, stdin io.Reader, stdout io.Writer) error {
	execOpt := &corev1.PodExecOptions{
		Container: "main",
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
		Stdout: stdout,
		Stderr: &stderrBuf,
	}
	if stdin != nil {
		opts.Stdin = stdin
	}
	if stdout == nil {
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

// execStat runs stat in the container and returns path metadata.
func (s *Server) execStat(ctx context.Context, podName, archivePath string) (*containerPathStat, error) {
	// BusyBox stat format: %n=name, %s=size, %f=mode(hex), %Y=mtime(epoch)
	var stdout bytes.Buffer
	if err := s.execInContainer(ctx, podName,
		[]string{"stat", "-c", "%n\n%s\n%f\n%Y", archivePath},
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

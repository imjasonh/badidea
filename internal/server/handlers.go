package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/system"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"
)

// --- System endpoints ---

func (s *Server) ping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, system.VersionResponse{
		Platform:     system.PlatformInfo{Name: "badidea"},
		APIVersion:   "1.45",
		Arch:         "amd64",
		Os:           "linux",
		GoVersion:    runtime.Version(),
		GitCommit:    "You're not going to believe this...",
		Experimental: true,
	})
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, system.Info{})
}

func (s *Server) diskUsage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, struct{}{})
}

// --- Container lifecycle ---

func (s *Server) containerCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := clog.FromContext(ctx)

	name := r.URL.Query().Get("name")

	var req container.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	if req.Config == nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{"missing container config"})
		return
	}

	env := make([]corev1.EnvVar, 0, len(req.Config.Env))
	for _, e := range req.Config.Env {
		k, v, _ := strings.Cut(e, "=")
		env = append(env, corev1.EnvVar{Name: k, Value: v})
	}

	cpus := int64(1)
	mem := int64(2000000000) // 2 GB
	if req.HostConfig != nil {
		if req.HostConfig.Resources.CPUQuota > 0 {
			cpus = req.HostConfig.Resources.CPUQuota
		}
		if req.HostConfig.Resources.Memory > 0 {
			mem = req.HostConfig.Resources.Memory
		}
	}
	log.Infof("creating pod with requests: cpus=%d, mem=%d", cpus, mem)
	res := corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse(fmt.Sprintf("%d", cpus)),
		corev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%d", mem)),
	}

	// Parse volume mounts from the request.
	var podVolumes []corev1.Volume
	var containerMounts []corev1.VolumeMount
	coveredPaths := map[string]bool{}

	if req.HostConfig != nil {
		// Parse Binds: "source:dest[:options]"
		if len(req.HostConfig.Binds) > 0 {
			vols, mnts, err := parseBinds(req.HostConfig.Binds)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
				return
			}
			podVolumes = append(podVolumes, vols...)
			containerMounts = append(containerMounts, mnts...)
			for _, m := range mnts {
				coveredPaths[m.MountPath] = true
			}
		}

		// Parse Mounts (structured mount API).
		if len(req.HostConfig.Mounts) > 0 {
			vols, vmounts, err := parseDockerMounts(req.HostConfig.Mounts)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
				return
			}
			podVolumes = append(podVolumes, vols...)
			containerMounts = append(containerMounts, vmounts...)
			for _, m := range vmounts {
				coveredPaths[m.MountPath] = true
			}
		}
	}

	// Parse Config.Volumes (anonymous volumes).
	if len(req.Config.Volumes) > 0 {
		vols, mnts := parseAnonymousVolumes(req.Config.Volumes, coveredPaths)
		podVolumes = append(podVolumes, vols...)
		containerMounts = append(containerMounts, mnts...)
	}

	// Build labels for network membership.
	podLabels := map[string]string{}
	if name != "" {
		podLabels["badidea.dev/pod-name"] = name
	}

	// Collect network names and aliases from NetworkingConfig.
	type netInfo struct {
		aliases []string
	}
	networkInfos := map[string]netInfo{}
	if req.NetworkingConfig != nil {
		for netName, epConfig := range req.NetworkingConfig.EndpointsConfig {
			if netName == "host" {
				writeJSON(w, http.StatusBadRequest, errorResponse{"host networking is not supported"})
				return
			}
			podLabels[networkLabelPrefix+netName] = "true"
			info := netInfo{}
			if epConfig != nil {
				info.aliases = epConfig.Aliases
			}
			networkInfos[netName] = info
		}
	}

	// If no network specified, pod is on bridge by default (implicit).

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: podLabels,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Volumes:       podVolumes,
			Containers: []corev1.Container{{
				Name:         "main",
				Image:        req.Config.Image,
				WorkingDir:   req.Config.WorkingDir,
				Command:      req.Config.Entrypoint,
				Args:         req.Config.Cmd,
				Env:          env,
				Resources:    corev1.ResourceRequirements{Requests: res},
				VolumeMounts: containerMounts,
			}},
		},
	}
	if name == "" {
		pod.GenerateName = "bad-"
	}
	pod, err := s.clientset.CoreV1().Pods("default").Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	// Create headless services for DNS resolution when a pod is on a named network.
	if len(networkInfos) > 0 && pod.Name != "" {
		if err := s.ensureHeadlessService(ctx, pod.Name, pod.Name); err != nil {
			log.Warnf("failed to create headless service for pod: %v", err)
		}
		// Create alias services.
		for _, info := range networkInfos {
			for _, alias := range info.aliases {
				if err := s.ensureHeadlessService(ctx, alias, pod.Name); err != nil {
					log.Warnf("failed to create alias service %s: %v", alias, err)
				}
			}
		}
	}

	// Create port mapping services if HostConfig has PortBindings.
	if req.HostConfig != nil && len(req.HostConfig.PortBindings) > 0 && pod.Name != "" {
		var mappings []portMapping
		for port, bindings := range req.HostConfig.PortBindings {
			cPort := int(port.Num())
			proto := strings.ToUpper(string(port.Proto()))
			for _, b := range bindings {
				hostPort := 0
				fmt.Sscanf(b.HostPort, "%d", &hostPort)
				if hostPort == 0 {
					hostPort = cPort
				}
				mappings = append(mappings, portMapping{
					hostPort:      hostPort,
					containerPort: cPort,
					protocol:      proto,
				})
			}
		}
		if err := s.createPortMappingService(ctx, pod.Name, mappings); err != nil {
			log.Warnf("failed to create port mapping service: %v", err)
		}
	}

	writeJSON(w, http.StatusCreated, container.CreateResponse{ID: pod.Name})
}

func (s *Server) containerStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	log := clog.FromContext(ctx).With("name", name)
	log.Info("waiting for pod to start")

	if err := s.waitForRunning(ctx, name); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) containerStop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	s.cleanupPodServices(ctx, name)
	if err := s.deletePod(ctx, name); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) containerKill(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	clog.FromContext(ctx).With("name", name).Info("killing pod")
	s.cleanupPodServices(ctx, name)
	zero := int64(0)
	if err := s.clientset.CoreV1().Pods("default").Delete(ctx, name, metav1.DeleteOptions{
		GracePeriodSeconds: &zero,
	}); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) containerRestart(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, errorResponse{"not implemented"})
}

func (s *Server) containerRm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	s.cleanupPodServices(ctx, name)
	if err := s.deletePod(ctx, name); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) containerResize(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// --- Container queries ---

func (s *Server) containerList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clog.FromContext(ctx).Info("listing pods")

	pods, err := s.clientset.CoreV1().Pods("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		writeError(w, err)
		return
	}
	containers := make([]container.Summary, 0, len(pods.Items))
	for _, pod := range pods.Items {
		containers = append(containers, podToSummary(&pod))
	}
	writeJSON(w, http.StatusOK, containers)
}

func (s *Server) containerInspect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	clog.FromContext(ctx).With("name", name).Info("inspecting pod")

	pod, err := s.clientset.CoreV1().Pods("default").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	env := make([]string, 0, len(pod.Spec.Containers[0].Env))
	for _, e := range pod.Spec.Containers[0].Env {
		env = append(env, fmt.Sprintf("%s=%s", e.Name, e.Value))
	}

	// Build Mounts from pod volumes.
	var mounts []container.MountPoint
	for _, vm := range pod.Spec.Containers[0].VolumeMounts {
		mp := container.MountPoint{
			Destination: vm.MountPath,
			RW:          !vm.ReadOnly,
		}
		// Find the corresponding pod volume to determine type/source.
		for _, v := range pod.Spec.Volumes {
			if v.Name == vm.Name {
				if v.PersistentVolumeClaim != nil {
					mp.Type = mount.TypeVolume
					mp.Name = v.PersistentVolumeClaim.ClaimName
					mp.Source = v.PersistentVolumeClaim.ClaimName
					mp.Driver = "local"
				} else if v.EmptyDir != nil {
					mp.Type = mount.TypeVolume
					mp.Name = v.Name
					mp.Source = ""
				}
				break
			}
		}
		mounts = append(mounts, mp)
	}

	writeJSON(w, http.StatusOK, container.InspectResponse{
		ID:     pod.Name,
		Image:  pod.Spec.Containers[0].Image,
		Name:   "/" + pod.Name,
		State:  podToState(pod),
		Mounts: mounts,
		Config: &container.Config{
			Env:        env,
			Entrypoint: pod.Spec.Containers[0].Command,
			Cmd:        pod.Spec.Containers[0].Args,
			Image:      pod.Spec.Containers[0].Image,
		},
	})
}

func (s *Server) containerLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	log := clog.FromContext(ctx).With("name", name)
	log.Info("getting logs")

	q := r.URL.Query()
	follow := q.Get("follow") == "1" || q.Get("follow") == "true"
	timestamps := q.Get("timestamps") == "1" || q.Get("timestamps") == "true"

	opts := &corev1.PodLogOptions{
		Container:  "main",
		Follow:     follow,
		Timestamps: timestamps,
	}

	stream, err := s.clientset.CoreV1().Pods("default").GetLogs(name, opts).Stream(ctx)
	if err != nil {
		writeError(w, err)
		return
	}
	defer stream.Close()

	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
	w.WriteHeader(http.StatusOK)

	buf := bufio.NewReader(stream)
	for {
		line, err := buf.ReadBytes('\n')
		if len(line) > 0 {
			writeStdcopyFrame(w, 1, line) // stdout
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// --- Container wait ---

func (s *Server) containerWait(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	log := clog.FromContext(ctx).With("name", name)
	log.Info("waiting for pod to finish")

	exitCode, err := s.waitForDone(ctx, name)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, container.WaitResponse{StatusCode: int64(exitCode)})
}

// --- Container attach ---

func (s *Server) containerAttach(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	log := clog.FromContext(ctx).With("name", name)
	log.Info("attaching to pod")

	q := r.URL.Query()
	wantStream := q.Get("stream") == "1" || q.Get("stream") == "true"
	wantLogs := q.Get("logs") == "1" || q.Get("logs") == "true"

	if !wantStream && !wantLogs {
		w.WriteHeader(http.StatusOK)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"server does not support hijacking"})
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Errorf("hijack failed: %v", err)
		return
	}
	defer conn.Close()

	bufrw.WriteString("HTTP/1.1 101 UPGRADED\r\n")
	bufrw.WriteString("Content-Type: application/vnd.docker.raw-stream\r\n")
	bufrw.WriteString("Connection: Upgrade\r\n")
	bufrw.WriteString("Upgrade: tcp\r\n")
	bufrw.WriteString("\r\n")
	bufrw.Flush()

	// Wait for the pod to be running before streaming logs.
	// docker run calls attach before start, so the pod may still be pending.
	if err := s.waitForRunning(ctx, name); err != nil {
		writeStdcopyFrame(bufrw, 2, []byte(fmt.Sprintf("error waiting for container: %v\n", err)))
		bufrw.Flush()
		return
	}

	opts := &corev1.PodLogOptions{
		Container: "main",
		Follow:    wantStream,
	}

	stream, err := s.clientset.CoreV1().Pods("default").GetLogs(name, opts).Stream(ctx)
	if err != nil {
		writeStdcopyFrame(bufrw, 2, []byte(fmt.Sprintf("error getting logs: %v\n", err)))
		bufrw.Flush()
		return
	}
	defer stream.Close()

	buf := bufio.NewReader(stream)
	for {
		line, err := buf.ReadBytes('\n')
		if len(line) > 0 {
			writeStdcopyFrame(bufrw, 1, line) // stdout
			bufrw.Flush()
		}
		if err != nil {
			return
		}
	}
}

// --- Exec ---

func (s *Server) execCreate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var req container.ExecCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}

	id := uuid.New().String()[:12]

	s.mu.Lock()
	s.execs[id] = &execConfig{
		containerName: name,
		cmd:           req.Cmd,
		tty:           req.Tty,
		attachStdin:   req.AttachStdin,
		attachStdout:  req.AttachStdout,
		attachStderr:  req.AttachStderr,
		env:           req.Env,
		workingDir:    req.WorkingDir,
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusCreated, struct {
		ID string `json:"Id"`
	}{ID: id})
}

func (s *Server) execStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	s.mu.Lock()
	ec, ok := s.execs[id]
	if ok {
		ec.running = true
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{"exec not found"})
		return
	}

	log := clog.FromContext(ctx).With("exec", id, "container", ec.containerName)
	log.Info("exec start")

	hj, ok := w.(http.Hijacker)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errorResponse{"server does not support hijacking"})
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Errorf("hijack failed: %v", err)
		return
	}
	defer conn.Close()

	bufrw.WriteString("HTTP/1.1 101 UPGRADED\r\n")
	bufrw.WriteString("Content-Type: application/vnd.docker.raw-stream\r\n")
	bufrw.WriteString("Connection: Upgrade\r\n")
	bufrw.WriteString("Upgrade: tcp\r\n")
	bufrw.WriteString("\r\n")
	bufrw.Flush()

	execOpt := &corev1.PodExecOptions{
		Container: "main",
		Command:   ec.cmd,
		Stdin:     ec.attachStdin,
		Stdout:    ec.attachStdout,
		Stderr:    ec.attachStderr,
		TTY:       ec.tty,
	}

	req := s.clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(ec.containerName).Namespace("default").
		SubResource("exec")
	req.VersionedParams(execOpt, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(&s.restConfig, http.MethodPost, req.URL())
	if err != nil {
		writeStdcopyFrame(bufrw, 2, []byte(fmt.Sprintf("exec error: %v\n", err)))
		bufrw.Flush()
		return
	}

	streamOpts := remotecommand.StreamOptions{
		Stdout: bufrw,
		Stderr: bufrw,
	}
	if ec.attachStdin {
		streamOpts.Stdin = conn
	}
	if err := exec.StreamWithContext(ctx, streamOpts); err != nil {
		writeStdcopyFrame(bufrw, 2, []byte(fmt.Sprintf("exec stream error: %v\n", err)))
	}
	bufrw.Flush()

	s.mu.Lock()
	delete(s.execs, id)
	s.mu.Unlock()
}

func (s *Server) execInspect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.mu.Lock()
	ec, ok := s.execs[id]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{"exec not found"})
		return
	}

	writeJSON(w, http.StatusOK, container.ExecInspectResponse{
		ID:          id,
		Running:     ec.running,
		ContainerID: ec.containerName,
	})
}

func (s *Server) execResize(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// --- Container prune ---

func (s *Server) containerPrune(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clog.FromContext(ctx).Info("pruning completed pods")

	pods, err := s.clientset.CoreV1().Pods("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	var deleted []string
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			if err := s.deletePod(ctx, pod.Name); err == nil {
				deleted = append(deleted, pod.Name)
			}
		}
	}

	writeJSON(w, http.StatusOK, container.PruneReport{
		ContainersDeleted: deleted,
	})
}

// --- K8s helpers ---

func (s *Server) deletePod(ctx context.Context, name string) error {
	clog.FromContext(ctx).With("name", name).Info("deleting pod")
	return s.clientset.CoreV1().Pods("default").Delete(ctx, name, metav1.DeleteOptions{})
}

func (s *Server) waitForRunning(ctx context.Context, name string) error {
	pod, err := s.clientset.CoreV1().Pods("default").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return nil
	}

	watcher, err := s.clientset.CoreV1().Pods("default").Watch(ctx, metav1.ListOptions{
		FieldSelector:   "metadata.name=" + name,
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
		switch pod.Status.Phase {
		case corev1.PodRunning, corev1.PodSucceeded, corev1.PodFailed:
			return nil
		}
	}
	return fmt.Errorf("watch closed before pod %s started", name)
}

func (s *Server) waitForDone(ctx context.Context, name string) (int, error) {
	pod, err := s.clientset.CoreV1().Pods("default").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return -1, err
	}
	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return podExitCode(pod), nil
	}

	watcher, err := s.clientset.CoreV1().Pods("default").Watch(ctx, metav1.ListOptions{
		FieldSelector:   "metadata.name=" + name,
		ResourceVersion: pod.ResourceVersion,
	})
	if err != nil {
		return -1, err
	}
	defer watcher.Stop()

	for event := range watcher.ResultChan() {
		if event.Type == watch.Deleted {
			return 0, nil
		}
		pod, ok := event.Object.(*corev1.Pod)
		if !ok {
			continue
		}
		switch pod.Status.Phase {
		case corev1.PodSucceeded, corev1.PodFailed:
			return podExitCode(pod), nil
		}
	}
	return -1, fmt.Errorf("watch closed before pod %s finished", name)
}

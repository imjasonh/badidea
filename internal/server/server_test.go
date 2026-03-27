package server

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/system"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func newTestServer(objects ...corev1.Pod) *httptest.Server {
	var objs []corev1.Pod
	objs = append(objs, objects...)

	// Convert to runtime.Object slice for the fake clientset.
	var runtimeObjs []interface{ GetObjectKind() interface{ GroupVersionKind() interface{} } }
	_ = runtimeObjs // unused, we'll pass pods differently

	clientset := fake.NewSimpleClientset()
	for i := range objs {
		clientset.Tracker().Add(&objs[i])
	}

	s := New(clientset, rest.Config{})
	return httptest.NewServer(s.Handler())
}

func request(t *testing.T, ts *httptest.Server, method, path string, body string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-badidea", "true")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decodeJSON[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestMiddlewareForbidsWithoutHeader(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	s := New(clientset, rest.Config{})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/_ping")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestPing(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "GET", "/_ping", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "OK" {
		t.Errorf("got %q, want %q", body, "OK")
	}
}

func TestVersion(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "GET", "/version", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	v := decodeJSON[system.VersionResponse](t, resp)
	if v.APIVersion != "1.45" {
		t.Errorf("got API version %q, want %q", v.APIVersion, "1.45")
	}
	if v.Platform.Name != "badidea" {
		t.Errorf("got platform %q, want %q", v.Platform.Name, "badidea")
	}
}

func TestVersionWithPrefix(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "GET", "/v1.45/version", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	v := decodeJSON[system.VersionResponse](t, resp)
	if v.APIVersion != "1.45" {
		t.Errorf("got API version %q, want %q", v.APIVersion, "1.45")
	}
}

func TestContainerCreateAndInspect(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=test-container",
		`{"Image": "hello-world", "Cmd": ["echo", "hi"], "Env": ["FOO=bar"]}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}
	cr := decodeJSON[container.CreateResponse](t, resp)
	if cr.ID != "test-container" {
		t.Errorf("got ID %q, want %q", cr.ID, "test-container")
	}

	// Inspect
	resp = request(t, ts, "GET", "/containers/test-container/json", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("inspect: got %d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if ir.Config.Image != "hello-world" {
		t.Errorf("got image %q, want %q", ir.Config.Image, "hello-world")
	}
	if len(ir.Config.Cmd) != 2 || ir.Config.Cmd[0] != "echo" {
		t.Errorf("got cmd %v, want [echo hi]", ir.Config.Cmd)
	}
	if len(ir.Config.Env) != 1 || ir.Config.Env[0] != "FOO=bar" {
		t.Errorf("got env %v, want [FOO=bar]", ir.Config.Env)
	}
}

func TestContainerCreateMissingConfig(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create", `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestContainerCreateNoName(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	// Without a name, the pod gets GenerateName="bad-".
	// The fake clientset doesn't simulate server-side name generation,
	// so just verify the create succeeds.
	resp := request(t, ts, "POST", "/containers/create",
		`{"Image": "alpine"}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}
	resp.Body.Close()
}

func TestContainerList(t *testing.T) {
	now := metav1.Now()
	ts := newTestServer(
		corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "main", Image: "alpine"}},
			},
			Status: corev1.PodStatus{
				Phase:     corev1.PodRunning,
				StartTime: &now,
			},
		},
		corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "main", Image: "nginx"}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodPending},
		},
	)
	defer ts.Close()

	resp := request(t, ts, "GET", "/containers/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	containers := decodeJSON[[]container.Summary](t, resp)
	if len(containers) != 2 {
		t.Fatalf("got %d containers, want 2", len(containers))
	}

	byID := map[string]container.Summary{}
	for _, c := range containers {
		byID[c.ID] = c
	}
	if c := byID["pod-a"]; c.Image != "alpine" || c.State != "running" {
		t.Errorf("pod-a: got image=%q state=%q, want alpine/running", c.Image, c.State)
	}
	if c := byID["pod-b"]; c.Image != "nginx" || c.State != "pending" {
		t.Errorf("pod-b: got image=%q state=%q, want nginx/pending", c.Image, c.State)
	}
}

func TestContainerInspectNotFound(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "GET", "/containers/nope/json", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestContainerKillAndRm(t *testing.T) {
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "to-kill", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "main", Image: "alpine"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	})
	defer ts.Close()

	// Kill
	resp := request(t, ts, "POST", "/containers/to-kill/kill", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("kill: got %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Verify gone
	resp = request(t, ts, "GET", "/containers/to-kill/json", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("inspect after kill: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestContainerStop(t *testing.T) {
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "to-stop", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "main", Image: "alpine"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	})
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/to-stop/stop", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	resp = request(t, ts, "GET", "/containers/to-stop/json", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("inspect after stop: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestContainerRm(t *testing.T) {
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "to-rm", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "main", Image: "alpine"}},
		},
	})
	defer ts.Close()

	resp := request(t, ts, "DELETE", "/containers/to-rm", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestContainerKillNotFound(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/nope/kill", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestContainerPrune(t *testing.T) {
	ts := newTestServer(
		corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "running", Namespace: "default"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "done", Namespace: "default"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
			Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
		},
		corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "failed", Namespace: "default"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
			Status:     corev1.PodStatus{Phase: corev1.PodFailed},
		},
	)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/prune", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	pr := decodeJSON[container.PruneReport](t, resp)
	if len(pr.ContainersDeleted) != 2 {
		t.Errorf("got %d deleted, want 2: %v", len(pr.ContainersDeleted), pr.ContainersDeleted)
	}

	// Running pod should still exist.
	resp = request(t, ts, "GET", "/containers/running/json", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("running pod should still exist, got %d", resp.StatusCode)
	}
}

func TestContainerWaitAlreadyDone(t *testing.T) {
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "exited", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodSucceeded,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "main",
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
				},
			}},
		},
	})
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/exited/wait", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("got %d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	wr := decodeJSON[container.WaitResponse](t, resp)
	if wr.StatusCode != 0 {
		t.Errorf("got exit code %d, want 0", wr.StatusCode)
	}
}

func TestContainerWaitFailedExitCode(t *testing.T) {
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "failed", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodFailed,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "main",
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: 42},
				},
			}},
		},
	})
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/failed/wait", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	wr := decodeJSON[container.WaitResponse](t, resp)
	if wr.StatusCode != 42 {
		t.Errorf("got exit code %d, want 42", wr.StatusCode)
	}
}

func TestContainerWaitNotFound(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/nope/wait", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestContainerStartAlreadyRunning(t *testing.T) {
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "running", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	})
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/running/start", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestContainerLogs(t *testing.T) {
	// The fake clientset doesn't support GetLogs (returns empty).
	// We verify the handler at least responds without error.
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "loggy", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	})
	defer ts.Close()

	resp := request(t, ts, "GET", "/containers/loggy/logs?stdout=1", "")
	defer resp.Body.Close()
	// The fake clientset's GetLogs returns an empty stream, so we get 200 with no body frames.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestExecCreateAndInspect(t *testing.T) {
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "exec-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	})
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/exec-pod/exec",
		`{"Cmd": ["ls", "-la"], "AttachStdout": true, "AttachStderr": true}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("exec create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}
	var cr struct {
		ID string `json:"Id"`
	}
	json.NewDecoder(resp.Body).Decode(&cr)
	resp.Body.Close()
	if cr.ID == "" {
		t.Fatal("exec create returned empty ID")
	}

	// Inspect
	resp = request(t, ts, "GET", "/exec/"+cr.ID+"/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exec inspect: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	ei := decodeJSON[container.ExecInspectResponse](t, resp)
	if ei.ContainerID != "exec-pod" {
		t.Errorf("got container %q, want %q", ei.ContainerID, "exec-pod")
	}
	if ei.Running {
		t.Error("exec should not be running yet")
	}
}

func TestExecInspectNotFound(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "GET", "/exec/bogus/json", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestContainerCreateAndList(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	// Create two containers.
	for _, name := range []string{"c1", "c2"} {
		resp := request(t, ts, "POST", "/containers/create?name="+name,
			`{"Image": "alpine"}`)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s: got %d", name, resp.StatusCode)
		}
	}

	resp := request(t, ts, "GET", "/containers/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d", resp.StatusCode)
	}
	containers := decodeJSON[[]container.Summary](t, resp)
	if len(containers) != 2 {
		t.Errorf("got %d containers, want 2", len(containers))
	}
}

func TestContainerCreateDuplicate(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=dupe",
		`{"Image": "alpine"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first create: got %d", resp.StatusCode)
	}

	resp = request(t, ts, "POST", "/containers/create?name=dupe",
		`{"Image": "alpine"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate create: got %d, want %d", resp.StatusCode, http.StatusConflict)
	}
}

func TestPodToState(t *testing.T) {
	tests := []struct {
		name      string
		phase     corev1.PodPhase
		exitCode  int32
		wantState string
		wantCode  int
	}{
		{"running", corev1.PodRunning, 0, "running", 0},
		{"pending", corev1.PodPending, 0, "created", 0},
		{"succeeded", corev1.PodSucceeded, 0, "exited", 0},
		{"failed", corev1.PodFailed, 1, "exited", 1},
		{"failed-42", corev1.PodFailed, 42, "exited", 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := metav1.NewTime(time.Now())
			pod := &corev1.Pod{
				Status: corev1.PodStatus{
					Phase:     tt.phase,
					StartTime: &now,
					ContainerStatuses: []corev1.ContainerStatus{{
						Name: "main",
						State: corev1.ContainerState{
							Terminated: &corev1.ContainerStateTerminated{ExitCode: tt.exitCode},
						},
					}},
				},
			}
			state := podToState(pod)
			if string(state.Status) != tt.wantState {
				t.Errorf("got status %q, want %q", state.Status, tt.wantState)
			}
			if state.ExitCode != tt.wantCode {
				t.Errorf("got exit code %d, want %d", state.ExitCode, tt.wantCode)
			}
		})
	}
}

func TestWriteStdcopyFrame(t *testing.T) {
	var buf strings.Builder
	writeStdcopyFrame(&buf, 1, []byte("hello\n"))
	data := buf.String()

	if len(data) != 8+6 {
		t.Fatalf("got %d bytes, want %d", len(data), 14)
	}
	if data[0] != 1 {
		t.Errorf("stream type: got %d, want 1", data[0])
	}
	size := binary.BigEndian.Uint32([]byte(data[4:8]))
	if size != 6 {
		t.Errorf("frame size: got %d, want 6", size)
	}
	if data[8:] != "hello\n" {
		t.Errorf("payload: got %q, want %q", data[8:], "hello\n")
	}
}

func TestResponseHeaders(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "GET", "/_ping", "")
	resp.Body.Close()

	if v := resp.Header.Get("Api-Version"); v != "1.45" {
		t.Errorf("Api-Version: got %q, want %q", v, "1.45")
	}
	if v := resp.Header.Get("Server"); v != "badidea" {
		t.Errorf("Server: got %q, want %q", v, "badidea")
	}
	if v := resp.Header.Get("Ostype"); v != "linux" {
		t.Errorf("Ostype: got %q, want %q", v, "linux")
	}
}

func TestStripVersionPrefix(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/version", "/version"},
		{"/v1.45/version", "/version"},
		{"/v1.45/containers/json", "/containers/json"},
		{"/v2.0/info", "/info"},
		{"/volumes/json", "/volumes/json"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			var got string
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.Path
			})
			handler := stripVersionPrefix(inner)
			req := httptest.NewRequest("GET", tt.path, nil)
			handler.ServeHTTP(httptest.NewRecorder(), req)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

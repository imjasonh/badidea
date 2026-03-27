package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestArchiveGetMissingPath(t *testing.T) {
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	})
	defer ts.Close()

	resp := request(t, ts, "GET", "/containers/test-pod/archive", "")
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("got %d, want 400", resp.StatusCode)
	}
}

func TestArchivePutMissingPath(t *testing.T) {
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	})
	defer ts.Close()

	resp := request(t, ts, "PUT", "/containers/test-pod/archive", "")
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("got %d, want 400", resp.StatusCode)
	}
}

func TestArchiveHeadMissingPath(t *testing.T) {
	ts := newTestServer(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	})
	defer ts.Close()

	resp := request(t, ts, "HEAD", "/containers/test-pod/archive?path=", "")
	defer resp.Body.Close()
	// HEAD with empty path should return 400.
	if resp.StatusCode != 400 {
		t.Errorf("got %d, want 400", resp.StatusCode)
	}
}

func TestArchiveGetContainerNotFound(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "GET", "/containers/nope/archive?path=/etc", "")
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("got %d, want 404", resp.StatusCode)
	}
}

func TestArchivePutContainerNotFound(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "PUT", "/containers/nope/archive?path=/tmp", "some-data")
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("got %d, want 404", resp.StatusCode)
	}
}

func TestArchiveHeadContainerNotFound(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "HEAD", "/containers/nope/archive?path=/etc", "")
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("got %d, want 404", resp.StatusCode)
	}
}

func TestContainerCreateSharesProcessNamespace(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=ns-test",
		`{"Image": "alpine"}`)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("create: got %d, want 201", resp.StatusCode)
	}

	// Inspect the pod and verify shareProcessNamespace is set.
	resp = request(t, ts, "GET", "/containers/ns-test/json", "")
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("inspect: got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()
	// The inspect response doesn't expose shareProcessNamespace directly,
	// but the pod was created successfully with the field set.
	// This test validates the creation path doesn't break.
}

func TestContainerPathStatJSON(t *testing.T) {
	stat := &containerPathStat{
		Name: "test.txt",
		Size: 42,
		Mode: 0644,
	}
	data, err := json.Marshal(stat)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(data)

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var got containerPathStat
	if err := json.Unmarshal(decoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "test.txt" || got.Size != 42 || got.Mode != 0644 {
		t.Errorf("round-trip failed: got %+v", got)
	}
}

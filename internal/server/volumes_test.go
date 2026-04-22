package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/volume"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

// newTestServerWithPVCs creates a test server pre-loaded with pods and PVCs.
func newTestServerWithPVCs(pods []corev1.Pod, pvcs []corev1.PersistentVolumeClaim) *httptest.Server {
	clientset := fake.NewSimpleClientset()
	for i := range pods {
		clientset.Tracker().Add(&pods[i])
	}
	for i := range pvcs {
		clientset.Tracker().Add(&pvcs[i])
	}
	s := New(clientset, rest.Config{})
	return httptest.NewServer(s.Handler())
}

func TestVolumeCreateAndInspect(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	// Create
	resp := request(t, ts, "POST", "/volumes/create",
		`{"Name": "mydata", "Labels": {"env": "test"}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}
	v := decodeJSON[volume.Volume](t, resp)
	if v.Name != "mydata" {
		t.Errorf("name: got %q, want %q", v.Name, "mydata")
	}
	if v.Driver != "local" {
		t.Errorf("driver: got %q, want %q", v.Driver, "local")
	}
	if v.Labels["env"] != "test" {
		t.Errorf("labels: got %v, want env=test", v.Labels)
	}
	if _, ok := v.Labels[labelApp]; ok {
		t.Errorf("internal label %s should be filtered from response", labelApp)
	}

	// Inspect
	resp = request(t, ts, "GET", "/volumes/mydata", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("inspect: got %d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	v = decodeJSON[volume.Volume](t, resp)
	if v.Name != "mydata" {
		t.Errorf("inspect name: got %q, want %q", v.Name, "mydata")
	}
}

func TestVolumeCreateMissingName(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/volumes/create", `{}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestVolumeCreateDuplicate(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/volumes/create", `{"Name": "dup"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first create: got %d", resp.StatusCode)
	}

	resp = request(t, ts, "POST", "/volumes/create", `{"Name": "dup"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate create: got %d, want %d", resp.StatusCode, http.StatusConflict)
	}
}

func TestVolumeInspectNotFound(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "GET", "/volumes/nope", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestVolumeDelete(t *testing.T) {
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "todelete",
			Namespace: "default",
			Labels:    map[string]string{labelApp: labelAppValue},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("1Gi"),
				},
			},
		},
	}
	ts := newTestServerWithPVCs(nil, []corev1.PersistentVolumeClaim{pvc})
	defer ts.Close()

	resp := request(t, ts, "DELETE", "/volumes/todelete", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: got %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Verify gone
	resp = request(t, ts, "GET", "/volumes/todelete", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("inspect after delete: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestVolumeDeleteNotFound(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "DELETE", "/volumes/nope", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestVolumeList(t *testing.T) {
	pvcs := []corev1.PersistentVolumeClaim{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vol-a",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue},
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vol-b",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue},
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			},
		},
	}
	ts := newTestServerWithPVCs(nil, pvcs)
	defer ts.Close()

	resp := request(t, ts, "GET", "/volumes", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	lr := decodeJSON[volume.ListResponse](t, resp)
	if len(lr.Volumes) != 2 {
		t.Errorf("got %d volumes, want 2", len(lr.Volumes))
	}
}

func TestVolumeListEmpty(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "GET", "/volumes", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	lr := decodeJSON[volume.ListResponse](t, resp)
	if len(lr.Volumes) != 0 {
		t.Errorf("got %d volumes, want 0", len(lr.Volumes))
	}
}

func TestVolumePrune(t *testing.T) {
	pvcs := []corev1.PersistentVolumeClaim{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unused-vol",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue},
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("1Gi"),
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "used-vol",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue},
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				Resources: corev1.VolumeResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceStorage: resource.MustParse("1Gi"),
					},
				},
			},
		},
	}
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "mypod", Namespace: "default"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "main", Image: "alpine"}},
				Volumes: []corev1.Volume{
					{
						Name: "vol-used-vol",
						VolumeSource: corev1.VolumeSource{
							PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
								ClaimName: "used-vol",
							},
						},
					},
				},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
	}
	ts := newTestServerWithPVCs(pods, pvcs)
	defer ts.Close()

	resp := request(t, ts, "POST", "/volumes/prune", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("prune: got %d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	pr := decodeJSON[volume.PruneReport](t, resp)
	if len(pr.VolumesDeleted) != 1 {
		t.Errorf("got %d deleted, want 1: %v", len(pr.VolumesDeleted), pr.VolumesDeleted)
	}
	if len(pr.VolumesDeleted) > 0 && pr.VolumesDeleted[0] != "unused-vol" {
		t.Errorf("deleted %q, want %q", pr.VolumesDeleted[0], "unused-vol")
	}

	// used-vol should still exist
	resp = request(t, ts, "GET", "/volumes/used-vol", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("used-vol should still exist, got %d", resp.StatusCode)
	}
}

func TestContainerCreateWithBinds(t *testing.T) {
	// Pre-create a PVC for the named volume.
	pvcs := []corev1.PersistentVolumeClaim{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mydata",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue},
			},
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			},
		},
	}
	ts := newTestServerWithPVCs(nil, pvcs)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=vol-test",
		`{"Image": "alpine", "HostConfig": {"Binds": ["mydata:/data"]}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}
	cr := decodeJSON[container.CreateResponse](t, resp)
	if cr.ID != "vol-test" {
		t.Errorf("got ID %q, want %q", cr.ID, "vol-test")
	}

	// Inspect and verify mounts
	resp = request(t, ts, "GET", "/containers/vol-test/json", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("inspect: got %d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if len(ir.Mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(ir.Mounts))
	}
	m := ir.Mounts[0]
	if m.Type != mount.TypeVolume {
		t.Errorf("mount type: got %q, want %q", m.Type, mount.TypeVolume)
	}
	if m.Name != "mydata" {
		t.Errorf("mount name: got %q, want %q", m.Name, "mydata")
	}
	if m.Destination != "/data" {
		t.Errorf("mount dest: got %q, want %q", m.Destination, "/data")
	}
	if !m.RW {
		t.Error("mount should be read-write")
	}
}

func TestContainerCreateWithBindsReadOnly(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=ro-test",
		`{"Image": "alpine", "HostConfig": {"Binds": ["mydata:/data:ro"]}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}

	resp = request(t, ts, "GET", "/containers/ro-test/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if len(ir.Mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(ir.Mounts))
	}
	if ir.Mounts[0].RW {
		t.Error("mount should be read-only")
	}
}

func TestContainerCreateWithBindMount(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	// Bind mounts (absolute path) should be rejected.
	resp := request(t, ts, "POST", "/containers/create?name=bind-test",
		`{"Image": "alpine", "HostConfig": {"Binds": ["/host/path:/data"]}}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bind mount: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestContainerCreateWithDockerMounts(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=mounts-test",
		`{"Image": "alpine", "HostConfig": {"Mounts": [{"Type": "volume", "Source": "myvol", "Target": "/app/data"}]}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}

	resp = request(t, ts, "GET", "/containers/mounts-test/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if len(ir.Mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(ir.Mounts))
	}
	if ir.Mounts[0].Name != "myvol" {
		t.Errorf("mount name: got %q, want %q", ir.Mounts[0].Name, "myvol")
	}
	if ir.Mounts[0].Destination != "/app/data" {
		t.Errorf("mount dest: got %q, want %q", ir.Mounts[0].Destination, "/app/data")
	}
}

func TestContainerCreateWithTmpfsMount(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=tmpfs-test",
		`{"Image": "alpine", "HostConfig": {"Mounts": [{"Type": "tmpfs", "Target": "/tmp/scratch"}]}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}

	resp = request(t, ts, "GET", "/containers/tmpfs-test/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if len(ir.Mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(ir.Mounts))
	}
	if ir.Mounts[0].Type != mount.TypeVolume {
		t.Errorf("mount type: got %q, want %q", ir.Mounts[0].Type, mount.TypeVolume)
	}
}

func TestContainerCreateWithBindMountType(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=bind-type-test",
		`{"Image": "alpine", "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/host", "Target": "/data"}]}}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bind mount type: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestContainerCreateWithAnonymousVolumes(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=anon-test",
		`{"Image": "alpine", "Volumes": {"/data": {}, "/cache": {}}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}

	resp = request(t, ts, "GET", "/containers/anon-test/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if len(ir.Mounts) != 2 {
		t.Fatalf("got %d mounts, want 2", len(ir.Mounts))
	}
}

func TestContainerCreateAnonymousVolumeSkipsCovered(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	// /data is covered by a Bind, so Config.Volumes should not create another mount for it.
	resp := request(t, ts, "POST", "/containers/create?name=covered-test",
		`{"Image": "alpine", "Volumes": {"/data": {}}, "HostConfig": {"Binds": ["myvol:/data"]}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}

	resp = request(t, ts, "GET", "/containers/covered-test/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if len(ir.Mounts) != 1 {
		t.Fatalf("got %d mounts, want 1 (anonymous should be skipped)", len(ir.Mounts))
	}
	if ir.Mounts[0].Name != "myvol" {
		t.Errorf("mount name: got %q, want %q", ir.Mounts[0].Name, "myvol")
	}
}

// --- Unit tests for parse functions ---

func TestParseBinds(t *testing.T) {
	tests := []struct {
		name    string
		binds   []string
		wantErr string
		wantN   int
	}{
		{"named volume", []string{"foo:/data"}, "", 1},
		{"read-only", []string{"foo:/data:ro"}, "", 1},
		{"bind mount rejected", []string{"/host:/data"}, "bind mounts are not supported", 0},
		{"invalid spec", []string{"nocolon"}, "invalid bind mount spec", 0},
		{"multiple", []string{"a:/x", "b:/y"}, "", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vols, mounts, err := parseBinds(tt.binds)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("got err %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(vols) != tt.wantN || len(mounts) != tt.wantN {
				t.Errorf("got %d vols, %d mounts, want %d each", len(vols), len(mounts), tt.wantN)
			}
		})
	}
}

func TestParseDockerMounts(t *testing.T) {
	tests := []struct {
		name    string
		mounts  []mount.Mount
		wantErr string
		wantN   int
	}{
		{
			"volume mount",
			[]mount.Mount{{Type: mount.TypeVolume, Source: "myvol", Target: "/data"}},
			"", 1,
		},
		{
			"tmpfs mount",
			[]mount.Mount{{Type: mount.TypeTmpfs, Target: "/tmp"}},
			"", 1,
		},
		{
			"bind rejected",
			[]mount.Mount{{Type: mount.TypeBind, Source: "/host", Target: "/data"}},
			"bind mounts are not supported", 0,
		},
		{
			"volume missing source",
			[]mount.Mount{{Type: mount.TypeVolume, Target: "/data"}},
			"volume source is required", 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vols, mounts, err := parseDockerMounts(tt.mounts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("got err %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(vols) != tt.wantN || len(mounts) != tt.wantN {
				t.Errorf("got %d vols, %d mounts, want %d each", len(vols), len(mounts), tt.wantN)
			}
		})
	}
}

func TestParseAnonymousVolumes(t *testing.T) {
	configVolumes := map[string]struct{}{
		"/data":  {},
		"/cache": {},
		"/logs":  {},
	}
	covered := map[string]bool{"/data": true}

	vols, mounts := parseAnonymousVolumes(configVolumes, covered)
	if len(vols) != 2 || len(mounts) != 2 {
		t.Errorf("got %d vols, %d mounts, want 2 each", len(vols), len(mounts))
	}
	for _, m := range mounts {
		if m.MountPath == "/data" {
			t.Error("should not have created mount for covered path /data")
		}
	}
}

func TestVolumeCreateAndList(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	// Create two volumes
	for _, name := range []string{"vol1", "vol2"} {
		resp := request(t, ts, "POST", "/volumes/create", `{"Name": "`+name+`"}`)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s: got %d, want %d", name, resp.StatusCode, http.StatusCreated)
		}
	}

	resp := request(t, ts, "GET", "/volumes", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	lr := decodeJSON[volume.ListResponse](t, resp)
	if len(lr.Volumes) != 2 {
		t.Errorf("got %d volumes, want 2", len(lr.Volumes))
	}
}

func TestVolumeVersionPrefix(t *testing.T) {
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/v"+DockerAPIVersion+"/volumes/create", `{"Name": "prefixed"}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create with version prefix: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}
	v := decodeJSON[volume.Volume](t, resp)
	if v.Name != "prefixed" {
		t.Errorf("name: got %q, want %q", v.Name, "prefixed")
	}
}

func TestVolumeInspectRejectsNonBadideaPVC(t *testing.T) {
	// A PVC without the badidea label should not be returned by inspect.
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foreign",
			Namespace: "default",
			Labels:    map[string]string{"owner": "someone-else"},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		},
	}
	ts := newTestServerWithPVCs(nil, []corev1.PersistentVolumeClaim{pvc})
	defer ts.Close()

	resp := request(t, ts, "GET", "/volumes/foreign", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("inspect non-badidea PVC: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestVolumeDeleteRejectsNonBadideaPVC(t *testing.T) {
	// A PVC without the badidea label should not be deletable via the API.
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foreign",
			Namespace: "default",
			Labels:    map[string]string{"owner": "someone-else"},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		},
	}
	ts := newTestServerWithPVCs(nil, []corev1.PersistentVolumeClaim{pvc})
	defer ts.Close()

	resp := request(t, ts, "DELETE", "/volumes/foreign", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete non-badidea PVC: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestVolumeLabelsFilterInternalLabel(t *testing.T) {
	// The internal app=badidea label should be filtered from volume responses.
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "labeled",
			Namespace: "default",
			Labels:    map[string]string{labelApp: labelAppValue, "env": "prod"},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		},
	}
	ts := newTestServerWithPVCs(nil, []corev1.PersistentVolumeClaim{pvc})
	defer ts.Close()

	resp := request(t, ts, "GET", "/volumes/labeled", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	v := decodeJSON[volume.Volume](t, resp)
	if _, ok := v.Labels[labelApp]; ok {
		t.Errorf("internal label %q should be filtered", labelApp)
	}
	if v.Labels["env"] != "prod" {
		t.Errorf("user label env: got %q, want %q", v.Labels["env"], "prod")
	}
}

func TestParseBindsDeduplicatesSameSource(t *testing.T) {
	// Same volume mounted to two different paths should produce 1 volume, 2 mounts.
	binds := []string{"mydata:/path1", "mydata:/path2"}
	vols, mounts, err := parseBinds(binds)
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 1 {
		t.Errorf("got %d volumes, want 1 (deduplicated)", len(vols))
	}
	if len(mounts) != 2 {
		t.Errorf("got %d mounts, want 2", len(mounts))
	}
}

func TestParseDockerMountsDeduplicatesSameSource(t *testing.T) {
	// Same volume mounted to two different paths should produce 1 volume, 2 mounts.
	mnts := []mount.Mount{
		{Type: mount.TypeVolume, Source: "shared", Target: "/a"},
		{Type: mount.TypeVolume, Source: "shared", Target: "/b"},
	}
	vols, mounts, err := parseDockerMounts(mnts)
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 1 {
		t.Errorf("got %d volumes, want 1 (deduplicated)", len(vols))
	}
	if len(mounts) != 2 {
		t.Errorf("got %d mounts, want 2", len(mounts))
	}
}

func TestContainerCreateAutoCreatesVolume(t *testing.T) {
	// When a named volume doesn't exist, containerCreate should auto-create it.
	ts := newTestServerWithPVCs(nil, nil)
	defer ts.Close()

	// Create container with a volume that doesn't exist yet.
	resp := request(t, ts, "POST", "/containers/create?name=autocreate-test",
		`{"Image": "alpine", "HostConfig": {"Binds": ["newvol:/data"]}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}

	// The volume should now be inspectable.
	resp = request(t, ts, "GET", "/volumes/newvol", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("auto-created volume should exist, got %d", resp.StatusCode)
	} else {
		v := decodeJSON[volume.Volume](t, resp)
		if v.Name != "newvol" {
			t.Errorf("volume name: got %q, want %q", v.Name, "newvol")
		}
	}
}

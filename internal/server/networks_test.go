package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

// newTestServerWithObjects creates a test server pre-loaded with pods, ConfigMaps, and Services.
func newTestServerWithObjects(pods []corev1.Pod, cms []corev1.ConfigMap, svcs []corev1.Service) *httptest.Server {
	clientset := fake.NewSimpleClientset()
	for i := range pods {
		clientset.Tracker().Add(&pods[i])
	}
	for i := range cms {
		clientset.Tracker().Add(&cms[i])
	}
	for i := range svcs {
		clientset.Tracker().Add(&svcs[i])
	}
	s := New(clientset, rest.Config{})
	return httptest.NewServer(s.Handler())
}

func TestNetworkCreateAndInspect(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	// Create a network.
	resp := request(t, ts, "POST", "/networks/create",
		`{"Name": "mynet", "Driver": "bridge", "Labels": {"env": "test"}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}
	cr := decodeJSON[network.CreateResponse](t, resp)
	if cr.ID != "mynet" {
		t.Errorf("id: got %q, want %q", cr.ID, "mynet")
	}

	// Inspect.
	resp = request(t, ts, "GET", "/networks/mynet", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("inspect: got %d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	n := decodeJSON[network.Inspect](t, resp)
	if n.Name != "mynet" {
		t.Errorf("name: got %q, want %q", n.Name, "mynet")
	}
	if n.Driver != "bridge" {
		t.Errorf("driver: got %q, want %q", n.Driver, "bridge")
	}
	if n.Labels["env"] != "test" {
		t.Errorf("labels: got %v, want env=test", n.Labels)
	}
}

func TestNetworkCreateMissingName(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/networks/create", `{}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestNetworkCreateDuplicate(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/networks/create", `{"Name": "dup"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first create: got %d", resp.StatusCode)
	}

	resp = request(t, ts, "POST", "/networks/create", `{"Name": "dup"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate: got %d, want %d", resp.StatusCode, http.StatusConflict)
	}
}

func TestNetworkCreateHostRejected(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/networks/create", `{"Name": "host"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("host: got %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestNetworkInspectNotFound(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "GET", "/networks/nope", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestNetworkDelete(t *testing.T) {
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "todelete",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	ts := newTestServerWithObjects(nil, cms, nil)
	defer ts.Close()

	resp := request(t, ts, "DELETE", "/networks/todelete", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: got %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Verify gone.
	resp = request(t, ts, "GET", "/networks/todelete", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("inspect after delete: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestNetworkDeleteBridgeRejected(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "DELETE", "/networks/bridge", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestNetworkDeleteNotFound(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "DELETE", "/networks/nope", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestNetworkList(t *testing.T) {
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "net-a",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "net-b",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "overlay"},
		},
	}
	ts := newTestServerWithObjects(nil, cms, nil)
	defer ts.Close()

	resp := request(t, ts, "GET", "/networks", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	networks := decodeJSON[[]network.Inspect](t, resp)
	// Should include at least the 2 pre-created + bridge (auto-created).
	if len(networks) < 2 {
		t.Errorf("got %d networks, want at least 2", len(networks))
	}
}

func TestNetworkListIncludesDefaultBridge(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "GET", "/networks", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d", resp.StatusCode)
	}
	networks := decodeJSON[[]network.Inspect](t, resp)
	found := false
	for _, n := range networks {
		if n.Name == "bridge" {
			found = true
			break
		}
	}
	if !found {
		t.Error("default bridge network not found in list")
	}
}

func TestNetworkInspectBridgeAutoCreated(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "GET", "/networks/bridge", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("inspect bridge: got %d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	n := decodeJSON[network.Inspect](t, resp)
	if n.Name != "bridge" {
		t.Errorf("name: got %q, want %q", n.Name, "bridge")
	}
	if n.Driver != "bridge" {
		t.Errorf("driver: got %q, want %q", n.Driver, "bridge")
	}
}

func TestNetworkPrune(t *testing.T) {
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unused-net",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "used-net",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mypod",
				Namespace: "default",
				Labels:    map[string]string{networkLabelPrefix + "used-net": "true"},
			},
			Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
	}
	ts := newTestServerWithObjects(pods, cms, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/networks/prune", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("prune: got %d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	pr := decodeJSON[network.PruneReport](t, resp)
	if len(pr.NetworksDeleted) != 1 {
		t.Errorf("got %d deleted, want 1: %v", len(pr.NetworksDeleted), pr.NetworksDeleted)
	}
	if len(pr.NetworksDeleted) > 0 && pr.NetworksDeleted[0] != "unused-net" {
		t.Errorf("deleted %q, want %q", pr.NetworksDeleted[0], "unused-net")
	}

	// used-net should still exist.
	resp = request(t, ts, "GET", "/networks/used-net", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("used-net should still exist, got %d", resp.StatusCode)
	}
}

func TestNetworkConnect(t *testing.T) {
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mynet",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mypod",
				Namespace: "default",
				Labels:    map[string]string{"badidea.dev/pod-name": "mypod"},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		},
	}
	ts := newTestServerWithObjects(pods, cms, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/networks/mynet/connect",
		`{"Container": "mypod"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Inspect network should show the container.
	resp = request(t, ts, "GET", "/networks/mynet", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d", resp.StatusCode)
	}
	n := decodeJSON[network.Inspect](t, resp)
	if _, ok := n.Containers["mypod"]; !ok {
		t.Error("mypod should be in network containers")
	}
}

func TestNetworkDisconnect(t *testing.T) {
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mynet",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mypod",
				Namespace: "default",
				Labels: map[string]string{
					"badidea.dev/pod-name":          "mypod",
					networkLabelPrefix + "mynet": "true",
				},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		},
	}
	ts := newTestServerWithObjects(pods, cms, nil)
	defer ts.Close()

	// Verify connected first.
	resp := request(t, ts, "GET", "/networks/mynet", "")
	n := decodeJSON[network.Inspect](t, resp)
	if _, ok := n.Containers["mypod"]; !ok {
		t.Fatal("mypod should be in network before disconnect")
	}

	// Disconnect.
	resp = request(t, ts, "POST", "/networks/mynet/disconnect",
		`{"Container": "mypod"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disconnect: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify disconnected.
	resp = request(t, ts, "GET", "/networks/mynet", "")
	n = decodeJSON[network.Inspect](t, resp)
	if _, ok := n.Containers["mypod"]; ok {
		t.Error("mypod should not be in network after disconnect")
	}
}

func TestNetworkConnectNotFoundNetwork(t *testing.T) {
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "mypod", Namespace: "default"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		},
	}
	ts := newTestServerWithObjects(pods, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/networks/nope/connect", `{"Container": "mypod"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestNetworkConnectNotFoundContainer(t *testing.T) {
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mynet",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	ts := newTestServerWithObjects(nil, cms, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/networks/mynet/connect", `{"Container": "nope"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestNetworkCreateAndList(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	for _, name := range []string{"net1", "net2"} {
		resp := request(t, ts, "POST", "/networks/create", `{"Name": "`+name+`"}`)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s: got %d", name, resp.StatusCode)
		}
	}

	resp := request(t, ts, "GET", "/networks", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d", resp.StatusCode)
	}
	networks := decodeJSON[[]network.Inspect](t, resp)
	// net1 + net2 + bridge (auto-created)
	if len(networks) != 3 {
		t.Errorf("got %d networks, want 3", len(networks))
	}
}

func TestNetworkVersionPrefix(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/v1.45/networks/create", `{"Name": "prefixed"}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create with version prefix: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}
	cr := decodeJSON[network.CreateResponse](t, resp)
	if cr.ID != "prefixed" {
		t.Errorf("id: got %q, want %q", cr.ID, "prefixed")
	}
}

func TestContainerCreateWithNetwork(t *testing.T) {
	// Pre-create the network.
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mynet",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	ts := newTestServerWithObjects(nil, cms, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=nettest",
		`{"Image": "alpine", "NetworkingConfig": {"EndpointsConfig": {"mynet": {}}}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}
	cr := decodeJSON[container.CreateResponse](t, resp)
	if cr.ID != "nettest" {
		t.Errorf("id: got %q, want %q", cr.ID, "nettest")
	}

	// The pod should be on the network.
	resp = request(t, ts, "GET", "/networks/mynet", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect net: got %d", resp.StatusCode)
	}
	n := decodeJSON[network.Inspect](t, resp)
	if _, ok := n.Containers["nettest"]; !ok {
		t.Error("nettest should be in network containers")
	}
}

func TestContainerCreateWithHostNetworkRejected(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=hostnet",
		`{"Image": "alpine", "NetworkingConfig": {"EndpointsConfig": {"host": {}}}}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("host network: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestNetworkInspectShowsContainers(t *testing.T) {
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mynet",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod-a",
				Namespace: "default",
				Labels:    map[string]string{networkLabelPrefix + "mynet": "true"},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod-b",
				Namespace: "default",
				Labels:    map[string]string{},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		},
	}
	ts := newTestServerWithObjects(pods, cms, nil)
	defer ts.Close()

	resp := request(t, ts, "GET", "/networks/mynet", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d", resp.StatusCode)
	}
	n := decodeJSON[network.Inspect](t, resp)
	if len(n.Containers) != 1 {
		t.Errorf("got %d containers, want 1", len(n.Containers))
	}
	if _, ok := n.Containers["pod-a"]; !ok {
		t.Error("pod-a should be in network containers")
	}
}

func TestBridgeNetworkShowsAllContainers(t *testing.T) {
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "default"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-b", Namespace: "default"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		},
	}
	ts := newTestServerWithObjects(pods, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "GET", "/networks/bridge", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("inspect bridge: got %d: %s", resp.StatusCode, body)
	}
	n := decodeJSON[network.Inspect](t, resp)
	if len(n.Containers) != 2 {
		t.Errorf("bridge should show all containers: got %d, want 2", len(n.Containers))
	}
}

func TestNetworkCreateDefaultDriver(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	// Create without specifying driver; should default to "bridge".
	resp := request(t, ts, "POST", "/networks/create", `{"Name": "nodriver"}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	resp = request(t, ts, "GET", "/networks/nodriver", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d", resp.StatusCode)
	}
	n := decodeJSON[network.Inspect](t, resp)
	if n.Driver != "bridge" {
		t.Errorf("driver: got %q, want %q", n.Driver, "bridge")
	}
}

func TestNetworkCreateOverlayDriverAccepted(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	// Overlay driver accepted but stored as-is (no effect).
	resp := request(t, ts, "POST", "/networks/create", `{"Name": "overlay-net", "Driver": "overlay"}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	resp = request(t, ts, "GET", "/networks/overlay-net", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d", resp.StatusCode)
	}
	n := decodeJSON[network.Inspect](t, resp)
	if n.Driver != "overlay" {
		t.Errorf("driver: got %q, want %q", n.Driver, "overlay")
	}
}

func TestNetworkPruneBridgeNeverPruned(t *testing.T) {
	// Create only a bridge ConfigMap (no pods reference it).
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bridge",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	ts := newTestServerWithObjects(nil, cms, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/networks/prune", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("prune: got %d", resp.StatusCode)
	}
	pr := decodeJSON[network.PruneReport](t, resp)
	for _, name := range pr.NetworksDeleted {
		if name == "bridge" {
			t.Error("bridge network should never be pruned")
		}
	}
}

// --- Helper unit tests ---

func TestNetworkLabelName(t *testing.T) {
	tests := []struct {
		key      string
		wantName string
		wantOK   bool
	}{
		{"badidea.network/mynet", "mynet", true},
		{"badidea.network/bridge", "bridge", true},
		{"other-label", "", false},
		{"badidea.network/", "", false},
	}
	for _, tt := range tests {
		name, ok := networkLabelName(tt.key)
		if ok != tt.wantOK || name != tt.wantName {
			t.Errorf("networkLabelName(%q) = %q, %v; want %q, %v", tt.key, name, ok, tt.wantName, tt.wantOK)
		}
	}
}

func TestPodOnNetwork(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				networkLabelPrefix + "mynet": "true",
			},
		},
	}

	if !podOnNetwork(pod, "bridge") {
		t.Error("all pods should be on bridge")
	}
	if !podOnNetwork(pod, "mynet") {
		t.Error("pod should be on mynet")
	}
	if podOnNetwork(pod, "other") {
		t.Error("pod should not be on other")
	}
}

func TestParsePortProto(t *testing.T) {
	tests := []struct {
		input     string
		wantPort  int
		wantProto string
	}{
		{"80/tcp", 80, "TCP"},
		{"443/udp", 443, "UDP"},
		{"8080", 8080, "TCP"},
	}
	for _, tt := range tests {
		port, proto := parsePortProto(tt.input)
		if port != tt.wantPort || proto != tt.wantProto {
			t.Errorf("parsePortProto(%q) = %d, %q; want %d, %q", tt.input, port, proto, tt.wantPort, tt.wantProto)
		}
	}
}

func TestContainerCreateWithNonexistentNetwork(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=badnet",
		`{"Image": "alpine", "NetworkingConfig": {"EndpointsConfig": {"nope": {}}}}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("nonexistent network via EndpointsConfig: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestContainerCreateWithNonexistentNetworkMode(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	// Docker CLI sends --network via HostConfig.NetworkMode.
	resp := request(t, ts, "POST", "/containers/create?name=badmode",
		`{"Image": "alpine", "HostConfig": {"NetworkMode": "nope"}}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("nonexistent network via NetworkMode: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestContainerCreateWithNetworkMode(t *testing.T) {
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mynet",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	ts := newTestServerWithObjects(nil, cms, nil)
	defer ts.Close()

	// Docker CLI sends --network via HostConfig.NetworkMode (not just EndpointsConfig).
	resp := request(t, ts, "POST", "/containers/create?name=modetest",
		`{"Image": "alpine", "HostConfig": {"NetworkMode": "mynet"}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want %d: %s", resp.StatusCode, http.StatusCreated, body)
	}
	resp.Body.Close()

	// Inspect should show mynet in NetworkSettings.
	resp = request(t, ts, "GET", "/containers/modetest/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d", resp.StatusCode)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if ir.NetworkSettings == nil {
		t.Fatal("NetworkSettings is nil")
	}
	if _, ok := ir.NetworkSettings.Networks["mynet"]; !ok {
		t.Errorf("expected mynet in NetworkSettings.Networks, got: %v", ir.NetworkSettings.Networks)
	}
}

func TestContainerCreateWithHostNetworkModeRejected(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/containers/create?name=hostmode",
		`{"Image": "alpine", "HostConfig": {"NetworkMode": "host"}}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("host NetworkMode: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestContainerInspectNetworkSettings(t *testing.T) {
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mynet",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	ts := newTestServerWithObjects(nil, cms, nil)
	defer ts.Close()

	// Create container on mynet.
	resp := request(t, ts, "POST", "/containers/create?name=netinspect",
		`{"Image": "alpine", "NetworkingConfig": {"EndpointsConfig": {"mynet": {}}}}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Inspect should show NetworkSettings with both bridge and mynet.
	resp = request(t, ts, "GET", "/containers/netinspect/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d", resp.StatusCode)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if ir.NetworkSettings == nil {
		t.Fatal("NetworkSettings is nil")
	}
	if _, ok := ir.NetworkSettings.Networks["bridge"]; !ok {
		t.Error("expected bridge in NetworkSettings.Networks")
	}
	if _, ok := ir.NetworkSettings.Networks["mynet"]; !ok {
		t.Error("expected mynet in NetworkSettings.Networks")
	}
}

func TestContainerInspectDefaultNetworkSettings(t *testing.T) {
	ts := newTestServerWithObjects(nil, nil, nil)
	defer ts.Close()

	// Create container without a network.
	resp := request(t, ts, "POST", "/containers/create?name=nonet",
		`{"Image": "alpine"}`)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Inspect should show bridge only.
	resp = request(t, ts, "GET", "/containers/nonet/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d", resp.StatusCode)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if ir.NetworkSettings == nil {
		t.Fatal("NetworkSettings is nil")
	}
	if len(ir.NetworkSettings.Networks) != 1 {
		t.Errorf("got %d networks, want 1 (bridge only)", len(ir.NetworkSettings.Networks))
	}
	if _, ok := ir.NetworkSettings.Networks["bridge"]; !ok {
		t.Error("expected bridge in NetworkSettings.Networks")
	}
}

func TestNetworkConnectAddsPodNameLabel(t *testing.T) {
	cms := []corev1.ConfigMap{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mynet",
				Namespace: "default",
				Labels:    map[string]string{labelApp: labelAppValue, networkConfigMapLabel: "true"},
			},
			Data: map[string]string{"driver": "bridge"},
		},
	}
	// Pod created WITHOUT badidea.dev/pod-name label (simulating a pod
	// created before network support was added).
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "oldpod",
				Namespace: "default",
				Labels:    map[string]string{},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "alpine"}}},
		},
	}
	ts := newTestServerWithObjects(pods, cms, nil)
	defer ts.Close()

	resp := request(t, ts, "POST", "/networks/mynet/connect",
		`{"Container": "oldpod"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Inspect the pod to verify it has the pod-name label.
	resp = request(t, ts, "GET", "/containers/oldpod/json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect: got %d", resp.StatusCode)
	}
	ir := decodeJSON[container.InspectResponse](t, resp)
	if ir.NetworkSettings == nil {
		t.Fatal("NetworkSettings is nil")
	}
	if _, ok := ir.NetworkSettings.Networks["mynet"]; !ok {
		t.Error("expected mynet in NetworkSettings after connect")
	}
}

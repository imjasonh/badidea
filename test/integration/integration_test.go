//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imjasonh/badidea/internal/server"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	dockerHost   string
	dockerConfig string
)

func TestMain(m *testing.M) {
	code := run(m)
	os.Exit(code)
}

func run(m *testing.M) int {
	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	externalCluster := clusterName != ""
	if !externalCluster {
		clusterName = "badidea-integration"
	}

	// Create the kind cluster unless one was provided externally (e.g. CI).
	if !externalCluster {
		if err := kindCreate(clusterName); err != nil {
			fmt.Fprintf(os.Stderr, "failed to create kind cluster: %v\n", err)
			return 1
		}
		defer kindDelete(clusterName)
	}

	// Build a Kubernetes clientset from the kind kubeconfig.
	kubeconfig, err := kindKubeconfig(clusterName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get kubeconfig: %v\n", err)
		return 1
	}
	restCfg, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfig))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build rest config: %v\n", err)
		return 1
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create clientset: %v\n", err)
		return 1
	}

	// Wait for the cluster to be ready.
	if err := waitForCluster(clientset); err != nil {
		fmt.Fprintf(os.Stderr, "cluster not ready: %v\n", err)
		return 1
	}

	// Start the badidea server on a random port.
	s := server.New(clientset, *restCfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen: %v\n", err)
		return 1
	}
	defer ln.Close()
	dockerHost = "tcp://" + ln.Addr().String()

	srv := &http.Server{Handler: s.Handler()}
	go srv.Serve(ln)
	defer srv.Close()

	// Create a temporary Docker config directory with the required header.
	tmpDir, err := os.MkdirTemp("", "badidea-docker-config-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmpDir)

	configJSON := `{"HttpHeaders": {"x-badidea": "true"}}`
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(configJSON), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write docker config: %v\n", err)
		return 1
	}
	dockerConfig = tmpDir

	return m.Run()
}

// dockerCmd builds an exec.Cmd for running the docker CLI against the test server.
func dockerCmd(args ...string) *exec.Cmd {
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(),
		"DOCKER_HOST="+dockerHost,
		"DOCKER_CONFIG="+dockerConfig,
	)
	return cmd
}

// dockerRun runs a docker CLI command and returns combined output.
func dockerRun(t *testing.T, args ...string) string {
	t.Helper()
	cmd := dockerCmd(args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s failed: %v\noutput: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// --- Kind helpers ---

func kindCreate(clusterName string) error {
	cmd := exec.Command("kind", "create", "cluster",
		"--name", clusterName,
		"--wait", "120s",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func kindDelete(clusterName string) {
	cmd := exec.Command("kind", "delete", "cluster", "--name", clusterName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func kindKubeconfig(clusterName string) (string, error) {
	out, err := exec.Command("kind", "get", "kubeconfig", "--name", clusterName).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func waitForCluster(clientset kubernetes.Interface) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for {
		_, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for cluster: %w", err)
		case <-time.After(2 * time.Second):
		}
	}
}

// --- Tests ---

func TestPing(t *testing.T) {
	out := dockerRun(t, "version")
	if !strings.Contains(out, "badidea") {
		t.Errorf("expected 'badidea' in version output, got: %s", out)
	}
}

func TestRunHelloWorld(t *testing.T) {
	name := "test-hello-" + randomSuffix()

	// Create and start a container that prints a message and exits.
	out := dockerRun(t, "run", "--name", name, "busybox", "echo", "hello from badidea")
	if !strings.Contains(out, "hello from badidea") {
		t.Errorf("expected 'hello from badidea' in output, got: %s", out)
	}

	// Clean up.
	dockerCmd("rm", "-f", name).Run()
}

func TestCreateStartStopRm(t *testing.T) {
	name := "test-lifecycle-" + randomSuffix()

	// Create
	out := dockerRun(t, "create", "--name", name, "busybox", "sleep", "300")
	if !strings.Contains(out, name) {
		t.Errorf("expected container name %q in create output, got: %s", name, out)
	}

	// Start
	dockerRun(t, "start", name)

	// Verify running via inspect
	out = dockerRun(t, "inspect", "--format", "{{.State.Running}}", name)
	if !strings.Contains(out, "true") {
		t.Errorf("expected container to be running, got: %s", out)
	}

	// Stop
	dockerRun(t, "stop", name)

	// Remove (may already be deleted by stop, ignore error)
	dockerCmd("rm", "-f", name).Run()
}

func TestPs(t *testing.T) {
	name := "test-ps-" + randomSuffix()

	// Create and start a long-running container.
	dockerRun(t, "create", "--name", name, "busybox", "sleep", "300")
	dockerRun(t, "start", name)
	defer dockerCmd("rm", "-f", name).Run()

	// List containers.
	out := dockerRun(t, "ps")
	if !strings.Contains(out, name) {
		t.Errorf("expected %q in docker ps output, got: %s", name, out)
	}
}

func TestInspect(t *testing.T) {
	name := "test-inspect-" + randomSuffix()

	dockerRun(t, "create", "--name", name, "busybox", "sleep", "300")
	dockerRun(t, "start", name)
	defer dockerCmd("rm", "-f", name).Run()

	out := dockerRun(t, "inspect", name)

	// Parse JSON to verify structure.
	var inspected []map[string]any
	if err := json.Unmarshal([]byte(out), &inspected); err != nil {
		t.Fatalf("failed to parse inspect output: %v", err)
	}
	if len(inspected) == 0 {
		t.Fatal("expected at least one inspect result")
	}
	cfg, ok := inspected[0]["Config"].(map[string]any)
	if !ok {
		t.Fatal("missing Config in inspect output")
	}
	image, _ := cfg["Image"].(string)
	if !strings.Contains(image, "busybox") {
		t.Errorf("expected image to contain 'busybox', got: %s", image)
	}
}

func TestLogs(t *testing.T) {
	name := "test-logs-" + randomSuffix()

	dockerRun(t, "run", "--name", name, "busybox", "echo", "log-test-output")
	defer dockerCmd("rm", "-f", name).Run()

	out := dockerRun(t, "logs", name)
	if !strings.Contains(out, "log-test-output") {
		t.Errorf("expected 'log-test-output' in logs, got: %s", out)
	}
}

func TestContainerPrune(t *testing.T) {
	name := "test-prune-" + randomSuffix()

	// Run a container that exits immediately.
	dockerRun(t, "run", "--name", name, "busybox", "true")

	// Wait briefly for the pod to reach a terminal state.
	time.Sleep(5 * time.Second)

	// Prune exited containers.
	out := dockerRun(t, "container", "prune", "-f")
	t.Logf("prune output: %s", out)

	// The container should no longer be visible.
	cmd := dockerCmd("inspect", name)
	if err := cmd.Run(); err == nil {
		t.Errorf("expected inspect to fail after prune, but it succeeded")
	}
}

func TestRunWithEnv(t *testing.T) {
	name := "test-env-" + randomSuffix()

	out := dockerRun(t, "run", "--name", name, "-e", "MY_VAR=hello123", "busybox", "env")
	if !strings.Contains(out, "MY_VAR=hello123") {
		t.Errorf("expected 'MY_VAR=hello123' in env output, got: %s", out)
	}
	defer dockerCmd("rm", "-f", name).Run()
}

func TestExitCode(t *testing.T) {
	name := "test-exit-" + randomSuffix()

	cmd := dockerCmd("run", "--name", name, "busybox", "sh", "-c", "exit 42")
	out, err := cmd.CombinedOutput()
	t.Logf("exit code test output: %s", out)

	if err == nil {
		t.Fatal("expected non-zero exit code, got nil error")
	}

	// Check that docker wait returns the correct exit code.
	waitOut := dockerRun(t, "wait", name)
	if !strings.Contains(strings.TrimSpace(waitOut), "42") {
		t.Errorf("expected exit code 42 from docker wait, got: %s", waitOut)
	}

	defer dockerCmd("rm", "-f", name).Run()
}

func TestKillContainer(t *testing.T) {
	name := "test-kill-" + randomSuffix()

	dockerRun(t, "create", "--name", name, "busybox", "sleep", "300")
	dockerRun(t, "start", name)

	// Kill should succeed.
	dockerRun(t, "kill", name)

	// Pod deletion in Kubernetes is async; poll until the container is
	// gone (inspect fails) or no longer running.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cmd := dockerCmd("inspect", "--format", "{{.State.Running}}", name)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// Container is gone — success.
			return
		}
		if !strings.Contains(string(out), "true") {
			// Container exists but is no longer running — success.
			return
		}
		time.Sleep(time.Second)
	}
	t.Errorf("container %s still running 30s after kill", name)
}

// --- Volume tests ---

func TestVolumeCreateInspectRm(t *testing.T) {
	name := "test-vol-" + randomSuffix()

	// Create
	out := dockerRun(t, "volume", "create", name)
	if !strings.Contains(out, name) {
		t.Errorf("expected volume name %q in create output, got: %s", name, out)
	}

	// Inspect
	out = dockerRun(t, "volume", "inspect", name)
	var volumes []map[string]any
	if err := json.Unmarshal([]byte(out), &volumes); err != nil {
		t.Fatalf("failed to parse volume inspect output: %v", err)
	}
	if len(volumes) == 0 {
		t.Fatal("expected at least one volume in inspect output")
	}
	if got, _ := volumes[0]["Name"].(string); got != name {
		t.Errorf("expected volume name %q, got %q", name, got)
	}

	// Remove
	dockerRun(t, "volume", "rm", name)

	// Verify gone
	cmd := dockerCmd("volume", "inspect", name)
	if err := cmd.Run(); err == nil {
		t.Error("expected volume inspect to fail after rm, but it succeeded")
	}
}

func TestVolumeList(t *testing.T) {
	name := "test-volls-" + randomSuffix()

	dockerRun(t, "volume", "create", name)
	defer dockerCmd("volume", "rm", name).Run()

	out := dockerRun(t, "volume", "ls")
	if !strings.Contains(out, name) {
		t.Errorf("expected %q in volume ls output, got: %s", name, out)
	}
}

func TestVolumePrune(t *testing.T) {
	name := "test-volpr-" + randomSuffix()

	dockerRun(t, "volume", "create", name)

	// Prune unused volumes.
	out := dockerRun(t, "volume", "prune", "-f")
	t.Logf("volume prune output: %s", out)

	// The volume should be gone.
	cmd := dockerCmd("volume", "inspect", name)
	if err := cmd.Run(); err == nil {
		t.Error("expected volume inspect to fail after prune, but it succeeded")
	}
}

func TestRunWithNamedVolume(t *testing.T) {
	volName := "test-runvol-" + randomSuffix()
	name := "test-volrun-" + randomSuffix()

	// Create a volume.
	dockerRun(t, "volume", "create", volName)
	defer dockerCmd("volume", "rm", volName).Run()

	// Run a container that writes to the volume.
	dockerRun(t, "run", "--name", name, "-v", volName+":/data",
		"busybox", "sh", "-c", "echo hello-volume > /data/test.txt")
	defer dockerCmd("rm", "-f", name).Run()

	// Run another container that reads from the same volume.
	name2 := "test-volread-" + randomSuffix()
	out := dockerRun(t, "run", "--name", name2, "-v", volName+":/data",
		"busybox", "cat", "/data/test.txt")
	defer dockerCmd("rm", "-f", name2).Run()

	if !strings.Contains(out, "hello-volume") {
		t.Errorf("expected 'hello-volume' in output, got: %s", out)
	}
}

func TestRunWithTmpfs(t *testing.T) {
	name := "test-tmpfs-" + randomSuffix()

	// Run a container with a tmpfs mount and verify it's writable.
	out := dockerRun(t, "run", "--name", name,
		"--mount", "type=tmpfs,target=/scratch",
		"busybox", "sh", "-c", "echo tmpfs-ok > /scratch/test.txt && cat /scratch/test.txt")
	defer dockerCmd("rm", "-f", name).Run()

	if !strings.Contains(out, "tmpfs-ok") {
		t.Errorf("expected 'tmpfs-ok' in output, got: %s", out)
	}
}

func TestRunWithBindMountRejected(t *testing.T) {
	name := "test-bind-" + randomSuffix()

	// Bind mounts should be rejected.
	cmd := dockerCmd("run", "--name", name, "-v", "/tmp:/data", "busybox", "true")
	out, err := cmd.CombinedOutput()
	defer dockerCmd("rm", "-f", name).Run()

	if err == nil {
		t.Error("expected bind mount to fail, but it succeeded")
	}
	if !strings.Contains(string(out), "bind mounts are not supported") {
		t.Logf("output: %s", out)
	}
}

func TestInspectWithMounts(t *testing.T) {
	volName := "test-inspvol-" + randomSuffix()
	name := "test-inspmnt-" + randomSuffix()

	dockerRun(t, "volume", "create", volName)
	defer dockerCmd("volume", "rm", volName).Run()

	dockerRun(t, "create", "--name", name, "-v", volName+":/data", "busybox", "true")
	defer dockerCmd("rm", "-f", name).Run()

	out := dockerRun(t, "inspect", name)
	var inspected []map[string]any
	if err := json.Unmarshal([]byte(out), &inspected); err != nil {
		t.Fatalf("failed to parse inspect output: %v", err)
	}
	if len(inspected) == 0 {
		t.Fatal("expected at least one inspect result")
	}

	mounts, ok := inspected[0]["Mounts"].([]any)
	if !ok || len(mounts) == 0 {
		t.Fatalf("expected Mounts in inspect output, got: %v", inspected[0]["Mounts"])
	}
	m, _ := mounts[0].(map[string]any)
	if dest, _ := m["Destination"].(string); dest != "/data" {
		t.Errorf("expected mount destination /data, got %q", dest)
	}
}

// --- Network tests ---

func TestNetworkCreateInspectRm(t *testing.T) {
	name := "test-net-" + randomSuffix()

	// Create
	out := dockerRun(t, "network", "create", name)
	if !strings.Contains(out, name) {
		t.Errorf("expected network name %q in create output, got: %s", name, out)
	}

	// Inspect
	out = dockerRun(t, "network", "inspect", name)
	var networks []map[string]any
	if err := json.Unmarshal([]byte(out), &networks); err != nil {
		t.Fatalf("failed to parse network inspect output: %v", err)
	}
	if len(networks) == 0 {
		t.Fatal("expected at least one network in inspect output")
	}
	if got, _ := networks[0]["Name"].(string); got != name {
		t.Errorf("expected network name %q, got %q", name, got)
	}

	// Remove
	dockerRun(t, "network", "rm", name)

	// Verify gone
	cmd := dockerCmd("network", "inspect", name)
	if err := cmd.Run(); err == nil {
		t.Error("expected network inspect to fail after rm, but it succeeded")
	}
}

func TestNetworkList(t *testing.T) {
	name := "test-netls-" + randomSuffix()

	dockerRun(t, "network", "create", name)
	defer dockerCmd("network", "rm", name).Run()

	out := dockerRun(t, "network", "ls")
	if !strings.Contains(out, name) {
		t.Errorf("expected %q in network ls output, got: %s", name, out)
	}
}

func TestNetworkListIncludesBridge(t *testing.T) {
	out := dockerRun(t, "network", "ls")
	if !strings.Contains(out, "bridge") {
		t.Errorf("expected 'bridge' in network ls output, got: %s", out)
	}
}

func TestNetworkPrune(t *testing.T) {
	name := "test-netpr-" + randomSuffix()

	dockerRun(t, "network", "create", name)

	// Prune unused networks.
	out := dockerRun(t, "network", "prune", "-f")
	t.Logf("network prune output: %s", out)

	// The network should be gone.
	cmd := dockerCmd("network", "inspect", name)
	if err := cmd.Run(); err == nil {
		t.Error("expected network inspect to fail after prune, but it succeeded")
	}
}

func TestRunWithNetwork(t *testing.T) {
	netName := "test-runnet-" + randomSuffix()
	name := "test-netrun-" + randomSuffix()

	// Create network.
	dockerRun(t, "network", "create", netName)
	defer dockerCmd("network", "rm", netName).Run()

	// Run a container on the network.
	out := dockerRun(t, "run", "--name", name, "--network", netName,
		"busybox", "echo", "hello-net")
	defer dockerCmd("rm", "-f", name).Run()

	if !strings.Contains(out, "hello-net") {
		t.Errorf("expected 'hello-net' in output, got: %s", out)
	}
}

func TestNetworkConnectDisconnect(t *testing.T) {
	netName := "test-connnet-" + randomSuffix()
	name := "test-conn-" + randomSuffix()

	// Create network and container.
	dockerRun(t, "network", "create", netName)
	defer dockerCmd("network", "rm", netName).Run()

	dockerRun(t, "create", "--name", name, "busybox", "sleep", "300")
	dockerRun(t, "start", name)
	defer dockerCmd("rm", "-f", name).Run()

	// Connect container to network.
	dockerRun(t, "network", "connect", netName, name)

	// Inspect network to verify container is connected.
	out := dockerRun(t, "network", "inspect", netName)
	if !strings.Contains(out, name) {
		t.Errorf("expected %q in network inspect after connect, got: %s", name, out)
	}

	// Disconnect.
	dockerRun(t, "network", "disconnect", netName, name)

	// Verify disconnected.
	out = dockerRun(t, "network", "inspect", netName)
	var networks []map[string]any
	if err := json.Unmarshal([]byte(out), &networks); err != nil {
		t.Fatalf("failed to parse inspect output: %v", err)
	}
	if len(networks) > 0 {
		containers, _ := networks[0]["Containers"].(map[string]any)
		if _, ok := containers[name]; ok {
			t.Errorf("container %q should not be in network after disconnect", name)
		}
	}
}

func TestRunWithNonexistentNetworkRejected(t *testing.T) {
	name := "test-nonet-" + randomSuffix()

	cmd := dockerCmd("run", "--name", name, "--network", "does-not-exist", "busybox", "true")
	out, err := cmd.CombinedOutput()
	defer dockerCmd("rm", "-f", name).Run()

	if err == nil {
		t.Error("expected run with nonexistent network to fail, but it succeeded")
	}
	t.Logf("output: %s", out)
}

func TestInspectShowsNetworkSettings(t *testing.T) {
	netName := "test-inspnet-" + randomSuffix()
	name := "test-netinsp-" + randomSuffix()

	dockerRun(t, "network", "create", netName)
	defer dockerCmd("network", "rm", netName).Run()

	dockerRun(t, "create", "--name", name, "--network", netName, "busybox", "sleep", "300")
	dockerRun(t, "start", name)
	defer dockerCmd("rm", "-f", name).Run()

	out := dockerRun(t, "inspect", name)
	var inspected []map[string]any
	if err := json.Unmarshal([]byte(out), &inspected); err != nil {
		t.Fatalf("failed to parse inspect output: %v", err)
	}
	if len(inspected) == 0 {
		t.Fatal("expected at least one inspect result")
	}

	netSettings, ok := inspected[0]["NetworkSettings"].(map[string]any)
	if !ok {
		t.Fatal("missing NetworkSettings in inspect output")
	}
	networks, ok := netSettings["Networks"].(map[string]any)
	if !ok {
		t.Fatal("missing Networks in NetworkSettings")
	}

	if _, ok := networks["bridge"]; !ok {
		t.Error("expected 'bridge' in NetworkSettings.Networks")
	}
	if _, ok := networks[netName]; !ok {
		t.Errorf("expected %q in NetworkSettings.Networks, got: %v", netName, networks)
	}
}

func TestNetworkConnectShowsInInspect(t *testing.T) {
	netName := "test-conninsp-" + randomSuffix()
	name := "test-conninsp-c-" + randomSuffix()

	dockerRun(t, "network", "create", netName)
	defer dockerCmd("network", "rm", netName).Run()

	// Create container WITHOUT --network, then connect after.
	dockerRun(t, "create", "--name", name, "busybox", "sleep", "300")
	dockerRun(t, "start", name)
	defer dockerCmd("rm", "-f", name).Run()

	dockerRun(t, "network", "connect", netName, name)

	// Container inspect should show the network.
	out := dockerRun(t, "inspect", name)
	var inspected []map[string]any
	if err := json.Unmarshal([]byte(out), &inspected); err != nil {
		t.Fatalf("failed to parse inspect output: %v", err)
	}
	netSettings, _ := inspected[0]["NetworkSettings"].(map[string]any)
	networks, _ := netSettings["Networks"].(map[string]any)
	if _, ok := networks[netName]; !ok {
		t.Errorf("expected %q in NetworkSettings.Networks after connect, got: %v", netName, networks)
	}

	// Network inspect should show the container.
	out = dockerRun(t, "network", "inspect", netName)
	if !strings.Contains(out, name) {
		t.Errorf("expected %q in network inspect after connect, got: %s", name, out)
	}
}

func TestContainerDNSViaHeadlessService(t *testing.T) {
	netName := "test-dns-" + randomSuffix()
	serverName := "test-dnssrv-" + randomSuffix()
	clientName := "test-dnscli-" + randomSuffix()

	dockerRun(t, "network", "create", netName)
	defer dockerCmd("network", "rm", netName).Run()

	// Start a "server" container on the network.
	dockerRun(t, "create", "--name", serverName, "--network", netName,
		"busybox", "sleep", "300")
	dockerRun(t, "start", serverName)
	defer dockerCmd("rm", "-f", serverName).Run()

	// Give the headless service a moment to register.
	time.Sleep(2 * time.Second)

	// Start a "client" container that tries to resolve the server by name.
	// nslookup will fail if DNS doesn't resolve, but the container itself
	// should at least run. We use getent which is available in busybox.
	out, _ := dockerCmd("run", "--name", clientName, "--network", netName,
		"busybox", "nslookup", serverName).CombinedOutput()
	defer dockerCmd("rm", "-f", clientName).Run()

	t.Logf("DNS lookup output: %s", out)
	// nslookup tries multiple search domains and may print "can't find" for
	// non-default domains even when the FQDN resolves successfully. So check
	// that the output contains a successful "Address" line for our service
	// (which means the FQDN resolved) rather than checking for absence of errors.
	outStr := string(out)
	lines := strings.Split(outStr, "\n")
	resolved := false
	for i, line := range lines {
		// nslookup output: the first "Address:" line is the DNS server itself.
		// Subsequent "Address:" lines are the resolution results.
		if strings.Contains(line, "Name:") && strings.Contains(line, serverName) {
			// The line after "Name:" should have "Address:" with the pod IP.
			if i+1 < len(lines) && strings.Contains(lines[i+1], "Address:") {
				resolved = true
			}
		}
	}
	if !resolved {
		t.Errorf("DNS resolution failed for %q: %s", serverName, outStr)
	}
}

func TestContainerPruneCleansUpFromNetwork(t *testing.T) {
	netName := "test-prunenet-" + randomSuffix()
	name := "test-prunec-" + randomSuffix()

	dockerRun(t, "network", "create", netName)
	defer dockerCmd("network", "rm", netName).Run()

	// Run a container on the network that exits immediately.
	dockerRun(t, "run", "--name", name, "--network", netName, "busybox", "true")

	// Wait for it to reach terminal state.
	time.Sleep(5 * time.Second)

	// Prune exited containers.
	dockerRun(t, "container", "prune", "-f")

	// The container should no longer appear in network inspect.
	out := dockerRun(t, "network", "inspect", netName)
	var networks []map[string]any
	if err := json.Unmarshal([]byte(out), &networks); err != nil {
		t.Fatalf("failed to parse inspect output: %v", err)
	}
	if len(networks) > 0 {
		containers, _ := networks[0]["Containers"].(map[string]any)
		if _, ok := containers[name]; ok {
			t.Errorf("container %q should not be in network after prune", name)
		}
	}
}

// --- Docker cp tests ---

func TestDockerCpFileToContainer(t *testing.T) {
	name := "test-cp-to-" + randomSuffix()

	dockerRun(t, "create", "--name", name, "busybox", "sleep", "300")
	dockerRun(t, "start", name)
	defer dockerCmd("rm", "-f", name).Run()

	// Create a local file and copy it into the container.
	tmpFile := filepath.Join(t.TempDir(), "hello.txt")
	if err := os.WriteFile(tmpFile, []byte("hello from cp\n"), 0644); err != nil {
		t.Fatal(err)
	}

	dockerRun(t, "cp", tmpFile, name+":/tmp/hello.txt")

	// Verify the file landed inside the container.
	out := dockerRun(t, "exec", name, "cat", "/tmp/hello.txt")
	if !strings.Contains(out, "hello from cp") {
		t.Errorf("expected 'hello from cp' in output, got: %s", out)
	}
}

func TestDockerCpFileFromContainer(t *testing.T) {
	name := "test-cp-from-" + randomSuffix()

	dockerRun(t, "create", "--name", name, "busybox", "sleep", "300")
	dockerRun(t, "start", name)
	defer dockerCmd("rm", "-f", name).Run()

	// Wait for the container to be fully running before exec.
	time.Sleep(2 * time.Second)

	// Create a file inside the container.
	dockerRun(t, "exec", name, "sh", "-c", "echo 'hello from container' > /tmp/output.txt")

	// Copy it out.
	outFile := filepath.Join(t.TempDir(), "output.txt")
	dockerRun(t, "cp", name+":/tmp/output.txt", outFile)

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read copied file: %v", err)
	}
	if !strings.Contains(string(data), "hello from container") {
		t.Errorf("expected 'hello from container', got: %s", data)
	}
}

func TestDockerCpDirectoryRoundTrip(t *testing.T) {
	name := "test-cp-dir-" + randomSuffix()

	dockerRun(t, "create", "--name", name, "busybox", "sleep", "300")
	dockerRun(t, "start", name)
	defer dockerCmd("rm", "-f", name).Run()

	// Create a local directory with files.
	srcDir := filepath.Join(t.TempDir(), "mydir")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("file a"), 0644)
	os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("file b"), 0644)

	// Copy directory into the container.
	dockerRun(t, "cp", srcDir, name+":/tmp/mydir")

	// Verify both files exist.
	out := dockerRun(t, "exec", name, "cat", "/tmp/mydir/a.txt")
	if !strings.Contains(out, "file a") {
		t.Errorf("expected 'file a', got: %s", out)
	}
	out = dockerRun(t, "exec", name, "cat", "/tmp/mydir/b.txt")
	if !strings.Contains(out, "file b") {
		t.Errorf("expected 'file b', got: %s", out)
	}

	// Copy directory back out and verify.
	outDir := filepath.Join(t.TempDir(), "out")
	dockerRun(t, "cp", name+":/tmp/mydir", outDir)

	data, err := os.ReadFile(filepath.Join(outDir, "a.txt"))
	if err != nil {
		t.Fatalf("failed to read a.txt: %v", err)
	}
	if !strings.Contains(string(data), "file a") {
		t.Errorf("expected 'file a', got: %s", data)
	}
	data, err = os.ReadFile(filepath.Join(outDir, "b.txt"))
	if err != nil {
		t.Fatalf("failed to read b.txt: %v", err)
	}
	if !strings.Contains(string(data), "file b") {
		t.Errorf("expected 'file b', got: %s", data)
	}
}

func TestDockerCpNoResourceLeak(t *testing.T) {
	name := "test-cp-leak-" + randomSuffix()

	dockerRun(t, "create", "--name", name, "busybox", "sleep", "300")
	dockerRun(t, "start", name)
	defer dockerCmd("rm", "-f", name).Run()

	// Perform a cp operation.
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	os.WriteFile(tmpFile, []byte("leak-test"), 0644)
	dockerRun(t, "cp", tmpFile, name+":/tmp/test.txt")

	// Wait for the cleanup to take effect.
	time.Sleep(3 * time.Second)

	// The main container should still be running (cp didn't break it).
	out := dockerRun(t, "inspect", "--format", "{{.State.Running}}", name)
	if !strings.Contains(out, "true") {
		t.Errorf("container should still be running after cp, got: %s", out)
	}

	// Verify there are no running cp-helper processes left inside the container.
	// In a shared PID namespace, the main container can see helper processes.
	// With targetContainerName (no shareProcessNamespace), the main container's
	// PID namespace is joined by the helper. After cleanup, the helper's sleep
	// should be gone. We check by listing processes visible to the main container.
	out = dockerRun(t, "exec", name, "sh", "-c", "ps aux 2>/dev/null || echo no-ps")
	t.Logf("processes after cp: %s", out)
	// ps might not be available in busybox, but if it is, verify no sleep 300 helper.
	if strings.Contains(out, "sleep 300") {
		t.Errorf("cp-helper sleep process still running after cleanup: %s", out)
	}
}

// randomSuffix returns a short suffix for unique container names.
func randomSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()%100000)
}

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/moby/moby/api/types/network"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	// networkLabelPrefix is the label prefix used to mark pods as members of a network.
	networkLabelPrefix = "badidea.network/"

	// networkConfigMapLabel identifies ConfigMaps that represent Docker networks.
	networkConfigMapLabel = "badidea.dev/network"

	// networkNS is the namespace used for network ConfigMaps.
	networkNS = "default"

	// defaultNetworkName is the default Docker bridge network.
	defaultNetworkName = "bridge"
)

// configMapToNetwork converts a ConfigMap to a Docker network inspect response.
func configMapToNetwork(cm *corev1.ConfigMap) network.Inspect {
	created := cm.CreationTimestamp.Time
	n := network.Inspect{
		Network: network.Network{
			Name:       cm.Name,
			ID:         cm.Name,
			Created:    created,
			Scope:      "local",
			Driver:     cm.Data["driver"],
			EnableIPv4: true,
			Internal:   cm.Data["internal"] == "true",
			Options:    map[string]string{},
			Labels:     map[string]string{},
		},
		Containers: map[string]network.EndpointResource{},
	}
	for k, v := range cm.Labels {
		if k != networkConfigMapLabel && k != labelApp {
			n.Labels[k] = v
		}
	}
	return n
}

// ensureDefaultNetwork creates the default "bridge" network ConfigMap if it doesn't exist.
func (s *Server) ensureDefaultNetwork(ctx context.Context) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultNetworkName,
			Namespace: networkNS,
			Labels: map[string]string{
				labelApp:              labelAppValue,
				networkConfigMapLabel: "true",
			},
		},
		Data: map[string]string{
			"driver": "bridge",
		},
	}
	_, err := s.clientset.CoreV1().ConfigMaps(networkNS).Create(ctx, cm, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		clog.FromContext(ctx).Warnf("failed to ensure default bridge network: %v", err)
	}
}

// --- Network endpoints ---

func (s *Server) networkList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clog.FromContext(ctx).Info("listing networks")

	s.ensureDefaultNetwork(ctx)

	cms, err := s.clientset.CoreV1().ConfigMaps(networkNS).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", networkConfigMapLabel),
	})
	if err != nil {
		writeError(w, err)
		return
	}

	pods, err := s.clientset.CoreV1().Pods(networkNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	networks := make([]network.Inspect, 0, len(cms.Items))
	for i := range cms.Items {
		n := configMapToNetwork(&cms.Items[i])
		for _, pod := range pods.Items {
			if podOnNetwork(&pod, cms.Items[i].Name) {
				n.Containers[pod.Name] = network.EndpointResource{
					Name: pod.Name,
				}
			}
		}
		networks = append(networks, n)
	}

	writeJSON(w, http.StatusOK, networks)
}

func (s *Server) networkCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req network.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"network name is required"})
		return
	}

	clog.FromContext(ctx).With("name", req.Name).Info("creating network")

	if req.Name == "host" {
		writeJSON(w, http.StatusForbidden, errorResponse{"host networking is not supported"})
		return
	}

	driver := req.Driver
	if driver == "" {
		driver = "bridge"
	}

	labels := map[string]string{
		labelApp:              labelAppValue,
		networkConfigMapLabel: "true",
	}
	for k, v := range req.Labels {
		labels[k] = v
	}

	data := map[string]string{
		"driver": driver,
	}
	if req.Internal {
		data["internal"] = "true"
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: networkNS,
			Labels:    labels,
		},
		Data: data,
	}

	_, err := s.clientset.CoreV1().ConfigMaps(networkNS).Create(ctx, cm, metav1.CreateOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, network.CreateResponse{
		ID:      req.Name,
		Warning: "",
	})
}

func (s *Server) networkInspect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	clog.FromContext(ctx).With("id", id).Info("inspecting network")

	if id == defaultNetworkName {
		s.ensureDefaultNetwork(ctx)
	}

	cm, err := s.clientset.CoreV1().ConfigMaps(networkNS).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		writeError(w, err)
		return
	}
	if cm.Labels[networkConfigMapLabel] != "true" {
		writeJSON(w, http.StatusNotFound, errorResponse{fmt.Sprintf("network %s not found", id)})
		return
	}

	n := configMapToNetwork(cm)

	pods, err := s.clientset.CoreV1().Pods(networkNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		writeError(w, err)
		return
	}
	for _, pod := range pods.Items {
		if podOnNetwork(&pod, id) {
			n.Containers[pod.Name] = network.EndpointResource{
				Name: pod.Name,
			}
		}
	}

	writeJSON(w, http.StatusOK, n)
}

func (s *Server) networkDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	clog.FromContext(ctx).With("id", id).Info("deleting network")

	if id == defaultNetworkName {
		writeJSON(w, http.StatusForbidden, errorResponse{"cannot remove default bridge network"})
		return
	}

	cm, err := s.clientset.CoreV1().ConfigMaps(networkNS).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		writeError(w, err)
		return
	}
	if cm.Labels[networkConfigMapLabel] != "true" {
		writeJSON(w, http.StatusNotFound, errorResponse{fmt.Sprintf("network %s not found", id)})
		return
	}

	if err := s.clientset.CoreV1().ConfigMaps(networkNS).Delete(ctx, id, metav1.DeleteOptions{}); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) networkPrune(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clog.FromContext(ctx).Info("pruning networks")

	cms, err := s.clientset.CoreV1().ConfigMaps(networkNS).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", networkConfigMapLabel),
	})
	if err != nil {
		writeError(w, err)
		return
	}

	pods, err := s.clientset.CoreV1().Pods(networkNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	inUse := map[string]bool{defaultNetworkName: true}
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending {
			for k := range pod.Labels {
				if name, ok := networkLabelName(k); ok {
					inUse[name] = true
				}
			}
		}
	}

	var deleted []string
	for _, cm := range cms.Items {
		if inUse[cm.Name] {
			continue
		}
		if err := s.clientset.CoreV1().ConfigMaps(networkNS).Delete(ctx, cm.Name, metav1.DeleteOptions{}); err == nil {
			deleted = append(deleted, cm.Name)
		}
	}

	writeJSON(w, http.StatusOK, network.PruneReport{
		NetworksDeleted: deleted,
	})
}

func (s *Server) networkConnect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req network.ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}

	clog.FromContext(ctx).With("network", id, "container", req.Container).Info("connecting container to network")

	if id == defaultNetworkName {
		s.ensureDefaultNetwork(ctx)
	}
	cm, err := s.clientset.CoreV1().ConfigMaps(networkNS).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		writeError(w, err)
		return
	}
	if cm.Labels[networkConfigMapLabel] != "true" {
		writeJSON(w, http.StatusNotFound, errorResponse{fmt.Sprintf("network %s not found", id)})
		return
	}

	pod, err := s.clientset.CoreV1().Pods(networkNS).Get(ctx, req.Container, metav1.GetOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels[networkLabelPrefix+id] = "true"
	// Ensure pod-name label exists so headless Service selectors work.
	if pod.Labels["badidea.dev/pod-name"] == "" {
		pod.Labels["badidea.dev/pod-name"] = pod.Name
	}

	if _, err := s.clientset.CoreV1().Pods(networkNS).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		writeError(w, err)
		return
	}

	// Create headless service for DNS.
	if err := s.ensureHeadlessService(ctx, pod.Name, pod.Name); err != nil {
		clog.FromContext(ctx).Warnf("failed to create headless service: %v", err)
	}

	// Create services for aliases.
	if req.EndpointConfig != nil {
		for _, alias := range req.EndpointConfig.Aliases {
			if err := s.ensureHeadlessService(ctx, alias, pod.Name); err != nil {
				clog.FromContext(ctx).Warnf("failed to create alias service %s: %v", alias, err)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) networkDisconnect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req network.DisconnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}

	clog.FromContext(ctx).With("network", id, "container", req.Container).Info("disconnecting container from network")

	pod, err := s.clientset.CoreV1().Pods(networkNS).Get(ctx, req.Container, metav1.GetOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	delete(pod.Labels, networkLabelPrefix+id)

	if _, err := s.clientset.CoreV1().Pods(networkNS).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		writeError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// --- Helpers ---

// networkLabelName extracts the network name from a label key like "badidea.network/mynet".
func networkLabelName(key string) (string, bool) {
	if strings.HasPrefix(key, networkLabelPrefix) {
		name := key[len(networkLabelPrefix):]
		if name == "" {
			return "", false
		}
		return name, true
	}
	return "", false
}

// podOnNetwork returns true if a pod is a member of the named network.
// All pods are implicitly on the "bridge" network.
func podOnNetwork(pod *corev1.Pod, networkName string) bool {
	if networkName == defaultNetworkName {
		return true
	}
	return pod.Labels[networkLabelPrefix+networkName] == "true"
}

// ensureHeadlessService creates a headless Service (ClusterIP: None) for DNS resolution.
func (s *Server) ensureHeadlessService(ctx context.Context, serviceName, podName string) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: networkNS,
			Labels: map[string]string{
				labelApp:                     labelAppValue,
				"badidea.dev/headless-for":   podName,
				"badidea.dev/service-reason": "dns",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Selector: map[string]string{
				"badidea.dev/pod-name": podName,
			},
			Ports: []corev1.ServicePort{{
				Port:     80,
				Protocol: corev1.ProtocolTCP,
			}},
		},
	}
	_, err := s.clientset.CoreV1().Services(networkNS).Create(ctx, svc, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// cleanupPodServices deletes headless/port-mapping Services created for a pod.
func (s *Server) cleanupPodServices(ctx context.Context, podName string) {
	svcs, err := s.clientset.CoreV1().Services(networkNS).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("badidea.dev/headless-for=%s", podName),
	})
	if err != nil {
		clog.FromContext(ctx).Warnf("failed to list services for pod %s: %v", podName, err)
		return
	}
	for _, svc := range svcs.Items {
		if err := s.clientset.CoreV1().Services(networkNS).Delete(ctx, svc.Name, metav1.DeleteOptions{}); err != nil {
			clog.FromContext(ctx).Warnf("failed to delete service %s: %v", svc.Name, err)
		}
	}
}

// createPortMappingService creates a ClusterIP Service for Docker -p port mappings.
func (s *Server) createPortMappingService(ctx context.Context, podName string, portMappings []portMapping) error {
	if len(portMappings) == 0 {
		return nil
	}

	var ports []corev1.ServicePort
	for i, pm := range portMappings {
		ports = append(ports, corev1.ServicePort{
			Name:       fmt.Sprintf("port-%d", i),
			Port:       int32(pm.hostPort),
			TargetPort: intstr.FromInt32(int32(pm.containerPort)),
			Protocol:   corev1.Protocol(pm.protocol),
		})
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-ports", podName),
			Namespace: networkNS,
			Labels: map[string]string{
				labelApp:                     labelAppValue,
				"badidea.dev/headless-for":   podName,
				"badidea.dev/service-reason": "ports",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"badidea.dev/pod-name": podName,
			},
			Ports: ports,
		},
	}
	_, err := s.clientset.CoreV1().Services(networkNS).Create(ctx, svc, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

type portMapping struct {
	hostPort      int
	containerPort int
	protocol      string
}

// parsePortProto parses "80/tcp" into port and protocol.
func parsePortProto(s string) (int, string) {
	proto := "TCP"
	portStr := s
	if idx := strings.LastIndex(s, "/"); idx > 0 {
		proto = strings.ToUpper(s[idx+1:])
		portStr = s[:idx]
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port, proto
}

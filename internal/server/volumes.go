package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/volume"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	labelApp       = "app"
	labelAppValue  = "badidea"
	defaultStorage = "1Gi"
	volumeNS       = "default"
)

var badideaLabels = map[string]string{labelApp: labelAppValue}

func pvcToVolume(pvc *corev1.PersistentVolumeClaim) volume.Volume {
	created := pvc.CreationTimestamp.Format(time.RFC3339)
	return volume.Volume{
		Name:       pvc.Name,
		Driver:     "local",
		Mountpoint: "/var/lib/badidea/volumes/" + pvc.Name,
		CreatedAt:  created,
		Status:     map[string]any{"phase": string(pvc.Status.Phase)},
		Labels:     pvc.Labels,
		Scope:      "local",
		Options:    map[string]string{},
	}
}

// --- Volume endpoints ---

func (s *Server) volumeList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clog.FromContext(ctx).Info("listing volumes")

	pvcs, err := s.clientset.CoreV1().PersistentVolumeClaims(volumeNS).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", labelApp, labelAppValue),
	})
	if err != nil {
		writeError(w, err)
		return
	}

	volumes := make([]volume.Volume, 0, len(pvcs.Items))
	for i := range pvcs.Items {
		volumes = append(volumes, pvcToVolume(&pvcs.Items[i]))
	}

	writeJSON(w, http.StatusOK, volume.ListResponse{
		Volumes:  volumes,
		Warnings: []string{},
	})
}

func (s *Server) volumeCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := clog.FromContext(ctx)

	var req volume.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"volume name is required"})
		return
	}
	log.With("name", req.Name).Info("creating volume")

	labels := make(map[string]string)
	for k, v := range badideaLabels {
		labels[k] = v
	}
	for k, v := range req.Labels {
		labels[k] = v
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: volumeNS,
			Labels:    labels,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(defaultStorage),
				},
			},
		},
	}

	created, err := s.clientset.CoreV1().PersistentVolumeClaims(volumeNS).Create(ctx, pvc, metav1.CreateOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, pvcToVolume(created))
}

func (s *Server) volumeInspect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	clog.FromContext(ctx).With("name", name).Info("inspecting volume")

	pvc, err := s.clientset.CoreV1().PersistentVolumeClaims(volumeNS).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, pvcToVolume(pvc))
}

func (s *Server) volumeDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	clog.FromContext(ctx).With("name", name).Info("deleting volume")

	err := s.clientset.CoreV1().PersistentVolumeClaims(volumeNS).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) volumePrune(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clog.FromContext(ctx).Info("pruning volumes")

	pvcs, err := s.clientset.CoreV1().PersistentVolumeClaims(volumeNS).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", labelApp, labelAppValue),
	})
	if err != nil {
		writeError(w, err)
		return
	}

	pods, err := s.clientset.CoreV1().Pods(volumeNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		writeError(w, err)
		return
	}

	inUse := map[string]bool{}
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending {
			for _, vol := range pod.Spec.Volumes {
				if vol.PersistentVolumeClaim != nil {
					inUse[vol.PersistentVolumeClaim.ClaimName] = true
				}
			}
		}
	}

	var deleted []string
	var reclaimedBytes int64
	for _, pvc := range pvcs.Items {
		if inUse[pvc.Name] {
			continue
		}
		if err := s.clientset.CoreV1().PersistentVolumeClaims(volumeNS).Delete(ctx, pvc.Name, metav1.DeleteOptions{}); err == nil {
			deleted = append(deleted, pvc.Name)
			if q, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; ok {
				reclaimedBytes += q.Value()
			}
		}
	}

	writeJSON(w, http.StatusOK, volume.PruneReport{
		VolumesDeleted:  deleted,
		SpaceReclaimed: uint64(reclaimedBytes),
	})
}

// parseBinds parses HostConfig.Binds entries and returns pod volumes and container mounts.
// Format: "source:dest[:options]"
// If source starts with "/", it's a bind mount (unsupported).
// Otherwise, source is a named volume.
func parseBinds(binds []string) ([]corev1.Volume, []corev1.VolumeMount, error) {
	var volumes []corev1.Volume
	var mounts []corev1.VolumeMount

	for _, bind := range binds {
		parts := strings.SplitN(bind, ":", 3)
		if len(parts) < 2 {
			return nil, nil, fmt.Errorf("invalid bind mount spec: %s", bind)
		}
		source := parts[0]
		dest := parts[1]

		if strings.HasPrefix(source, "/") {
			return nil, nil, fmt.Errorf("bind mounts are not supported; use named volumes instead")
		}

		readOnly := false
		if len(parts) == 3 && strings.Contains(parts[2], "ro") {
			readOnly = true
		}

		volName := "vol-" + source
		volumes = append(volumes, corev1.Volume{
			Name: volName,
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: source,
					ReadOnly:  readOnly,
				},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{
			Name:      volName,
			MountPath: dest,
			ReadOnly:  readOnly,
		})
	}

	return volumes, mounts, nil
}

// parseDockerMounts parses HostConfig.Mounts entries.
func parseDockerMounts(mnts []mount.Mount) ([]corev1.Volume, []corev1.VolumeMount, error) {
	var volumes []corev1.Volume
	var mounts []corev1.VolumeMount

	for i, m := range mnts {
		switch m.Type {
		case mount.TypeVolume:
			if m.Source == "" {
				return nil, nil, fmt.Errorf("mount[%d]: volume source is required", i)
			}
			volName := "vol-" + m.Source
			volumes = append(volumes, corev1.Volume{
				Name: volName,
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: m.Source,
						ReadOnly:  m.ReadOnly,
					},
				},
			})
			mounts = append(mounts, corev1.VolumeMount{
				Name:      volName,
				MountPath: m.Target,
				ReadOnly:  m.ReadOnly,
			})
		case mount.TypeTmpfs:
			volName := fmt.Sprintf("tmpfs-%d", i)
			volumes = append(volumes, corev1.Volume{
				Name: volName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumMemory,
					},
				},
			})
			mounts = append(mounts, corev1.VolumeMount{
				Name:      volName,
				MountPath: m.Target,
			})
		case mount.TypeBind:
			return nil, nil, fmt.Errorf("bind mounts are not supported; use named volumes instead")
		default:
			return nil, nil, fmt.Errorf("mount[%d]: unsupported mount type %q", i, m.Type)
		}
	}

	return volumes, mounts, nil
}

// parseAnonymousVolumes creates emptyDir volumes for Config.Volumes entries
// that aren't already covered by Binds or Mounts.
func parseAnonymousVolumes(configVolumes map[string]struct{}, coveredPaths map[string]bool) ([]corev1.Volume, []corev1.VolumeMount) {
	var volumes []corev1.Volume
	var mounts []corev1.VolumeMount
	idx := 0
	for path := range configVolumes {
		if coveredPaths[path] {
			continue
		}
		volName := fmt.Sprintf("anon-%d", idx)
		idx++
		volumes = append(volumes, corev1.Volume{
			Name: volName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
		mounts = append(mounts, corev1.VolumeMount{
			Name:      volName,
			MountPath: path,
		})
	}
	return volumes, mounts
}

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"cloud.google.com/go/compute/metadata"
	gke "cloud.google.com/go/container/apiv1"
	gkepb "cloud.google.com/go/container/apiv1/containerpb"
	"github.com/chainguard-dev/clog"
	_ "github.com/chainguard-dev/clog/gcp/init"
	"github.com/imjasonh/badidea/internal/server"
	"github.com/sethvargo/go-envconfig"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var env = envconfig.MustProcess(context.Background(), &struct {
	ClusterName string `env:"CLUSTER_NAME"`
	Kubeconfig  string `env:"KUBECONFIG"`
}{})

func main() {
	ctx := context.Background()
	log := clog.FromContext(ctx)

	var cfg *rest.Config
	if env.Kubeconfig != "" {
		log.Infof("using kubeconfig: %s", env.Kubeconfig)
		var err error
		cfg, err = clientcmd.BuildConfigFromFlags("", env.Kubeconfig)
		if err != nil {
			log.Fatalf("failed to build config from kubeconfig: %v", err)
		}
	} else {
		cfg = gkeConfig(ctx)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("failed to create clientset: %v", err)
	}
	if _, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		log.Fatalf("failed to list namespaces: %v", err)
	}

	s := server.New(clientset, *cfg)

	log.Infof("listening on :8080")
	if err := http.ListenAndServe(":8080", s.Handler()); err != nil {
		log.Fatalf("listen and serve: %v", err)
	}
}

func gkeConfig(ctx context.Context) *rest.Config {
	log := clog.FromContext(ctx)

	if env.ClusterName == "" {
		log.Fatalf("CLUSTER_NAME is required when KUBECONFIG is not set")
	}

	region, err := metadata.Get("instance/region")
	if err != nil {
		log.Fatalf("failed to get region: %v", err)
	}
	region = region[strings.LastIndex(region, "/")+1:]
	project, err := metadata.ProjectID()
	if err != nil {
		log.Fatalf("failed to get project: %v", err)
	}

	log.Infof("project: %s, region: %s, cluster: %s", project, region, env.ClusterName)

	gkeclient, err := gke.NewClusterManagerClient(ctx)
	if err != nil {
		log.Fatalf("failed to create cluster client: %v", err)
	}
	cluster, err := gkeclient.GetCluster(ctx, &gkepb.GetClusterRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/clusters/%s", project, region, env.ClusterName),
	})
	if err != nil {
		log.Fatalf("failed to get cluster: %v", err)
	}
	cacert, err := base64.StdEncoding.DecodeString(cluster.MasterAuth.ClusterCaCertificate)
	if err != nil {
		log.Fatalf("failed to decode ca cert: %v", err)
	}

	cred, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		log.Fatalf("failed to get credentials: %v", err)
	}
	cfg := &rest.Config{
		Host:            cluster.Endpoint,
		TLSClientConfig: rest.TLSClientConfig{CAData: cacert},
	}
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return &oauth2.Transport{Source: cred.TokenSource, Base: rt}
	})
	return cfg
}

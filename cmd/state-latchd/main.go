package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/achirothmane/state-latch/internal/kubeadapter"
	"github.com/achirothmane/state-latch/internal/server"
)

func main() {
	var (
		listenAddress   = flag.String("listen-address", ":8443", "HTTP(S) listen address")
		kubeconfig      = flag.String("kubeconfig", "", "path to kubeconfig; empty uses in-cluster configuration")
		tlsCertFile     = flag.String("tls-cert-file", "", "server TLS certificate")
		tlsKeyFile      = flag.String("tls-key-file", "", "server TLS private key")
		clientCAFile    = flag.String("client-ca-file", "", "CA used to verify mTLS client certificates")
		authzFile       = flag.String("authz-file", "", "JSON principal/permission configuration")
		dataDir         = flag.String("data-dir", "/var/lib/state-latch", "durable local data directory for file backend")
		stateBackend    = flag.String("state-backend", "kubernetes", "shared state backend: kubernetes or file")
		stateNamespace  = flag.String("state-namespace", "kube-system", "namespace for shared Kubernetes state")
		enableMutations = flag.Bool("enable-mutations", false, "enable authenticated real node-drain execution")
		insecureReadOnly = flag.Bool("insecure-read-only", false, "allow HTTP without mTLS; mutations are forbidden")
	)
	flag.Parse()

	if *insecureReadOnly && *enableMutations {
		fatal("invalid configuration", fmt.Errorf("insecure-read-only cannot be combined with enable-mutations"))
	}

	kubeConfig, err := kubernetesConfig(*kubeconfig)
	if err != nil {
		fatal("load Kubernetes configuration", err)
	}

	var (
		adapter    *kubeadapter.Adapter
		store      kubeadapter.DrainCheckpointStore
		replay     server.ReplayGuard
		authorizer server.Authorizer
	)

	if *enableMutations {
		adapter, err = kubeadapter.NewForConfigWithExperimentalMutations(kubeConfig)
		if err != nil {
			fatal("create mutation-enabled Kubernetes adapter", err)
		}

		switch *stateBackend {
		case "kubernetes":
			client, err := kubernetes.NewForConfig(kubeConfig)
			if err != nil {
				fatal("create Kubernetes state client", err)
			}
			checkpointStore, err := kubeadapter.NewKubernetesDrainCheckpointStore(client, *stateNamespace)
			if err != nil {
				fatal("create shared checkpoint store", err)
			}
			replayGuard, err := server.NewKubernetesReplayGuard(client, *stateNamespace)
			if err != nil {
				fatal("create shared replay guard", err)
			}
			store = checkpointStore
			replay = replayGuard

		case "file":
			checkpointStore, err := kubeadapter.NewFileDrainCheckpointStore(filepath.Join(*dataDir, "checkpoints"))
			if err != nil {
				fatal("create checkpoint store", err)
			}
			replayGuard, err := server.NewFileReplayGuard(filepath.Join(*dataDir, "replay"))
			if err != nil {
				fatal("create replay guard", err)
			}
			store = checkpointStore
			replay = replayGuard

		default:
			fatal("invalid configuration", fmt.Errorf("unsupported state-backend %q", *stateBackend))
		}
	} else {
		adapter, err = kubeadapter.NewForConfig(kubeConfig)
		if err != nil {
			fatal("create Kubernetes adapter", err)
		}
	}

	requireAuthentication := !*insecureReadOnly
	var tlsConfigured bool
	if requireAuthentication {
		for name, value := range map[string]string{
			"tls-cert-file":  *tlsCertFile,
			"tls-key-file":   *tlsKeyFile,
			"client-ca-file": *clientCAFile,
			"authz-file":     *authzFile,
		} {
			if value == "" {
				fatal("invalid configuration", fmt.Errorf("%s is required unless insecure-read-only is set", name))
			}
		}

		authorizer, err = server.LoadMTLSAuthorizer(*authzFile)
		if err != nil {
			fatal("load API authorization policy", err)
		}
		tlsConfigured = true
	}

	api, err := server.New(adapter, store, server.Config{
		Policy: kubeadapter.NodeDrainPolicy{
			MaxEvidenceAge:             15 * time.Second,
			RequiredSourceCount:        1,
			MaxBlastRadius:             50,
			AuthorizationTTL:           5 * time.Second,
			EvictionObservationTimeout: 30 * time.Second,
			ExecutionLockNamespace:     "kube-system",
			ExecutionLockDuration:      30 * time.Second,
			IgnoreDaemonSets:           false,
			ForceUnmanagedPods:         false,
			DeleteEmptyDirData:         false,
		},
		MutationsEnabled:      *enableMutations,
		RequestTimeout:        15 * time.Second,
		MaxBodyBytes:          1 << 20,
		RequireAuthentication: requireAuthentication,
		Authorizer:            authorizer,
		ReplayGuard:           replay,
		AuditSink:             server.SlogAuditSink{},
	})
	if err != nil {
		fatal("create API server", err)
	}

	httpServer := &http.Server{
		Addr:              *listenAddress,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if tlsConfigured {
		clientCAPEM, err := os.ReadFile(*clientCAFile)
		if err != nil {
			fatal("read client CA", err)
		}
		tlsConfig, err := server.MutualTLSConfig(clientCAPEM)
		if err != nil {
			fatal("build mTLS configuration", err)
		}
		httpServer.TLSConfig = tlsConfig
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info(
			"StateLatch daemon listening",
			"address", *listenAddress,
			"mutations_enabled", *enableMutations,
			"authentication_required", requireAuthentication,
		)
		var serveErr error
		if tlsConfigured {
			serveErr = httpServer.ListenAndServeTLS(*tlsCertFile, *tlsKeyFile)
		} else {
			serveErr = httpServer.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- serveErr
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		if err != nil {
			fatal("serve HTTP", err)
		}
	case <-shutdownContext.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			fatal("shutdown HTTP server", err)
		}
		if err := <-errCh; err != nil {
			fatal("serve HTTP", err)
		}
	}
}

func kubernetesConfig(path string) (*rest.Config, error) {
	if path != "" {
		config, err := clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			return nil, fmt.Errorf("build kubeconfig: %w", err)
		}
		return config, nil
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("build in-cluster config: %w", err)
	}
	return config, nil
}

func fatal(message string, err error) {
	slog.Error(message, "error", err)
	os.Exit(1)
}

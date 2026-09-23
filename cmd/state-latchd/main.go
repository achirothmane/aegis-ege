package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/achirothmane/state-latch/internal/kubeadapter"
	"github.com/achirothmane/state-latch/internal/server"
)

func main() {
	var (
		listenAddress = flag.String("listen-address", ":8080", "HTTP listen address")
		kubeconfig    = flag.String("kubeconfig", "", "path to kubeconfig; empty uses in-cluster configuration")
	)
	flag.Parse()

	config, err := kubernetesConfig(*kubeconfig)
	if err != nil {
		fatal("load Kubernetes configuration", err)
	}

	adapter, err := kubeadapter.NewForConfig(config)
	if err != nil {
		fatal("create Kubernetes adapter", err)
	}

	api, err := server.New(adapter, nil, server.Config{
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
		MutationsEnabled: false,
		RequestTimeout:   15 * time.Second,
		MaxBodyBytes:     1 << 20,
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

	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("StateLatch daemon listening",
			"address", *listenAddress,
			"mutations_enabled", false,
		)
		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
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

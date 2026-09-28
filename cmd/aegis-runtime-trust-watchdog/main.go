//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/achirothmane/aegis-ege/internal/cliio"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	lifecycleDir := flag.String("lifecycle-dir", "", "durable workload lifecycle directory")
	deviceID := flag.String("device", "", "device id")
	workloadID := flag.String("workload", "", "workload id")
	activationPath := flag.String("activation", "", "signed Activation Receipt v2")
	hostKeyPath := flag.String("host-attestor-key", "", "host attestor private key (0600)")
	bpftoolPath := flag.String("bpftool", "", "bpftool path; empty resolves from PATH")
	capsuleMap := flag.String("capsule-map", kernelfabric.DefaultCapsuleMapPath, "pinned capsule map path")
	fenceMap := flag.String("fence-map", kernelfabric.DefaultFenceMapPath, "pinned fence map path")
	poll := flag.Duration("poll", 5*time.Second, "maximum interval for noticing lease renewal or lifecycle changes")
	out := flag.String("out", "runtime-trust-expiry-evidence.json", "signed expiry evidence output")
	flag.Parse()

	if *lifecycleDir == "" || *deviceID == "" || *workloadID == "" ||
		*activationPath == "" || *hostKeyPath == "" {
		fatalf("-lifecycle-dir, -device, -workload, -activation and -host-attestor-key are required")
	}
	if *poll <= 0 {
		fatalf("-poll must be positive")
	}

	activation, err := cliio.ReadJSON[kernelfabric.SignedWorkloadActivationReceipt](*activationPath)
	if err != nil {
		fatalf("read activation receipt: %v", err)
	}
	hostKey, err := kernelfabric.LoadEd25519PrivateKey(*hostKeyPath)
	if err != nil {
		fatalf("load host attestor key: %v", err)
	}
	kernelStore, err := kernelfabric.NewBPFToolStore(*bpftoolPath, *capsuleMap, *fenceMap)
	if err != nil {
		fatalf("open kernel enforcement store: %v", err)
	}
	store := kernelfabric.WorkloadLifecycleStore{Dir: *lifecycleDir}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for {
		state, exists, err := store.Read(*deviceID, *workloadID)
		if err != nil {
			fatalf("read lifecycle state: %v", err)
		}
		if !exists {
			fatalf("no lifecycle state exists for %s/%s", *deviceID, *workloadID)
		}
		if state.State != kernelfabric.LifecycleStateRunning {
			fmt.Printf("watchdog exit: lifecycle state is %s\n", state.State)
			return
		}
		if state.RuntimeTrustEpoch == 0 {
			fatalf("RUNNING lifecycle has no active runtime trust lease")
		}

		now := time.Now().UTC()
		clock, err := kernelfabric.CaptureBootClockSnapshot(now, kernelfabric.DefaultBootIDPath)
		if err != nil {
			fatalf("capture boot clock: %v", err)
		}
		remaining, expired, err := kernelfabric.RuntimeTrustWatchdogRemaining(state, clock)
		if err != nil {
			if errors.Is(err, kernelfabric.ErrRuntimeTrustBootChanged) {
				fatalf("boot identity changed; use orphaned RUNNING reconciliation instead")
			}
			fatalf("evaluate runtime trust deadline: %v", err)
		}

		if expired {
			evidence, fence, err := kernelfabric.EnforceCurrentRuntimeTrustExpiry(
				ctx,
				store,
				kernelfabric.Installer{Store: kernelStore},
				*deviceID,
				*workloadID,
				activation,
				hostKey,
				clock,
				now,
			)
			if errors.Is(err, kernelfabric.ErrRuntimeTrustDeadlineNotReached) {
				// A renewal won the lifecycle lock before containment. Re-read state.
				continue
			}
			if err != nil {
				fatalf("enforce runtime trust expiry: %v", err)
			}
			if err := cliio.WriteJSON(*out, evidence, 0o600); err != nil {
				fatalf("write runtime trust expiry evidence: %v", err)
			}
			fmt.Printf("runtime trust expired: lease_epoch=%d\n", evidence.Evidence.RuntimeTrustLeaseEpoch)
			fmt.Printf("kernel revocation epoch: %d -> %d\n",
				evidence.Evidence.KernelPreviousRevocationEpoch,
				fence.RevocationEpoch,
			)
			fmt.Printf("process state: %s\n", evidence.Evidence.ProcessState)
			fmt.Printf("artifact: %s\n", *out)
			return
		}

		wait := remaining
		if wait > *poll {
			wait = *poll
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			fmt.Println("runtime trust watchdog stopped")
			return
		case <-timer.C:
		}
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-runtime-trust-watchdog: "+format+"\n", args...)
	os.Exit(1)
}

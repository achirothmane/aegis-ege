//go:build linux

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/achirothmane/aegis-ege/internal/cliio"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func main() {
	deviceID := flag.String("device", "", "enrolled device id")
	workloadID := flag.String("workload", "", "stable workload id")
	specPath := flag.String("spec", "", "workload launch spec JSON")
	targetCgroup := flag.String("cgroup", "", "target cgroup v2 path")
	bootstrapDigest := flag.String("bootstrap-digest", "", "verified bootstrap receipt digest")
	out := flag.String("out", "workload-admission-request.json", "request output")
	flag.Parse()

	if *deviceID == "" || *workloadID == "" || *specPath == "" ||
		*targetCgroup == "" || *bootstrapDigest == "" {
		fatalf("-device, -workload, -spec, -cgroup and -bootstrap-digest are required")
	}
	spec, err := cliio.ReadJSON[kernelfabric.WorkloadLaunchSpec](*specPath)
	if err != nil {
		fatalf("read workload spec: %v", err)
	}
	cgroupID, err := kernelfabric.ResolveCgroupV2ID(*targetCgroup)
	if err != nil {
		fatalf("resolve target cgroup identity: %v", err)
	}
	req, err := kernelfabric.NewWorkloadAdmissionRequest(
		*deviceID,
		*workloadID,
		spec,
		*targetCgroup,
		cgroupID,
		*bootstrapDigest,
		time.Now().UTC(),
	)
	if err != nil {
		fatalf("%v", err)
	}
	if err := cliio.WriteJSON(*out, req, 0o600); err != nil {
		fatalf("write admission request: %v", err)
	}
	fmt.Printf("workload admission request: %s\n", *out)
	fmt.Printf("target cgroup id: %d\n", cgroupID)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-admission-request: "+format+"\n", args...)
	os.Exit(1)
}

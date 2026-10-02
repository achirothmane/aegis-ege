//go:build linux

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

type sourceFlags []string

func (s *sourceFlags) String() string { return strings.Join(*s, ",") }
func (s *sourceFlags) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	var sources sourceFlags
	var (
		cgroupPath = flag.String("cgroup", "", "target cgroup v2 path")
		allowed    = flag.String("allowed-labels", "0", "allowed egress label bitmask (decimal or 0x...)")
		bpffsRoot  = flag.String("bpffs-root", kernelfabric.DefaultTaintBPFFSRoot, "pinned taint BPF root used for kernel-observed source identity")
		output     = flag.String("out", "aegis-taint-activation-plan.json", "activation plan output")
	)
	flag.Var(&sources, "source", "sensitive regular file as ABSOLUTE_PATH=LABEL_MASK; repeatable")
	flag.Parse()

	if *cgroupPath == "" || len(sources) == 0 {
		fatalf("-cgroup and at least one -source are required")
	}
	allowedMask, err := strconv.ParseUint(strings.TrimSpace(*allowed), 0, 64)
	if err != nil {
		fatalf("parse -allowed-labels: %v", err)
	}

	plan := kernelfabric.TaintActivationPlan{
		CgroupPath:    *cgroupPath,
		AllowedLabels: allowedMask,
	}
	sourceLabels := make(map[kernelfabric.TaintFileKey]uint64)
	for _, raw := range sources {
		index := strings.LastIndex(raw, "=")
		if index <= 0 || index == len(raw)-1 {
			fatalf("invalid -source %q; expected ABSOLUTE_PATH=LABEL_MASK", raw)
		}
		path := raw[:index]
		maskText := raw[index+1:]
		mask, err := strconv.ParseUint(strings.TrimSpace(maskText), 0, 64)
		if err != nil || mask == 0 {
			fatalf("invalid label mask in -source %q", raw)
		}
		keys, err := kernelfabric.ResolveTaintFileKeysObserved(*bpffsRoot, path)
		if err != nil {
			fatalf("kernel-observe -source %q: %v", path, err)
		}
		for _, key := range keys {
			sourceLabels[key] |= mask
		}
	}
	keys := make([]kernelfabric.TaintFileKey, 0, len(sourceLabels))
	for key := range sourceLabels {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Device != keys[j].Device {
			return keys[i].Device < keys[j].Device
		}
		return keys[i].Inode < keys[j].Inode
	})
	for _, key := range keys {
		plan.Sources = append(plan.Sources, kernelfabric.TaintSourceBinding{
			File:   key,
			Labels: sourceLabels[key],
		})
	}

	if err := kernelfabric.WriteTaintActivationPlan(*output, plan); err != nil {
		fatalf("write activation plan: %v", err)
	}
	digest, err := kernelfabric.TaintActivationPlanDigest(plan)
	if err != nil {
		fatalf("digest activation plan: %v", err)
	}

	fmt.Printf("taint activation plan written to %s\n", *output)
	fmt.Printf("plan digest: %s\n", digest)
	fmt.Printf("sources: %d\n", len(plan.Sources))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "aegis-taint-plan: "+format+"\n", args...)
	os.Exit(1)
}

# Kernel enforcement adapter

This directory contains the first kernel adapter for Aegis-EGE's enforcement fabric.

It compiles two cgroup socket-address programs:

- `cgroup/connect4`
- `cgroup/connect6`

Both programs are fail-closed. Once attached to a protected cgroup, an outbound connect is allowed only when a matching DecisionCapsule and current scope fence agree on:

- boot instance;
- authority term;
- decision epoch;
- revocation epoch;
- local monotonic lease deadline;
- ALLOW decision.

The program first checks an exact destination scope and then a cgroup-wide wildcard scope.

## Build

```bash
make -C kernel/bpf
```

## Load and attach

Root privileges and a mounted bpffs are required:

```bash
sudo kernel/bpf/load.sh \
  kernel/bpf/build/aegis_connect.bpf.o \
  /sys/fs/cgroup/<protected-cgroup>
```

The loader pins programs under:

```text
/sys/fs/bpf/aegis-ege/programs
```

and maps under:

```text
/sys/fs/bpf/aegis-ege/maps
```

Userspace installs scope fences and DecisionCapsules through the pinned maps. The Go package `internal/kernelfabric` provides a bpftool-backed `KernelStore` for those updates.

This is the cgroup network adapter only. XDP and BPF-LSM are separate enforcement adapters and are not implied by this directory.

//go:build linux

package kernelfabric

import (
	"testing"

	"github.com/cilium/ebpf"
)

func validTaintCollectionSpecForTest() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"aegis_fperm": {
				Name:       "aegis_fperm",
				Type:       ebpf.LSM,
				AttachType: ebpf.AttachLSMMac,
			},
			"aegis_fork": {
				Name: "aegis_fork",
				Type: ebpf.RawTracepoint,
			},
			"aegis_tconn4": {
				Name:       "aegis_tconn4",
				Type:       ebpf.CGroupSockAddr,
				AttachType: ebpf.AttachCGroupInet4Connect,
			},
			"aegis_tconn6": {
				Name:       "aegis_tconn6",
				Type:       ebpf.CGroupSockAddr,
				AttachType: ebpf.AttachCGroupInet6Connect,
			},
		},
		Maps: map[string]*ebpf.MapSpec{
			"aegis_tsrc": {
				Name:       "aegis_tsrc",
				Type:       ebpf.Hash,
				KeySize:    16,
				ValueSize:  8,
				MaxEntries: 32768,
			},
			"aegis_ftaint": {
				Name:       "aegis_ftaint",
				Type:       ebpf.Hash,
				KeySize:    16,
				ValueSize:  8,
				MaxEntries: 65536,
			},
			"aegis_ptaint": {
				Name:       "aegis_ptaint",
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: 65536,
			},
			"aegis_tcgroups": {
				Name:       "aegis_tcgroups",
				Type:       ebpf.Hash,
				KeySize:    8,
				ValueSize:  4,
				MaxEntries: 4096,
			},
			"aegis_tallow": {
				Name:       "aegis_tallow",
				Type:       ebpf.Hash,
				KeySize:    8,
				ValueSize:  8,
				MaxEntries: 4096,
			},
			"aegis_tfail": {
				Name:       "aegis_tfail",
				Type:       ebpf.Hash,
				KeySize:    8,
				ValueSize:  8,
				MaxEntries: 4096,
			},
			"aegis_tevents": {
				Name:       "aegis_tevents",
				Type:       ebpf.RingBuf,
				MaxEntries: 1 << 20,
			},
			"aegis_tacct": {
				Name:       "aegis_tacct",
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  TaintAccountingSize,
				MaxEntries: 1,
			},
		},
	}
}

func TestValidateTaintCollectionSpecExact(t *testing.T) {
	spec := validTaintCollectionSpecForTest()
	if err := validateTaintCollectionSpec(spec); err != nil {
		t.Fatal(err)
	}

	spec = validTaintCollectionSpecForTest()
	spec.Programs["aegis_tconn4"].AttachType = ebpf.AttachCGroupInet6Connect
	if err := validateTaintCollectionSpec(spec); err == nil {
		t.Fatal("wrong IPv4 connect attach type accepted")
	}

	spec = validTaintCollectionSpecForTest()
	spec.Maps["aegis_ptaint"].ValueSize = 16
	if err := validateTaintCollectionSpec(spec); err == nil {
		t.Fatal("wrong process taint map ABI accepted")
	}

	spec = validTaintCollectionSpecForTest()
	spec.Programs["extra"] = &ebpf.ProgramSpec{Name: "extra", Type: ebpf.SocketFilter}
	if err := validateTaintCollectionSpec(spec); err == nil {
		t.Fatal("program surface expansion accepted")
	}
}

package kernelfabric

import "testing"

func TestTaintActivationPlanDigestIsOrderIndependent(t *testing.T) {
	a := TaintActivationPlan{
		CgroupPath:    "/sys/fs/cgroup/aegis",
		AllowedLabels: 0,
		Sources: []TaintSourceBinding{
			{Path: "/var/lib/aegis/source-b", File: TaintFileKey{Device: 8, Inode: 22}, Labels: 1 << 3},
			{Path: "/var/lib/aegis/source-a", File: TaintFileKey{Device: 8, Inode: 11}, Labels: 1 << 0},
		},
	}
	b := TaintActivationPlan{
		CgroupPath:    "/sys/fs/cgroup/aegis",
		AllowedLabels: 0,
		Sources: []TaintSourceBinding{
			{Path: "/var/lib/aegis/source-a", File: TaintFileKey{Device: 8, Inode: 11}, Labels: 1 << 0},
			{Path: "/var/lib/aegis/source-b", File: TaintFileKey{Device: 8, Inode: 22}, Labels: 1 << 3},
		},
	}
	da, err := TaintActivationPlanDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := TaintActivationPlanDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("digest differs by source order: %s != %s", da, db)
	}
}

func TestTaintActivationPlanDigestBindsSourcePath(t *testing.T) {
	base := TaintActivationPlan{
		CgroupPath: "/sys/fs/cgroup/aegis",
		Sources: []TaintSourceBinding{
			{
				Path:   "/var/lib/aegis/source-a",
				File:   TaintFileKey{Device: 8, Inode: 11},
				Labels: 1,
			},
		},
	}
	first, err := TaintActivationPlanDigest(base)
	if err != nil {
		t.Fatal(err)
	}

	mutated := base
	mutated.Sources = append([]TaintSourceBinding(nil), base.Sources...)
	mutated.Sources[0].Path = "/var/lib/aegis/source-b"
	second, err := TaintActivationPlanDigest(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("source path mutation did not change activation plan digest")
	}
}

func TestTaintActivationPlanRejectsDuplicatesAndEmptyLabels(t *testing.T) {
	base := TaintActivationPlan{
		CgroupPath: "/sys/fs/cgroup/aegis",
		Sources: []TaintSourceBinding{
			{Path: "/var/lib/aegis/source-a", File: TaintFileKey{Device: 8, Inode: 11}, Labels: 1},
		},
	}
	if err := ValidateTaintActivationPlan(base); err != nil {
		t.Fatal(err)
	}

	duplicate := base
	duplicate.Sources = append(append([]TaintSourceBinding(nil), base.Sources...), base.Sources[0])
	if err := ValidateTaintActivationPlan(duplicate); err == nil {
		t.Fatal("duplicate source identity accepted")
	}

	empty := base
	empty.Sources = []TaintSourceBinding{{Path: "/var/lib/aegis/source-a", File: TaintFileKey{Device: 8, Inode: 11}}}
	if err := ValidateTaintActivationPlan(empty); err == nil {
		t.Fatal("zero source label set accepted")
	}
}

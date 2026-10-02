package taintflow

import (
	"errors"
	"reflect"
	"testing"
)

func TestForkCopiesAllParentTaints(t *testing.T) {
	tracker, err := New("monitor:synthetic-taintflow", "epoch-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.RegisterProcess("process:parent"); err != nil {
		t.Fatal(err)
	}
	if err := tracker.TaintProcess("process:parent", "user.private"); err != nil {
		t.Fatal(err)
	}
	if err := tracker.TaintProcess("process:parent", "tenant.secret"); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Fork("process:parent", "process:child"); err != nil {
		t.Fatal(err)
	}

	child, err := tracker.Observation("process:child")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tenant.secret", "user.private"}
	if !reflect.DeepEqual(child.Labels, want) {
		t.Fatalf("child taints=%v; want=%v", child.Labels, want)
	}
}

func TestFileOrIPCTransferPropagatesTaintMonotonically(t *testing.T) {
	tracker, err := New("monitor:synthetic-taintflow", "epoch-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, process := range []string{"process:writer", "process:reader"} {
		if err := tracker.RegisterProcess(process); err != nil {
			t.Fatal(err)
		}
	}
	if err := tracker.TaintProcess("process:writer", "user.private"); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Write("process:writer", "channel:/tmp/bridge"); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Read("process:reader", "channel:/tmp/bridge"); err != nil {
		t.Fatal(err)
	}

	reader, err := tracker.Observation("process:reader")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reader.Labels, []string{"user.private"}) {
		t.Fatalf("reader taints=%v", reader.Labels)
	}

	// A later clean writer cannot erase already propagated channel taint.
	if err := tracker.RegisterProcess("process:clean"); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Write("process:clean", "channel:/tmp/bridge"); err != nil {
		t.Fatal(err)
	}
	channel, err := tracker.ChannelLabels("channel:/tmp/bridge")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(channel, []string{"user.private"}) {
		t.Fatalf("channel taints were cleared: %v", channel)
	}
}

func TestTrackerRejectsUnknownLineage(t *testing.T) {
	tracker, err := New("monitor:synthetic-taintflow", "epoch-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.RegisterProcess("process:p1"); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Fork("process:missing", "process:child"); !errors.Is(err, ErrUnknownProcess) {
		t.Fatalf("fork error=%v", err)
	}
	if err := tracker.Read("process:p1", "channel:missing"); !errors.Is(err, ErrUnknownChannel) {
		t.Fatalf("read error=%v", err)
	}
}

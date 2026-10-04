package simulation

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

type noCustodyProcessInput struct {
	Request   r.Request
	Admission v.Envelope
	Policy    v.Policy
	Withheld  bool
}

// Only the independent caller supplies the claim/request inputs. The executor
// has no surviving input file or checkpoint. Its process environment disappears
// on abrupt exit; the destination's atomic completion is the retained cause.
func TestPostgresCompositeNoCustodyProcess(t *testing.T) {
	mode := os.Getenv("NO_CUSTODY_MODE")
	if mode == "" {
		return
	}
	var input noCustodyProcessInput
	if err := json.Unmarshal([]byte(os.Getenv("NO_CUSTODY_INPUT")), &input); err != nil {
		t.Fatal(err)
	}
	db, err := openDB(os.Getenv("NO_CUSTODY_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if mode == "observe" {
		d, err := observeWithoutCustody(ctx, db, input.Request, input.Withheld)
		if err != nil {
			t.Fatal(err)
		}
		_, mutationErr := db.Exec("UPDATE " + nativeFenceTable("target_state") + " SET digest=digest")
		if err := json.NewEncoder(os.Stdout).Encode(struct {
			Destination    v.Destination
			MutationDenied bool
			PID            int
		}{d, mutationErr != nil && strings.Contains(mutationErr.Error(), "permission denied"), os.Getpid()}); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	barrier := func(name string, code int) {
		fmt.Fprintln(os.Stdout, name)
		var release [1]byte
		if _, err := io.ReadFull(os.Stdin, release[:]); err != nil {
			os.Exit(101)
		}
		os.Exit(code)
	}
	var beforeCommit func() error
	if mode == "pre-commit" {
		beforeCommit = func() error {
			barrier("NO_CUSTODY_UNCOMMITTED", 99)
			return nil
		}
	} else if mode != "post-commit" {
		t.Fatal("unknown native no-custody process mode")
	}
	if err := executeWithoutCustody(ctx, db, input.Request, input.Admission, input.Policy, beforeCommit); err != nil {
		t.Fatal(err)
	}
	// The destination committed. No effect callback result reaches the caller.
	barrier("NO_CUSTODY_COMMITTED", 100)
}

func noCustodyCommand(t *testing.T, f *noCustodyFixture, mode, dsn string, withheld bool) (*exec.Cmd, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPostgresCompositeNoCustodyProcess$")
	input := noCustodyProcessInput{f.req, f.seal(t, "admission", f.admission(f.req, 1)), f.policy, withheld}
	raw, err := json.Marshal(input)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	// The recovery process receives only a read credential; all fixture private
	// keys remain in the caller. No COMPOSITE/admin credentials are inherited.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "NO_CUSTODY_MODE=" + mode, "NO_CUSTODY_DSN=" + dsn, "NO_CUSTODY_INPUT=" + string(raw)}
	return cmd, cancel
}

func noCustodyCrash(t *testing.T, f *noCustodyFixture, preCommit bool) {
	t.Helper()
	mode, marker, code := "post-commit", "NO_CUSTODY_COMMITTED", 100
	if preCommit {
		mode, marker, code = "pre-commit", "NO_CUSTODY_UNCOMMITTED", 99
	}
	cmd, cancel := noCustodyCommand(t, f, mode, os.Getenv("GOSMIG_SIM_ADMIN_DSN"), false)
	defer cancel()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	select {
	case line := <-ready:
		if line != marker {
			t.Fatalf("native no-custody barrier failed: %q %s", line, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("native no-custody barrier timed out")
	}
	if preCommit && f.tally(t) != 0 || !preCommit && f.tally(t) != 1 {
		t.Fatal("native transaction visibility violated the crash boundary")
	}
	if _, err := stdin.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	err = cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != code {
		t.Fatalf("native no-custody process did not die at the required boundary: %v %s", err, stderr.String())
	}
}

func noCustodyReadProcess(t *testing.T, f *noCustodyFixture, withheld bool) v.Destination {
	t.Helper()
	cmd, cancel := noCustodyCommand(t, f, "observe", compositeReadDSN(t, f.a), withheld)
	defer cancel()
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("fresh native observer failed: %v %s", err, raw)
	}
	var result struct {
		Destination    v.Destination
		MutationDenied bool
		PID            int
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !result.MutationDenied || result.PID == os.Getpid() || result.PID <= 0 {
		t.Fatal("native recovery lost process or mutation-authority separation")
	}
	return result.Destination
}

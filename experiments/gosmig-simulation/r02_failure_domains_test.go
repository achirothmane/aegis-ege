package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type r02ProviderAEffect struct {
	ActionRef string `json:"action_ref"`
	Amount    int64  `json:"amount"`
	APIValue  string `json:"api_value"`
}

type r02ProviderAState struct {
	Effects map[string]r02ProviderAEffect `json:"effects"`
}

type r02Shipment struct {
	ActionRef string `json:"action_ref"`
	Fence     int64  `json:"fence"`
}

type r02ProviderBState struct {
	HighestFence int64                  `json:"highest_fence"`
	Shipments    map[string]r02Shipment `json:"shipments"`
}

type r02Evidence struct {
	SchemaVersion  string `json:"schema_version"`
	ActionRef      string `json:"action_ref"`
\tAmount         int64  `json:"amount"`\n	FailureDomains struct {
		E1       string `json:"e1"`
		E2       string `json:"e2"`
		E3       string `json:"e3"`
		Distinct bool   `json:"distinct"`
	} `json:"failure_domains"`
	E1 struct {
		EffectID   string `json:"effect_id"`
		FinalState string `json:"final_state"`
	} `json:"e1"`
	E2 struct {
		EffectID                string   `json:"effect_id"`
		LostAckExit             int      `json:"lost_ack_exit"`
		UnavailableAfterExit    bool     `json:"unavailable_after_exit"`
		BAliveDuringAPartition  bool     `json:"b_alive_during_a_partition"`
		ObservedAfterRestart    string   `json:"observed_after_restart"`
		WebhookEventIDs         []string `json:"webhook_event_ids"`
		WebhookValues           []string `json:"webhook_values"`
		APIValue                string   `json:"api_value"`
		UnrelatedEffectID       string   `json:"unrelated_effect_id"`
		AggregateCapturedAmount int64    `json:"aggregate_captured_amount"`
	} `json:"e2"`
	Authority struct {
		OldFence     int64 `json:"old_fence"`
		CurrentFence int64 `json:"current_fence"`
	} `json:"authority"`
	E3 struct {
		EffectID             string `json:"effect_id"`
		StaleStatus          int    `json:"stale_status"`
		TargetDurableRows    int    `json:"target_durable_rows"`
		ControlStatus        int    `json:"control_status"`
		ControlDuplicateCode int    `json:"control_duplicate_code"`
		ControlDurableRows   int    `json:"control_durable_rows"`
	} `json:"e3"`
	ExactPostcondition bool `json:"exact_postcondition"`
}

func saveJSONSync(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadProviderA(path string) (r02ProviderAState, error) {
	st := r02ProviderAState{Effects: map[string]r02ProviderAEffect{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(data, &st)
	if st.Effects == nil {
		st.Effects = map[string]r02ProviderAEffect{}
	}
	return st, err
}

func loadProviderB(path string) (r02ProviderBState, error) {
	st := r02ProviderBState{Shipments: map[string]r02Shipment{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(data, &st)
	if st.Shipments == nil {
		st.Shipments = map[string]r02Shipment{}
	}
	return st, err
}

func TestR02ProviderHelperProcess(t *testing.T) {
	role := os.Getenv("R02_HELPER_ROLE")
	if role == "" {
		return
	}
	store := os.Getenv("R02_STORE")
	ready := os.Getenv("R02_READY")
	if store == "" || ready == "" {
		os.Exit(70)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(71)
	}
	baseURL := "http://" + ln.Addr().String()
	if err := os.WriteFile(ready, []byte(baseURL), 0600); err != nil {
		os.Exit(72)
	}

	mux := http.NewServeMux()
	switch role {
	case "provider-a":
		var mu sync.Mutex
		mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/capture", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			st, err := loadProviderA(store)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			amount, _ := strconv.ParseInt(r.URL.Query().Get("amount"), 10, 64)
			effect := r.URL.Query().Get("effect")
			st.Effects[effect] = r02ProviderAEffect{
				ActionRef: r.URL.Query().Get("action"),
				Amount:    amount,
				APIValue:  "CAPTURED",
			}
			if err := saveJSONSync(store, st); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if r.URL.Query().Get("lose_ack") == "1" {
				hj, ok := w.(http.Hijacker)
				if !ok {
					os.Exit(73)
				}
				conn, _, err := hj.Hijack()
				if err == nil {
					_ = conn.Close()
				}
				go func() {
					time.Sleep(10 * time.Millisecond)
					os.Exit(94)
				}()
				return
			}
			w.WriteHeader(http.StatusCreated)
		})
		mux.HandleFunc("/effect", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			st, err := loadProviderA(store)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			e, ok := st.Effects[r.URL.Query().Get("effect")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(e)
		})
		mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			st, err := loadProviderA(store)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			effect := r.URL.Query().Get("effect")
			e, ok := st.Effects[effect]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"event_id": "evt-" + strings.ReplaceAll(effect, ":", "-"),
				"value":    "CAPTURED",
				"action":   e.ActionRef,
			})
		})
		mux.HandleFunc("/override", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			st, err := loadProviderA(store)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			effect := r.URL.Query().Get("effect")
			e, ok := st.Effects[effect]
			if !ok {
				http.NotFound(w, r)
				return
			}
			e.APIValue = r.URL.Query().Get("value")
			st.Effects[effect] = e
			if err := saveJSONSync(store, st); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/aggregate", func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			st, err := loadProviderA(store)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var sum int64
			for _, e := range st.Effects {
				if e.APIValue == "CAPTURED" {
					sum += e.Amount
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]int64{"captured_amount": sum})
		})
	case "provider-b":
		var mu sync.Mutex
		mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/advance-fence", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			st, err := loadProviderB(store)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fence, _ := strconv.ParseInt(r.URL.Query().Get("fence"), 10, 64)
			if fence > st.HighestFence {
				st.HighestFence = fence
			}
			if err := saveJSONSync(store, st); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/ship", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			st, err := loadProviderB(store)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fence, _ := strconv.ParseInt(r.URL.Query().Get("fence"), 10, 64)
			if fence < st.HighestFence {
				http.Error(w, "STALE_FENCE", http.StatusConflict)
				return
			}
			if fence > st.HighestFence {
				st.HighestFence = fence
			}
			effect := r.URL.Query().Get("effect")
			if _, exists := st.Shipments[effect]; exists {
				w.Header().Set("X-Created", "false")
				w.WriteHeader(http.StatusOK)
				return
			}
			st.Shipments[effect] = r02Shipment{ActionRef: r.URL.Query().Get("action"), Fence: fence}
			if err := saveJSONSync(store, st); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("X-Created", "true")
			w.WriteHeader(http.StatusCreated)
		})
	default:
		os.Exit(74)
	}

	srv := &http.Server{Handler: mux}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		os.Exit(75)
	}
}

type r02ProviderProcess struct {
	cmd     *exec.Cmd
	baseURL string
	store   string
	role    string
}

func startR02Provider(t *testing.T, role, store string) r02ProviderProcess {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	exe, err := os.Executable()
	must(t, err)
	cmd := exec.Command(exe, "-test.run=^TestR02ProviderHelperProcess$")
	cmd.Env = append(os.Environ(),
		"R02_HELPER_ROLE="+role,
		"R02_STORE="+store,
		"R02_READY="+ready,
	)
	must(t, cmd.Start())
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(ready)
		if err == nil && len(data) > 0 {
			return r02ProviderProcess{cmd: cmd, baseURL: string(data), store: store, role: role}
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	t.Fatalf("%s did not become ready", role)
	return r02ProviderProcess{}
}

func stopR02Provider(p r02ProviderProcess) {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
}

func r02GET(client *http.Client, raw string, out any) (int, error) {
	resp, err := client.Get(raw)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func r02POST(client *http.Client, raw string) (int, http.Header, error) {
	req, err := http.NewRequest(http.MethodPost, raw, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Clone(), nil
}

func TestR02IndependentFailureDomainsWholeTrace(t *testing.T) {
	if os.Getenv("GOSMIG_SIM_ADMIN_DSN") == "" {
		t.Fatal("R02 requires isolated PostgreSQL plus independent provider processes")
	}
	const (
		actionRef = "action:r02:fulfill-order-731"
		e1        = "effect:r02:e1"
		e2        = "effect:r02:e2"
		e3        = "effect:r02:e3"
		unrelated = "effect:r02:semantic-aba-unrelated"
		controlE3 = "effect:r02:e3-control"
		amount    = int64(73100)
	)
	client := &http.Client{Timeout: 2 * time.Second}

	root, err := openDB(roleDSN(t, "", "public"))
	must(t, err)
	defer root.Close()
	initRoles(t, root)
	const schema = "gs_r02_failure_domains"
	db := initSchema(t, schema)
	_, err = db.Exec(`CREATE TABLE r02_inventory(effect_id TEXT PRIMARY KEY, action_ref TEXT NOT NULL, state TEXT NOT NULL)`)
	must(t, err)
	_, err = db.Exec(`INSERT INTO r02_inventory(effect_id,action_ref,state) VALUES ($1,$2,'RESERVED')`, e1, actionRef)
	must(t, err)

	aStore := filepath.Join(t.TempDir(), "provider-a.json")
	bStore := filepath.Join(t.TempDir(), "provider-b.json")
	providerA := startR02Provider(t, "provider-a", aStore)
	providerB := startR02Provider(t, "provider-b", bStore)
	defer stopR02Provider(providerB)

	// E2 crosses a real process/network boundary. Provider A durably accepts
	// then terminates before the acknowledgement reaches the caller.
	captureURL := providerA.baseURL + "/capture?effect=" + url.QueryEscape(e2) +
		"&action=" + url.QueryEscape(actionRef) +
		"&amount=" + strconv.FormatInt(amount, 10) + "&lose_ack=1"
	_, _, captureErr := r02POST(client, captureURL)
	if captureErr == nil {
		t.Fatal("lost-ack schedule unexpectedly returned a normal HTTP response")
	}
	aExit := exitCode(providerA.cmd.Wait())
	if aExit != 94 {
		t.Fatalf("provider A exit=%d want=94", aExit)
	}

	// A is unavailable, while B remains independently available.
	_, aHealthErr := r02GET(client, providerA.baseURL+"/health", nil)
	bHealth, bHealthErr := r02GET(client, providerB.baseURL+"/health", nil)
	if aHealthErr == nil || bHealthErr != nil || bHealth != http.StatusOK {
		t.Fatalf("failure-domain separation not demonstrated: aErr=%v bStatus=%d bErr=%v", aHealthErr, bHealth, bHealthErr)
	}

	// Authority takeover advances the destination fence at provider B itself.
	const oldFence int64 = 1
	const currentFence int64 = 2
	status, _, err := r02POST(client, providerB.baseURL+"/advance-fence?fence=2")
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("advance provider-B fence: status=%d err=%v", status, err)
	}

	// Stale E3 reaches a separate provider boundary and is rejected there.
	staleURL := providerB.baseURL + "/ship?effect=" + url.QueryEscape(e3) +
		"&action=" + url.QueryEscape(actionRef) +
		"&fence=" + strconv.FormatInt(oldFence, 10)
	staleStatus, _, err := r02POST(client, staleURL)
	if err != nil {
		t.Fatal(err)
	}
	if staleStatus != http.StatusConflict {
		t.Fatalf("stale provider-B mutation status=%d want=%d", staleStatus, http.StatusConflict)
	}

	// Restart provider A from its own durable store only.
	providerA = startR02Provider(t, "provider-a", aStore)
	defer stopR02Provider(providerA)
	var observed r02ProviderAEffect
	status, err = r02GET(client, providerA.baseURL+"/effect?effect="+url.QueryEscape(e2), &observed)
	if err != nil || status != http.StatusOK || observed.APIValue != "CAPTURED" {
		t.Fatalf("provider A did not recover accepted E2: status=%d err=%v observed=%+v", status, err, observed)
	}

	var webhook1, webhook2 map[string]string
	_, err = r02GET(client, providerA.baseURL+"/webhook?effect="+url.QueryEscape(e2), &webhook1)
	must(t, err)
	_, err = r02GET(client, providerA.baseURL+"/webhook?effect="+url.QueryEscape(e2), &webhook2)
	must(t, err)

	// E1 is independently reversed in PostgreSQL.
	_, err = db.Exec(`UPDATE r02_inventory SET state='REVERSED' WHERE effect_id=$1`, e1)
	must(t, err)

	// Provider A later contradicts its old webhook and semantic ABA makes the
	// aggregate look correct with a different effect identity.
	overrideURL := providerA.baseURL + "/override?effect=" + url.QueryEscape(e2) + "&value=NOT_CAPTURED"
	status, _, err = r02POST(client, overrideURL)
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("override E2 API state: status=%d err=%v", status, err)
	}
	unrelatedURL := providerA.baseURL + "/capture?effect=" + url.QueryEscape(unrelated) +
		"&action=" + url.QueryEscape("action:r02:unrelated") +
		"&amount=" + strconv.FormatInt(amount, 10)
	status, _, err = r02POST(client, unrelatedURL)
	if err != nil || status != http.StatusCreated {
		t.Fatalf("create semantic-ABA effect: status=%d err=%v", status, err)
	}
	var exact r02ProviderAEffect
	_, err = r02GET(client, providerA.baseURL+"/effect?effect="+url.QueryEscape(e2), &exact)
	must(t, err)
	var aggregate map[string]int64
	_, err = r02GET(client, providerA.baseURL+"/aggregate", &aggregate)
	must(t, err)

	// Clean provider-B control proves the independent boundary is useful and
	// enforces duplicate cardinality at the current fence.
	controlURL := providerB.baseURL + "/ship?effect=" + url.QueryEscape(controlE3) +
		"&action=" + url.QueryEscape("action:r02:control") +
		"&fence=" + strconv.FormatInt(currentFence, 10)
	controlStatus, controlHeader, err := r02POST(client, controlURL)
	if err != nil || controlStatus != http.StatusCreated || controlHeader.Get("X-Created") != "true" {
		t.Fatalf("provider-B clean control failed: status=%d created=%q err=%v", controlStatus, controlHeader.Get("X-Created"), err)
	}
	duplicateStatus, duplicateHeader, err := r02POST(client, controlURL)
	if err != nil || duplicateStatus != http.StatusOK || duplicateHeader.Get("X-Created") != "false" {
		t.Fatalf("provider-B duplicate control failed: status=%d created=%q err=%v", duplicateStatus, duplicateHeader.Get("X-Created"), err)
	}

	aState, err := loadProviderA(aStore)
	must(t, err)
	bState, err := loadProviderB(bStore)
	must(t, err)
	var e1State string
	must(t, db.QueryRow(`SELECT state FROM r02_inventory WHERE effect_id=$1`, e1).Scan(&e1State))

	ev := r02Evidence{SchemaVersion: "governed-action.r02-failure-domains/v1", ActionRef: actionRef, Amount: amount}
	ev.FailureDomains.E1 = "postgresql-service-container"
	ev.FailureDomains.E2 = "provider-a-http-process+durable-file"
	ev.FailureDomains.E3 = "provider-b-http-process+durable-file"
	ev.FailureDomains.Distinct = ev.FailureDomains.E1 != ev.FailureDomains.E2 &&
		ev.FailureDomains.E1 != ev.FailureDomains.E3 &&
		ev.FailureDomains.E2 != ev.FailureDomains.E3
	ev.E1.EffectID = e1
	ev.E1.FinalState = e1State
	ev.E2.EffectID = e2
	ev.E2.LostAckExit = aExit
	ev.E2.UnavailableAfterExit = aHealthErr != nil
	ev.E2.BAliveDuringAPartition = bHealthErr == nil && bHealth == http.StatusOK
	ev.E2.ObservedAfterRestart = observed.APIValue
	ev.E2.WebhookEventIDs = []string{webhook1["event_id"], webhook2["event_id"]}
	ev.E2.WebhookValues = []string{webhook1["value"], webhook2["value"]}
	ev.E2.APIValue = exact.APIValue
	ev.E2.UnrelatedEffectID = unrelated
	ev.E2.AggregateCapturedAmount = aggregate["captured_amount"]
	ev.Authority.OldFence = oldFence
	ev.Authority.CurrentFence = currentFence
	ev.E3.EffectID = e3
	ev.E3.StaleStatus = staleStatus
	if _, ok := bState.Shipments[e3]; ok {
		ev.E3.TargetDurableRows = 1
	}
	ev.E3.ControlStatus = controlStatus
	ev.E3.ControlDuplicateCode = duplicateStatus
	if _, ok := bState.Shipments[controlE3]; ok {
		ev.E3.ControlDurableRows = 1
	}
	ev.ExactPostcondition = e1State == "RESERVED" &&
		exact.APIValue == "CAPTURED" &&
		ev.E3.TargetDurableRows == 1

	if !ev.FailureDomains.Distinct ||
		ev.E1.FinalState != "REVERSED" ||
		ev.E2.LostAckExit != 94 ||
		!ev.E2.UnavailableAfterExit ||
		!ev.E2.BAliveDuringAPartition ||
		ev.E2.ObservedAfterRestart != "CAPTURED" ||
		len(ev.E2.WebhookEventIDs) != 2 ||
		ev.E2.WebhookEventIDs[0] != ev.E2.WebhookEventIDs[1] ||
		ev.E2.WebhookValues[0] != "CAPTURED" ||
		ev.E2.WebhookValues[1] != "CAPTURED" ||
		ev.E2.APIValue != "NOT_CAPTURED" ||
		ev.E2.AggregateCapturedAmount != amount ||
		ev.E2.UnrelatedEffectID == ev.E2.EffectID ||
		ev.E3.StaleStatus != http.StatusConflict ||
		ev.E3.TargetDurableRows != 0 ||
		ev.E3.ControlDurableRows != 1 ||
		ev.ExactPostcondition {
		t.Fatalf("R02 failure-domain facts drifted: %+v providerA=%+v", ev, aState)
	}

	if out := os.Getenv("GOSMIG_R02_EVIDENCE"); out != "" {
		must(t, saveJSONSync(out, ev))
	}
}

func r02ReadEvidence(path string) (r02Evidence, error) {
	var ev r02Evidence
	data, err := os.ReadFile(path)
	if err != nil {
		return ev, err
	}
	err = json.Unmarshal(data, &ev)
	return ev, err
}

var _ = context.Background
var _ = fmt.Sprintf

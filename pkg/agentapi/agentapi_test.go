package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tyler-lloyd/zora/internal/plantest"
	"github.com/tyler-lloyd/zora/pkg/plan"
)

// TestWirePlanRoundTrip sends every golden plan through JSON and back.
func TestWirePlanRoundTrip(t *testing.T) {
	for _, c := range plantest.Cases(t) {
		t.Run(c.Name, func(t *testing.T) {
			b, err := json.Marshal(EncodePlan(c.Plan))
			if err != nil {
				t.Fatal(err)
			}
			var w WirePlan
			if err := json.Unmarshal(b, &w); err != nil {
				t.Fatal(err)
			}
			got, err := w.Decode()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.Plan) {
				t.Fatalf("round trip changed the plan\nwant %+v\ngot  %+v", c.Plan, got)
			}
		})
	}
}

// TestWirePlanCoversPlan fails when a plan type gains (or loses) a field
// that its wire twin doesn't mirror, so a new field can't silently vanish
// between agent and plugin.
func TestWirePlanCoversPlan(t *testing.T) {
	pairs := []struct{ plan, wire any }{
		{plan.Plan{}, WirePlan{}},
		{plan.Device{}, WireDevice{}},
		{plan.DevicePeer{}, WirePeer{}},
	}
	for _, p := range pairs {
		pt, wt := reflect.TypeOf(p.plan), reflect.TypeOf(p.wire)
		var pf, wf []string
		for i := range pt.NumField() {
			pf = append(pf, pt.Field(i).Name+" "+pt.Field(i).Tag.Get("json"))
		}
		for i := range wt.NumField() {
			wf = append(wf, wt.Field(i).Name+" "+wt.Field(i).Tag.Get("json"))
		}
		if !reflect.DeepEqual(pf, wf) {
			t.Errorf("%s fields %v do not match %s fields %v: update EncodePlan/Decode", pt, pf, wt, wf)
		}
	}
}

func TestDecodeRejectsBadKeysWithoutEchoingThem(t *testing.T) {
	const almostKey = "KZKC22QUVCRS52irjCHVv2MX/QI/lHAsVKW1m1J/s9"
	w := &WirePlan{Device: WireDevice{PrivateKey: almostKey}}
	_, err := w.Decode()
	if err == nil || strings.Contains(err.Error(), almostKey[:10]) {
		t.Fatalf("Decode() = %v; want an error that does not echo the key", err)
	}
}

// fakeHandler records calls and returns canned answers.
type fakeHandler struct {
	mu       sync.Mutex
	resolve  func(ResolveRequest) (*ResolveResponse, error)
	reports  []ReportRequest
	healthy  error
	resolved []ResolveRequest
}

func (f *fakeHandler) Resolve(_ context.Context, req ResolveRequest) (*ResolveResponse, error) {
	f.mu.Lock()
	f.resolved = append(f.resolved, req)
	f.mu.Unlock()
	return f.resolve(req)
}

func (f *fakeHandler) Report(_ context.Context, req ReportRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, req)
	return nil
}

func (f *fakeHandler) Healthy(context.Context) error { return f.healthy }

func serve(t *testing.T, h Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "run", "zora.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(h)
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestResolveRoundTrip(t *testing.T) {
	gc := plantest.Cases(t)[0]
	h := &fakeHandler{resolve: func(req ResolveRequest) (*ResolveResponse, error) {
		if req.Pod.Name == "plain" {
			return &ResolveResponse{Action: ActionSkip}, nil
		}
		return &ResolveResponse{Action: ActionConfigure, Plan: EncodePlan(gc.Plan)}, nil
	}}
	c := NewClient(serve(t, h), time.Second)
	ctx := context.Background()

	resp, err := c.Resolve(ctx, ResolveRequest{Pod: Pod{Namespace: "ns", Name: "plain", UID: "u1"}, ContainerID: "c1"})
	if err != nil || resp.Action != ActionSkip || resp.Plan != nil {
		t.Fatalf("skip: %+v, %v", resp, err)
	}
	resp, err = c.Resolve(ctx, ResolveRequest{Pod: Pod{Namespace: "ns", Name: "vpn"}, ContainerID: "c2", UplinkMTU: 1450})
	if err != nil || resp.Action != ActionConfigure {
		t.Fatalf("configure: %+v, %v", resp, err)
	}
	got, err := resp.Plan.Decode()
	if err != nil || !reflect.DeepEqual(got, gc.Plan) {
		t.Fatalf("plan changed in transit: %v", err)
	}
	if h.resolved[1].UplinkMTU != 1450 || h.resolved[0].Pod.UID != "u1" {
		t.Fatalf("request fields lost: %+v", h.resolved)
	}

	report := ReportRequest{Pod: Pod{Namespace: "ns", Name: "vpn"}, ContainerID: "c2", OK: false, Error: "boom", Warnings: []string{"w"}}
	if err := c.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(h.reports, []ReportRequest{report}) {
		t.Fatalf("reports = %+v", h.reports)
	}
}

func TestErrors(t *testing.T) {
	h := &fakeHandler{
		resolve: func(req ResolveRequest) (*ResolveResponse, error) {
			switch req.Pod.Name {
			case "no-secret":
				return nil, errors.New(`secret "vpn" not found`)
			case "no-plan":
				return &ResolveResponse{Action: ActionConfigure}, nil
			case "weird":
				return &ResolveResponse{Action: "dance"}, nil
			}
			time.Sleep(2 * time.Second)
			return &ResolveResponse{Action: ActionSkip}, nil
		},
		healthy: errors.New("informers not synced"),
	}
	sock := serve(t, h)
	c := NewClient(sock, 500*time.Millisecond)
	ctx := context.Background()

	var agentErr *AgentError
	_, err := c.Resolve(ctx, ResolveRequest{Pod: Pod{Name: "no-secret"}})
	if !errors.As(err, &agentErr) || agentErr.Status != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), `secret "vpn" not found`) {
		t.Errorf("agent error: %v", err)
	}
	for _, name := range []string{"no-plan", "weird"} {
		if _, err := c.Resolve(ctx, ResolveRequest{Pod: Pod{Name: name}}); !errors.As(err, &agentErr) {
			t.Errorf("%s: want *AgentError, got %v", name, err)
		}
	}
	if err := c.Healthy(ctx); !errors.As(err, &agentErr) || agentErr.Status != http.StatusServiceUnavailable || !strings.Contains(err.Error(), "informers not synced") {
		t.Errorf("Healthy: %v", err)
	}

	start := time.Now()
	if _, err := c.Resolve(ctx, ResolveRequest{Pod: Pod{Name: "slow"}}); err == nil || time.Since(start) > 1500*time.Millisecond {
		t.Errorf("slow agent: err %v after %s; want a timeout near 500ms", err, time.Since(start))
	}

	var unavailable *UnavailableError
	down := NewClient(filepath.Join(t.TempDir(), "nobody-home.sock"), time.Second)
	if _, err := down.Resolve(ctx, ResolveRequest{}); !errors.As(err, &unavailable) {
		t.Errorf("no agent: want *UnavailableError, got %v", err)
	}
}

func TestServerRejectsUnknownFields(t *testing.T) {
	sock := serve(t, &fakeHandler{resolve: func(ResolveRequest) (*ResolveResponse, error) {
		return &ResolveResponse{Action: ActionSkip}, nil
	}})
	c := NewClient(sock, time.Second)
	err := c.do(context.Background(), http.MethodPost, PathResolve, map[string]any{"pod": map[string]any{}, "surprise": 1}, nil)
	var agentErr *AgentError
	if !errors.As(err, &agentErr) || agentErr.Status != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown fields, got %v", err)
	}
}

func TestListenPermissionsAndStaleSocket(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "zora.sock")
	if err := os.WriteFile(sock, nil, 0o644); err != nil { // stale file from a crashed agent
		t.Fatal(err)
	}
	l, err := Listen(sock)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	defer func() { _ = l.Close() }()
	for path, want := range map[string]os.FileMode{dir: 0o700, sock: 0o600} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", path, got, want)
		}
	}
}

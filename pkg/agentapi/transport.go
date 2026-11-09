package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// maxBody bounds request and response bodies. Plans are a few KiB; a
// config with thousands of AllowedIPs is still well under this.
const maxBody = 4 << 20

// DefaultTimeout bounds each call from the plugin. The runtime has its own,
// longer, deadline for the whole CNI operation.
const DefaultTimeout = 15 * time.Second

// Handler is what the agent implements.
type Handler interface {
	Resolve(ctx context.Context, req ResolveRequest) (*ResolveResponse, error)
	Report(ctx context.Context, req ReportRequest) error
	// Healthy returns nil when the agent can serve Resolve.
	Healthy(ctx context.Context) error
}

// Listen creates the agent's socket at path. The parent directory is created
// (or tightened) to 0700 and the socket to 0600: only root on the node may
// talk to the agent, because Resolve hands out private keys.
func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory needs its execute bit
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("removing stale socket: %w", err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// NewServer returns an http.Server that serves h.
func NewServer(h Handler) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PathResolve, func(w http.ResponseWriter, r *http.Request) {
		var req ResolveRequest
		if !decode(w, r, &req) {
			return
		}
		resp, err := h.Resolve(r.Context(), req)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("POST "+PathReport, func(w http.ResponseWriter, r *http.Request) {
		var req ReportRequest
		if !decode(w, r, &req) {
			return
		}
		if err := h.Report(r.Context(), req); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET "+PathHealth, func(w http.ResponseWriter, r *http.Request) {
		if err := h.Healthy(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, ErrorResponse{Error: err.Error()})
}

// Client calls the agent.
type Client struct {
	socket string
	http   *http.Client
}

// NewClient returns a client for the agent listening on socket.
func NewClient(socket string, timeout time.Duration) *Client {
	d := net.Dialer{Timeout: timeout}
	return &Client{
		socket: socket,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return d.DialContext(ctx, "unix", socket)
				},
				DisableKeepAlives: true, // one-shot process
			},
		},
	}
}

// UnavailableError means the agent could not be reached at all, as opposed
// to the agent answering with an error.
type UnavailableError struct {
	Socket string
	Err    error
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("zora agent unreachable at %s: %v", e.Socket, e.Err)
}
func (e *UnavailableError) Unwrap() error { return e.Err }

// AgentError is an error the agent returned.
type AgentError struct {
	Status  int
	Message string
}

func (e *AgentError) Error() string { return "zora agent: " + e.Message }

// Resolve asks the agent what to do for a pod.
func (c *Client) Resolve(ctx context.Context, req ResolveRequest) (*ResolveResponse, error) {
	var resp ResolveResponse
	if err := c.do(ctx, http.MethodPost, PathResolve, req, &resp); err != nil {
		return nil, err
	}
	switch resp.Action {
	case ActionSkip:
	case ActionConfigure:
		if resp.Plan == nil {
			return nil, &AgentError{Status: http.StatusOK, Message: "configure response without a plan"}
		}
	default:
		return nil, &AgentError{Status: http.StatusOK, Message: fmt.Sprintf("unknown action %q", resp.Action)}
	}
	return &resp, nil
}

// Report tells the agent the outcome of an ADD.
func (c *Client) Report(ctx context.Context, req ReportRequest) error {
	return c.do(ctx, http.MethodPost, PathReport, req, nil)
}

// Healthy checks the agent is up and ready.
func (c *Client) Healthy(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, PathHealth, nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	// The host part is ignored: DialContext always dials the socket.
	req, err := http.NewRequestWithContext(ctx, method, "http://zora-agent"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &UnavailableError{Socket: c.socket, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	r := io.LimitReader(resp.Body, maxBody)
	if resp.StatusCode/100 != 2 {
		var e ErrorResponse
		if err := json.NewDecoder(r).Decode(&e); err != nil || e.Error == "" {
			e.Error = resp.Status
		}
		return &AgentError{Status: resp.StatusCode, Message: e.Error}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(r).Decode(out); err != nil {
		return &AgentError{Status: resp.StatusCode, Message: "decoding response: " + err.Error()}
	}
	return nil
}

package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// apiVersion is the X-Ops-Server-API-Version every request sends. Cinc Client
// 18+ speaks v2 (cookbooks with all_files).
const apiVersion = "2"

// actor is one API identity: a node's client, the validator, or the admin.
type actor struct {
	name string
	key  *rsa.PrivateKey
}

func loadActor(name, keyPath string) (*actor, error) {
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := auth.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyPath, err)
	}
	return &actor{name: name, key: key}, nil
}

// keyPath is where a node's client key lives under the keys directory.
func keyPath(dir, name string) string { return filepath.Join(dir, name+".pem") }

// newHTTP builds an HTTP client. A real chef-client run opens its own
// connections, so run uses one of these per run (fresh TLS handshakes) unless
// -reuse-conns is set; setup and register share one.
func newHTTP(timeout time.Duration, maxConns int) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               nil, // talk to the lab server directly, never through an outbound proxy
			MaxIdleConns:        maxConns,
			MaxIdleConnsPerHost: maxConns,
			IdleConnTimeout:     90 * time.Second,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   false, // chef-client speaks HTTP/1.1
		},
		// Presigned file URLs are fetched as-is; never follow a redirect
		// silently into a different host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// api is the org endpoint plus how to reach it.
type api struct {
	http *http.Client
	base string // https://host/organizations/org
}

// response is what one call returned, with its timing.
type response struct {
	status int
	body   []byte
	dur    time.Duration
}

// do sends one request to an org-relative path (or an absolute URL), signed by
// who when who is non-nil, and reads the whole body.
func (a *api) do(ctx context.Context, who *actor, method, path string, body []byte) (response, error) {
	url := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		url = a.base + path
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Chef-Version", "19.4.46")
	req.Header.Set("X-Ops-Server-API-Version", apiVersion)
	req.Header.Set("User-Agent", "runsim (cinc-server-ng load test)")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if who != nil {
		ts := time.Now().UTC().Format(time.RFC3339)
		if err := auth.SignRequest(req, who.name, ts, body, who.key); err != nil {
			return response{}, err
		}
	}
	start := time.Now()
	resp, err := a.http.Do(req)
	if err != nil {
		return response{dur: time.Since(start)}, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	dur := time.Since(start)
	if err != nil {
		return response{status: resp.StatusCode, dur: dur}, err
	}
	return response{status: resp.StatusCode, body: out, dur: dur}, nil
}

// statusError is a call that came back with an unexpected status.
type statusError struct {
	op     string
	status int
	body   []byte
}

func (e *statusError) Error() string {
	b := string(e.body)
	if len(b) > 200 {
		b = b[:200] + "…"
	}
	return fmt.Sprintf("%s: status %d: %s", e.op, e.status, strings.TrimSpace(b))
}

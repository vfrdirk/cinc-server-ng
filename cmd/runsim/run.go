package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// runConfig is everything one simulated run needs, shared by all nodes.
type runConfig struct {
	base, org      string
	prefix         string
	env            string
	runList        []string
	scannerEvery   int // every Nth node also has role[security-scanner]
	dataBags       []string
	searchQuery    string
	searchFrac     float64
	fileChurn      float64
	coldCache      bool
	reports        bool
	reuseConns     bool
	timeout        time.Duration
	interval       time.Duration
	splay          time.Duration
	firstSpread    time.Duration
	speed          float64
	template       []byte // node JSON with __NODE__/__IP__/__ROLES__/"__OHAI__" markers
	collectorPath  string
	sharedTransprt *http.Client
}

// sim is one simulated node.
type sim struct {
	idx     int
	name    string
	who     *actor
	created bool // node object exists (known after its first run)
	warm    bool // has run before, so its file cache is warm
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	base := fs.String("base", "", "org URL, e.g. https://loadtest.home.arpa/organizations/loadtest")
	keys := fs.String("keys", "keys", "directory of client keys from register")
	prefix := fs.String("prefix", "ltnode-", "node/client name prefix")
	start := fs.Int("start", 0, "first node index")
	n := fs.Int("clients", 1000, "number of simulated nodes")
	env := fs.String("env", "peach", "chef_environment")
	runList := fs.String("run-list", "role[linux],role[container]", "comma-separated run list")
	scanner := fs.Int("scanner-every", 100, "every Nth node also gets role[security-scanner] (0 = none); search finds these")
	bags := fs.String("data-bags", "secrets/defectdojo,apps/web", "comma-separated bag/item reads per run")
	sq := fs.String("search", "role:security-scanner", "partial-search query per run (empty = no search)")
	sfrac := fs.Float64("search-frac", 1.0, "fraction of runs that search")
	churn := fs.Float64("file-churn", 0.01, "fraction of cookbook files a warm run re-downloads")
	cold := fs.Bool("cold", false, "every node starts with an empty file cache (downloads all files on its first run)")
	reports := fs.Bool("reports", true, "send data-collector run_start/run_converge reports")
	reuse := fs.Bool("reuse-conns", false, "share connections across runs (real clients don't; default opens fresh TLS per run)")
	timeout := fs.Duration("timeout", 60*time.Second, "per-request timeout")
	interval := fs.Duration("interval", 30*time.Minute, "time between a node's runs")
	splay := fs.Duration("splay", 5*time.Minute, "random extra delay per run, 0..splay")
	first := fs.Duration("first-spread", 0, "spread first runs over this long (default interval+splay: steady state from the start; small = thundering herd)")
	speed := fs.Float64("speed", 1, "time compression: 2 = twice as many runs per real minute")
	conc := fs.Int("max-inflight", 4000, "cap on runs in progress (queue time is recorded as op queue_wait)")
	tmpl := fs.String("node-template", "node-template.json", "a real node's JSON (knife node show -l -F json)")
	out := fs.String("out", "results", "results directory")
	window := fs.Duration("window", 10*time.Second, "latency.csv row interval")
	duration := fs.Duration("duration", 0, "stop after this long (0 = until interrupted)")
	seed := fs.Int64("seed", 1, "RNG seed")
	_ = fs.Parse(args)
	if *base == "" {
		return errors.New("run needs -base")
	}
	if *first == 0 {
		*first = *interval + *splay
	}
	if *speed <= 0 {
		return errors.New("-speed must be positive")
	}

	org, err := orgOf(*base)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*tmpl)
	if err != nil {
		return err
	}
	template, err := prepareTemplate(raw, *env)
	if err != nil {
		return err
	}
	cfg := &runConfig{
		base: *base, org: org, prefix: *prefix, env: *env,
		runList: splitList(*runList), scannerEvery: *scanner, dataBags: splitList(*bags),
		searchQuery: *sq, searchFrac: *sfrac, fileChurn: *churn, coldCache: *cold,
		reports: *reports, reuseConns: *reuse, timeout: *timeout,
		interval: *interval, splay: *splay, firstSpread: *first, speed: *speed,
		template: template, collectorPath: strings.TrimSuffix(*base, "/") + "/data-collector",
	}
	if cfg.reuseConns {
		cfg.sharedTransprt = newHTTP(cfg.timeout, *conc)
	}

	log.Printf("loading %d client keys from %s", *n, *keys)
	sims := make([]*sim, 0, *n)
	for i := *start; i < *start+*n; i++ {
		name := nodeName(*prefix, i)
		who, err := loadActor(name, keyPath(*keys, name))
		if err != nil {
			return fmt.Errorf("%w (run register first)", err)
		}
		sims = append(sims, &sim{idx: i, name: name, who: who, warm: !*cold})
	}

	rec, err := newRecorder(*out)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	expected := float64(*n) / (cfg.interval + cfg.splay/2).Seconds() * cfg.speed
	log.Printf("fleet: %d nodes, %s every %v + up to %v splay at %gx, first runs over %v: ~%.1f runs/s expected",
		*n, strings.Join(cfg.runList, ","), cfg.interval, cfg.splay, cfg.speed, cfg.firstSpread, expected)

	sem := make(chan struct{}, *conc)
	var ok, failed, inflight int64
	var wg sync.WaitGroup
	for _, s := range sims {
		wg.Add(1)
		go func(s *sim) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(*seed ^ int64(s.idx)*7919))
			if !sleepCtx(ctx, cfg.scaled(time.Duration(rng.Int63n(int64(cfg.firstSpread)+1)))) {
				return
			}
			for {
				queued := time.Now()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				rec.add("queue_wait", time.Since(queued), 0, false)
				atomic.AddInt64(&inflight, 1)
				t0 := time.Now()
				err := cfg.runOnce(ctx, s, rng, rec)
				atomic.AddInt64(&inflight, -1)
				<-sem
				if ctx.Err() != nil {
					return // stopping: a cut-off run is not a failure
				}
				rec.add("run", time.Since(t0), 0, err != nil)
				rec.runDone()
				if err != nil {
					atomic.AddInt64(&failed, 1)
					log.Printf("run %s: %v", s.name, err)
				} else {
					atomic.AddInt64(&ok, 1)
				}
				next := cfg.interval
				if cfg.splay > 0 {
					next += time.Duration(rng.Int63n(int64(cfg.splay)))
				}
				if !sleepCtx(ctx, cfg.scaled(next)) {
					return
				}
			}
		}(s)
	}

	go func() {
		tk := time.NewTicker(*window)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tk.C:
				st := rec.flush(now, *window)
				log.Printf("%s | in flight %d | total ok %d failed %d",
					brief(st), atomic.LoadInt64(&inflight), atomic.LoadInt64(&ok), atomic.LoadInt64(&failed))
			}
		}
	}()

	wg.Wait()
	rec.flush(time.Now(), *window)
	log.Printf("stopped: %d runs ok, %d failed", ok, failed)
	return rec.close(map[string]any{
		"mode": "run", "clients": *n, "interval": cfg.interval.String(), "splay": cfg.splay.String(),
		"first_spread": cfg.firstSpread.String(), "speed": cfg.speed, "run_list": cfg.runList,
		"search": cfg.searchQuery, "reports": cfg.reports, "cold": cfg.coldCache,
		"reuse_conns": cfg.reuseConns, "runs_ok": ok, "runs_failed": failed,
	})
}

// brief is the one-line live view: runs/s, run p95, and error totals.
func brief(st []stat) string {
	var errs int64
	var run stat
	for _, s := range st {
		errs += s.Errors
		if s.Op == "run" {
			run = s
		}
	}
	return fmt.Sprintf("runs %.1f/s p50 %.0fms p95 %.0fms p99 %.0fms | errors %d", run.RPS, run.P50, run.P95, run.P99, errs)
}

func (c *runConfig) scaled(d time.Duration) time.Duration {
	return time.Duration(float64(d) / c.speed)
}

// runOnce is one chef-client run for s. It stops at the first failed call, as
// chef-client does, and records every call it made.
func (c *runConfig) runOnce(ctx context.Context, s *sim, rng *mrand.Rand, rec *recorder) error {
	hc := c.sharedTransprt
	if hc == nil {
		hc = newHTTP(c.timeout, 4)
		defer hc.CloseIdleConnections()
	}
	a := &api{http: hc, base: c.base}
	call := func(op, method, path string, body []byte, want ...int) (response, error) {
		r, err := a.do(ctx, s.who, method, path, body)
		failed := err != nil || !statusIn(r.status, want)
		rec.add(op, r.dur, len(r.body)+len(body), failed)
		if err != nil {
			return r, fmt.Errorf("%s: %w", op, err)
		}
		if failed {
			return r, &statusError{op, r.status, r.body}
		}
		return r, nil
	}

	runID := uuid()
	startTime := time.Now().UTC()
	runList := c.runList
	if c.scannerEvery > 0 && s.idx%c.scannerEvery == 0 {
		runList = append(append([]string(nil), runList...), "role[security-scanner]")
	}

	// 1. Load the node (create it on the very first run).
	if !s.created {
		r, err := call("node_get", "GET", "/nodes/"+s.name, nil, 200, 404)
		if err != nil {
			return err
		}
		if r.status == 404 {
			if _, err := call("node_create", "POST", "/nodes", c.nodeBody(s, runList, startTime), 201); err != nil {
				return err
			}
		}
		s.created = true
	} else if _, err := call("node_get", "GET", "/nodes/"+s.name, nil, 200); err != nil {
		return err
	}

	if c.reports {
		c.report(ctx, a, rec, s, runID, "run_started", startTime, nil)
	}

	// 2. Expand the run list: environment, then each role (and nested roles).
	if _, err := call("env_get", "GET", "/environments/"+c.env, nil, 200); err != nil {
		return err
	}
	recipes, err := c.expand(runList, func(role string) ([]byte, error) {
		r, err := call("role_get", "GET", "/roles/"+role, nil, 200)
		return r.body, err
	})
	if err != nil {
		return err
	}

	// 3. Resolve cookbook versions.
	body, _ := json.Marshal(map[string]any{"run_list": recipes})
	r, err := call("depsolve", "POST", "/environments/"+c.env+"/cookbook_versions", body, 200)
	if err != nil {
		return err
	}

	// 4. Download files: all on a cold first run, then the churned fraction.
	files := fileURLs(r.body)
	for _, u := range files {
		if s.warm && rng.Float64() >= c.fileChurn {
			continue
		}
		if _, err := call("file_get", "GET", u, nil, 200); err != nil {
			return err
		}
	}
	s.warm = true

	// 5. What recipes read while converging: data bag items and a search.
	for _, b := range c.dataBags {
		if _, err := call("databag_get", "GET", "/data/"+b, nil, 200); err != nil {
			return err
		}
	}
	if c.searchQuery != "" && rng.Float64() < c.searchFrac {
		q := url.Values{"q": {c.searchQuery}, "start": {"0"}, "rows": {"1000"}}
		pbody := []byte(`{"name":["name"],"ip":["ipaddress"],"platform":["platform"]}`)
		if _, err := call("search", "POST", "/search/node?"+q.Encode(), pbody, 200); err != nil {
			return err
		}
	}

	// 6. Save the node.
	node := c.nodeBody(s, runList, time.Now())
	if _, err := call("node_save", "PUT", "/nodes/"+s.name, node, 200); err != nil {
		return err
	}

	if c.reports {
		c.report(ctx, a, rec, s, runID, "run_converge", startTime, node)
	}
	return nil
}

// report sends one data-collector message. Like chef-client, a failed report
// is recorded but never fails the run. Reports go through the server's proxy
// unsigned (the proxy strips auth before the collector anyway).
func (c *runConfig) report(ctx context.Context, a *api, rec *recorder, s *sim, runID, kind string, start time.Time, node []byte) {
	var b bytes.Buffer
	fmt.Fprintf(&b, `{"message_type":%q,"message_version":"1.1.0","run_id":%q,"node_name":%q,"organization_name":%q,"chef_server_fqdn":%q,"start_time":%q,"source":"chef_client"`,
		kind, runID, s.name, c.org, hostOf(c.base), start.Format(time.RFC3339))
	if node != nil {
		fmt.Fprintf(&b, `,"status":"success","end_time":%q,"total_resource_count":120,"updated_resource_count":2,"node":`, time.Now().UTC().Format(time.RFC3339))
		b.Write(node)
		b.WriteString(`,"resources":[]`)
	}
	b.WriteString("}")
	r, err := a.do(ctx, nil, "POST", c.collectorPath, b.Bytes())
	rec.add("report", r.dur, b.Len(), err != nil || !statusIn(r.status, []int{200, 201, 202, 204}))
}

// expand turns a run list into its recipes, fetching each role (and nested
// role) once, the way chef-client's run-list expansion does.
func (c *runConfig) expand(runList []string, getRole func(string) ([]byte, error)) ([]string, error) {
	var recipes []string
	seenRole := map[string]bool{}
	seenRecipe := map[string]bool{}
	var walk func([]string) error
	walk = func(items []string) error {
		for _, it := range items {
			switch {
			case strings.HasPrefix(it, "role["):
				role := strings.TrimSuffix(strings.TrimPrefix(it, "role["), "]")
				if seenRole[role] {
					continue
				}
				seenRole[role] = true
				b, err := getRole(role)
				if err != nil {
					return err
				}
				var rl struct {
					RunList    []string            `json:"run_list"`
					EnvRunList map[string][]string `json:"env_run_lists"`
				}
				if err := json.Unmarshal(b, &rl); err != nil {
					return fmt.Errorf("role %s: %w", role, err)
				}
				list := rl.RunList
				if e, ok := rl.EnvRunList[c.env]; ok {
					list = e
				}
				if err := walk(list); err != nil {
					return err
				}
			default:
				r := strings.TrimSuffix(strings.TrimPrefix(it, "recipe["), "]")
				if !seenRecipe[r] {
					seenRecipe[r] = true
					recipes = append(recipes, r)
				}
			}
		}
		return nil
	}
	return recipes, walk(runList)
}

// fileURLs finds every file URL in a cookbook_versions response, whichever
// API version shaped it (all_files, or per-segment lists).
func fileURLs(body []byte) []string {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			if u, ok := t["url"].(string); ok {
				if _, ok := t["checksum"]; ok {
					out = append(out, u)
					return
				}
			}
			for _, v := range t {
				walk(v)
			}
		case []any:
			for _, v := range t {
				walk(v)
			}
		}
	}
	walk(v)
	return out
}

// prepareTemplate turns a real node's JSON into a template: identity fields
// become markers that nodeBody fills per node, so the expensive part (a
// couple of hundred KB of Ohai data) is encoded once.
func prepareTemplate(raw []byte, env string) ([]byte, error) {
	var node map[string]any
	if err := json.Unmarshal(raw, &node); err != nil {
		return nil, fmt.Errorf("node template: %w", err)
	}
	node["name"] = "__NODE__"
	node["chef_environment"] = env
	node["run_list"] = "__RUNLIST__"
	node["json_class"] = "Chef::Node"
	node["chef_type"] = "node"
	auto, _ := node["automatic"].(map[string]any)
	if auto == nil {
		auto = map[string]any{}
		node["automatic"] = auto
	}
	auto["fqdn"] = "__NODE__.loadtest.arpa"
	auto["hostname"] = "__NODE__"
	auto["machinename"] = "__NODE__"
	auto["ipaddress"] = "__IP__"
	auto["roles"] = "__ROLES__"
	auto["ohai_time"] = "__OHAI__"
	return json.Marshal(node)
}

// nodeBody fills the template for s.
func (c *runConfig) nodeBody(s *sim, runList []string, now time.Time) []byte {
	var roles []string
	for _, it := range runList {
		if strings.HasPrefix(it, "role[") {
			roles = append(roles, strings.TrimSuffix(strings.TrimPrefix(it, "role["), "]"))
		}
	}
	rl, _ := json.Marshal(runList)
	rs, _ := json.Marshal(roles)
	ip := fmt.Sprintf("10.%d.%d.%d", (s.idx>>16)&255, (s.idx>>8)&255, s.idx&255)
	ohai := strconv.FormatFloat(float64(now.UnixNano())/1e9, 'f', 4, 64)
	b := c.template
	b = bytes.ReplaceAll(b, []byte(`"__RUNLIST__"`), rl)
	b = bytes.ReplaceAll(b, []byte(`"__ROLES__"`), rs)
	b = bytes.ReplaceAll(b, []byte(`"__OHAI__"`), []byte(ohai))
	b = bytes.ReplaceAll(b, []byte("__NODE__"), []byte(s.name))
	b = bytes.ReplaceAll(b, []byte("__IP__"), []byte(ip))
	return b
}

func statusIn(code int, want []int) bool {
	for _, w := range want {
		if code == w {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orgOf(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "organizations" {
		return "", fmt.Errorf("-base must end in /organizations/<org>, got %q", base)
	}
	return parts[1], nil
}

func hostOf(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

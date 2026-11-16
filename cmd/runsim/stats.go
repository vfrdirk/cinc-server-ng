package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// recorder collects per-operation latencies and errors. Every window it writes
// one CSV row per operation to latency.csv; at the end it writes a whole-run
// summary to summary.json. Latencies are kept exactly (a window holds a few
// hundred thousand samples at most), so percentiles are exact, not estimated.
type recorder struct {
	mu     sync.Mutex
	window map[string]*samples // since the last flush
	total  map[string]*samples // whole run
	runs   int64

	csv     *bufio.Writer
	csvFile *os.File
	dir     string
	started time.Time
}

type samples struct {
	durs   []time.Duration
	errors int64
	bytes  int64
}

func newRecorder(dir string) (*recorder, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(filepath.Join(dir, "latency.csv"))
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "time,op,count,errors,rps,p50_ms,p95_ms,p99_ms,max_ms,mb")
	return &recorder{
		window: map[string]*samples{}, total: map[string]*samples{},
		csv: w, csvFile: f, dir: dir, started: time.Now(),
	}, nil
}

// add records one call of op. A failed call counts as an error; its duration
// is still recorded, because a timeout is latency the client paid for.
func (r *recorder) add(op string, d time.Duration, nbytes int, failed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range []map[string]*samples{r.window, r.total} {
		s := m[op]
		if s == nil {
			s = &samples{}
			m[op] = s
		}
		s.durs = append(s.durs, d)
		s.bytes += int64(nbytes)
		if failed {
			s.errors++
		}
	}
}

func (r *recorder) runDone() {
	r.mu.Lock()
	r.runs++
	r.mu.Unlock()
}

// stat is the summary of one operation over some span.
type stat struct {
	Op     string  `json:"op"`
	Count  int     `json:"count"`
	Errors int64   `json:"errors"`
	RPS    float64 `json:"rps"`
	P50    float64 `json:"p50_ms"`
	P95    float64 `json:"p95_ms"`
	P99    float64 `json:"p99_ms"`
	Max    float64 `json:"max_ms"`
	MB     float64 `json:"mb"`
}

func summarize(op string, s *samples, span time.Duration) stat {
	d := append([]time.Duration(nil), s.durs...)
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	st := stat{Op: op, Count: len(d), Errors: s.errors, MB: float64(s.bytes) / 1e6}
	if span > 0 {
		st.RPS = float64(len(d)) / span.Seconds()
	}
	if len(d) > 0 {
		st.P50 = ms(pct(d, 0.50))
		st.P95 = ms(pct(d, 0.95))
		st.P99 = ms(pct(d, 0.99))
		st.Max = ms(d[len(d)-1])
	}
	return st
}

// pct is the nearest-rank percentile of sorted d.
func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	i := int(float64(len(d))*p+0.5) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(d) {
		i = len(d) - 1
	}
	return d[i]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// flush writes the current window to latency.csv and starts a new one. It
// returns the window's stats, sorted by op, for the live log line.
func (r *recorder) flush(now time.Time, span time.Duration) []stat {
	r.mu.Lock()
	w := r.window
	r.window = map[string]*samples{}
	r.mu.Unlock()

	out := make([]stat, 0, len(w))
	for op, s := range w {
		out = append(out, summarize(op, s, span))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Op < out[j].Op })
	ts := now.UTC().Format(time.RFC3339)
	for _, st := range out {
		fmt.Fprintf(r.csv, "%s,%s,%d,%d,%.2f,%.1f,%.1f,%.1f,%.1f,%.2f\n",
			ts, st.Op, st.Count, st.Errors, st.RPS, st.P50, st.P95, st.P99, st.Max, st.MB)
	}
	_ = r.csv.Flush()
	return out
}

// close writes summary.json for the whole run and closes latency.csv.
func (r *recorder) close(meta map[string]any) error {
	span := time.Since(r.started)
	r.mu.Lock()
	ops := make([]stat, 0, len(r.total))
	for op, s := range r.total {
		ops = append(ops, summarize(op, s, span))
	}
	runs := r.runs
	r.mu.Unlock()
	sort.Slice(ops, func(i, j int) bool { return ops[i].Op < ops[j].Op })

	meta["started"] = r.started.UTC().Format(time.RFC3339)
	meta["seconds"] = int(span.Seconds())
	meta["runs"] = runs
	meta["ops"] = ops
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r.dir, "summary.json"), b, 0o644); err != nil {
		return err
	}
	if err := r.csv.Flush(); err != nil {
		return err
	}
	return r.csvFile.Close()
}

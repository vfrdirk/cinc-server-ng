package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPct(t *testing.T) {
	var d []time.Duration
	for i := 1; i <= 100; i++ {
		d = append(d, time.Duration(i)*time.Millisecond)
	}
	for _, c := range []struct {
		p    float64
		want time.Duration
	}{{0.50, 50 * time.Millisecond}, {0.95, 95 * time.Millisecond}, {0.99, 99 * time.Millisecond}, {1, 100 * time.Millisecond}} {
		if got := pct(d, c.p); got != c.want {
			t.Errorf("pct(%v) = %v, want %v", c.p, got, c.want)
		}
	}
	if pct(nil, 0.5) != 0 {
		t.Error("pct of nothing should be 0")
	}
}

func TestExpandFollowsNestedRolesOnce(t *testing.T) {
	roles := map[string]string{
		"linux":     `{"run_list":["recipe[base]","role[common]"]}`,
		"common":    `{"run_list":["recipe[ntp]","recipe[base]"]}`,
		"container": `{"run_list":["recipe[lab::waivers]"],"env_run_lists":{"peach":["recipe[lab::waivers_peach]","role[common]"]}}`,
	}
	fetched := map[string]int{}
	c := &runConfig{env: "peach"}
	got, err := c.expand([]string{"role[linux]", "role[container]", "recipe[extra]"}, func(r string) ([]byte, error) {
		fetched[r]++
		b, ok := roles[r]
		if !ok {
			return nil, errors.New("no role " + r)
		}
		return []byte(b), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "base,ntp,lab::waivers_peach,extra"
	if strings.Join(got, ",") != want {
		t.Errorf("recipes = %v, want %s", got, want)
	}
	if fetched["common"] != 1 {
		t.Errorf("common fetched %d times, want once", fetched["common"])
	}
}

func TestFileURLsBothShapes(t *testing.T) {
	v2 := `{"apache2":{"all_files":[{"name":"recipes/default.rb","checksum":"aa","url":"https://h/f1"},{"name":"metadata.rb","checksum":"bb","url":"https://h/f2"}]}}`
	v1 := `{"apache2":{"recipes":[{"name":"default.rb","checksum":"aa","url":"https://h/f1"}],"root_files":[{"name":"metadata.rb","checksum":"bb","url":"https://h/f2"}],"metadata":{"url":"not-a-file"}}}`
	for name, body := range map[string]string{"v2": v2, "v1": v1} {
		if got := fileURLs([]byte(body)); len(got) != 2 {
			t.Errorf("%s: got %v, want 2 file URLs", name, got)
		}
	}
}

func TestNodeBodyFillsTemplate(t *testing.T) {
	raw := `{"name":"vulnscan","chef_environment":"peach","run_list":["role[x]"],"normal":{"tags":[]},
	         "automatic":{"fqdn":"vulnscan.home.arpa","hostname":"vulnscan","roles":["x"],"ohai_time":1.5,"kernel":{"name":"Linux"}}}`
	tmpl, err := prepareTemplate([]byte(raw), "loadtest")
	if err != nil {
		t.Fatal(err)
	}
	c := &runConfig{template: tmpl}
	body := c.nodeBody(&sim{idx: 70000, name: "ltnode-070000"}, []string{"role[linux]", "recipe[y]"}, time.Unix(1700000000, 0))
	var n struct {
		Name    string   `json:"name"`
		Env     string   `json:"chef_environment"`
		RunList []string `json:"run_list"`
		Auto    struct {
			FQDN string   `json:"fqdn"`
			IP   string   `json:"ipaddress"`
			Role []string `json:"roles"`
			Ohai float64  `json:"ohai_time"`
			K    struct {
				Name string `json:"name"`
			} `json:"kernel"`
		} `json:"automatic"`
	}
	if err := json.Unmarshal(body, &n); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	if n.Name != "ltnode-070000" || n.Env != "loadtest" || n.Auto.FQDN != "ltnode-070000.loadtest.arpa" ||
		n.Auto.IP != "10.1.17.112" || n.Auto.Ohai != 1700000000 || n.Auto.K.Name != "Linux" ||
		strings.Join(n.RunList, ",") != "role[linux],recipe[y]" || strings.Join(n.Auto.Role, ",") != "linux" {
		t.Errorf("unexpected node: %+v", n)
	}
	if strings.Contains(string(body), "vulnscan") {
		t.Error("template node's identity leaked into the generated node")
	}
}

func TestRecorderWritesCSVAndSummary(t *testing.T) {
	dir := t.TempDir()
	r, err := newRecorder(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.add("node_save", 20*time.Millisecond, 1000, false)
	r.add("node_save", 40*time.Millisecond, 1000, true)
	st := r.flush(time.Now(), 10*time.Second)
	if len(st) != 1 || st[0].Count != 2 || st[0].Errors != 1 {
		t.Fatalf("flush = %+v", st)
	}
	if err := r.close(map[string]any{"mode": "test"}); err != nil {
		t.Fatal(err)
	}
	csv, _ := os.ReadFile(filepath.Join(dir, "latency.csv"))
	if lines := strings.Count(string(csv), "\n"); lines != 2 {
		t.Errorf("latency.csv has %d lines, want header + 1", lines)
	}
	var sum struct {
		Ops []stat `json:"ops"`
	}
	b, _ := os.ReadFile(filepath.Join(dir, "summary.json"))
	if err := json.Unmarshal(b, &sum); err != nil || len(sum.Ops) != 1 || sum.Ops[0].P99 != 40 {
		t.Errorf("summary = %s (%v)", b, err)
	}
}

func TestOrgOf(t *testing.T) {
	if o, err := orgOf("https://h/organizations/loadtest"); err != nil || o != "loadtest" {
		t.Errorf("orgOf = %q, %v", o, err)
	}
	if _, err := orgOf("https://h/"); err == nil {
		t.Error("want error for a base without an org")
	}
}

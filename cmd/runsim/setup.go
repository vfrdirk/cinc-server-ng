package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// cmdSetup creates (or recreates) the validator client that register signs
// with, and writes its private key.
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	base := fs.String("base", "", "org URL, e.g. https://loadtest.home.arpa/organizations/loadtest")
	admin := fs.String("admin", "pivotal", "admin user that creates the validator")
	adminKey := fs.String("admin-key", "", "admin private key (PEM)")
	name := fs.String("validator", "runsim-validator", "validator client name")
	out := fs.String("out", "validator.pem", "where to write the validator's private key")
	_ = fs.Parse(args)
	if *base == "" || *adminKey == "" {
		return errors.New("setup needs -base and -admin-key")
	}
	who, err := loadActor(*admin, *adminKey)
	if err != nil {
		return err
	}
	a := &api{http: newHTTP(30*time.Second, 4), base: *base}
	ctx := context.Background()

	// Recreate, so the key on disk always matches.
	if r, err := a.do(ctx, who, "DELETE", "/clients/"+*name, nil); err != nil {
		return err
	} else if r.status != http.StatusOK && r.status != http.StatusNotFound {
		return &statusError{"delete validator", r.status, r.body}
	}
	body, _ := json.Marshal(map[string]any{"name": *name, "validator": true, "create_key": true})
	r, err := a.do(ctx, who, "POST", "/clients", body)
	if err != nil {
		return err
	}
	if r.status != http.StatusCreated {
		return &statusError{"create validator", r.status, r.body}
	}
	key, err := privateKeyFrom(r.body)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(key), 0o600); err != nil {
		return err
	}
	// As on a real Chef server, only the org's own validator may create
	// clients; grant this one the same create permission on the container.
	if err := grantCreate(ctx, a, who, *name); err != nil {
		return err
	}
	log.Printf("validator %q created and allowed to register clients; key written to %s", *name, *out)
	return nil
}

// grantCreate adds client name to the clients container's create ACE.
func grantCreate(ctx context.Context, a *api, admin *actor, name string) error {
	r, err := a.do(ctx, admin, "GET", "/containers/clients/_acl", nil)
	if err != nil {
		return err
	}
	if r.status != http.StatusOK {
		return &statusError{"read clients container ACL", r.status, r.body}
	}
	var acl map[string]struct {
		Actors  []string `json:"actors"`
		Clients []string `json:"clients"`
		Users   []string `json:"users"`
		Groups  []string `json:"groups"`
	}
	if err := json.Unmarshal(r.body, &acl); err != nil {
		return err
	}
	ace := acl["create"]
	for _, c := range ace.Clients {
		if c == name {
			return nil
		}
	}
	ace.Clients = append(ace.Clients, name)
	clients, users := ace.Clients, ace.Users
	if clients == nil {
		clients = []string{}
	}
	if users == nil {
		users = []string{}
	}
	groups := ace.Groups
	if groups == nil {
		groups = []string{}
	}
	body, _ := json.Marshal(map[string]any{"create": map[string]any{"clients": clients, "users": users, "groups": groups}})
	r, err = a.do(ctx, admin, "PUT", "/containers/clients/_acl/create", body)
	if err != nil {
		return err
	}
	if r.status != http.StatusOK {
		return &statusError{"grant create on clients", r.status, r.body}
	}
	return nil
}

// privateKeyFrom pulls the generated private key out of a client-create
// response, in either the v1 (chef_key.private_key) or v0 shape.
func privateKeyFrom(body []byte) (string, error) {
	var resp struct {
		PrivateKey string `json:"private_key"`
		ChefKey    struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	if resp.ChefKey.PrivateKey != "" {
		return resp.ChefKey.PrivateKey, nil
	}
	if resp.PrivateKey != "" {
		return resp.PrivateKey, nil
	}
	return "", errors.New("create response has no private key")
}

// cmdRegister creates -clients node clients through the validator, as a fresh
// fleet's first chef-client runs would, and stores each client's key under
// -keys. Clients whose key is already there are skipped, so it can be re-run
// to grow the fleet.
func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	base := fs.String("base", "", "org URL")
	vname := fs.String("validator", "runsim-validator", "validator client name")
	vkey := fs.String("validator-key", "validator.pem", "validator private key (PEM)")
	keys := fs.String("keys", "keys", "directory for client keys")
	prefix := fs.String("prefix", "ltnode-", "node/client name prefix")
	start := fs.Int("start", 0, "first node index")
	n := fs.Int("clients", 1000, "number of clients")
	conc := fs.Int("concurrency", 32, "registrations in flight")
	out := fs.String("out", "", "write latency.csv/summary.json here (optional)")
	_ = fs.Parse(args)
	if *base == "" {
		return errors.New("register needs -base")
	}
	val, err := loadActor(*vname, *vkey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*keys, 0o700); err != nil {
		return err
	}
	var rec *recorder
	if *out != "" {
		if rec, err = newRecorder(*out); err != nil {
			return err
		}
	}
	a := &api{http: newHTTP(60*time.Second, *conc), base: *base}
	ctx := context.Background()

	var done, skipped, failed int64
	work := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				name := nodeName(*prefix, i)
				path := keyPath(*keys, name)
				if _, err := os.Stat(path); err == nil {
					atomic.AddInt64(&skipped, 1)
					continue
				}
				body, _ := json.Marshal(map[string]any{"name": name, "create_key": true})
				r, err := a.do(ctx, val, "POST", "/clients", body)
				ok := err == nil && r.status == http.StatusCreated
				if rec != nil {
					rec.add("register", r.dur, len(r.body), !ok)
				}
				if !ok {
					atomic.AddInt64(&failed, 1)
					if err == nil {
						err = &statusError{"register " + name, r.status, r.body}
					}
					log.Print(err)
					continue
				}
				key, err := privateKeyFrom(r.body)
				if err == nil {
					err = os.WriteFile(path, []byte(key), 0o600)
				}
				if err != nil {
					atomic.AddInt64(&failed, 1)
					log.Printf("register %s: %v", name, err)
					continue
				}
				atomic.AddInt64(&done, 1)
			}
		}()
	}

	t0 := time.Now()
	stop := make(chan struct{})
	go func() {
		tk := time.NewTicker(10 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-tk.C:
				if rec != nil {
					rec.flush(now, 10*time.Second)
				}
				log.Printf("register: %d created, %d skipped, %d failed", atomic.LoadInt64(&done), atomic.LoadInt64(&skipped), atomic.LoadInt64(&failed))
			}
		}
	}()
	for i := *start; i < *start+*n; i++ {
		work <- i
	}
	close(work)
	wg.Wait()
	close(stop)
	el := time.Since(t0)
	log.Printf("register finished in %v: %d created (%.1f/s), %d skipped, %d failed",
		el.Round(time.Second), done, float64(done)/el.Seconds(), skipped, failed)
	if rec != nil {
		rec.flush(time.Now(), 10*time.Second)
		if err := rec.close(map[string]any{"mode": "register", "clients": *n, "concurrency": *conc}); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d registrations failed", failed)
	}
	return nil
}

func nodeName(prefix string, i int) string { return fmt.Sprintf("%s%06d", prefix, i) }

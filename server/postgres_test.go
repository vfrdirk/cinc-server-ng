package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store/postgres/pgtest"
)

// These tests drive the full server (real signatures, ACL enforcement on) over
// the PostgreSQL backend. They skip unless CINC_SERVER_NG_TEST_POSTGRES is set.

// TestPostgresZeroToWorkingClientBootstrap is TestZeroToWorkingClientBootstrap
// on PostgreSQL: a validator registers a client, which must then be able to
// create, read and update its own node. It is the flow a fleet runs on every new
// machine, and the one a backend that loses group-membership writes breaks with
// "403 missing create permission" on the node create.
func TestPostgresZeroToWorkingClientBootstrap(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true, Storage: "postgres", DB: pgtest.NewDatabase(t)})
	base := srv.URL() + "/organizations/acme"
	mustStatus(t, signed(t, srv, "POST", base+"/roles", `{"name":"web"}`), 201)

	clientKey := createClientAndKey(t, srv, base, "node1")
	mustStatus(t, signedAs(t, "node1", clientKey, "POST", base+"/nodes", `{"name":"node1"}`), 201)
	mustStatus(t, signedAs(t, "node1", clientKey, "GET", base+"/nodes/node1", ""), 200)
	mustStatus(t, signedAs(t, "node1", clientKey, "PUT", base+"/nodes/node1",
		`{"name":"node1","run_list":["role[web]"],"normal":{"k":"v"}}`), 200)
	mustStatus(t, signedAs(t, "node1", clientKey, "GET", base+"/roles/web", ""), 200)

	// The registered client is listed in the clients group, as on Chef.
	if !slices.Contains(groupClients(t, srv, base, "clients"), "node1") {
		t.Fatal(`registered client "node1" is not a member of the clients group`)
	}
	// Enforcement is real: the client cannot modify a node it does not own.
	mustStatus(t, signed(t, srv, "POST", base+"/nodes", `{"name":"other"}`), 201)
	mustStatus(t, signedAs(t, "node1", clientKey, "PUT", base+"/nodes/other", `{"name":"other","normal":{"x":1}}`), 403)
}

// TestPostgresRestartKeepsKeysAndBootstrap restarts a server on the same
// database: the admin and validator keys must survive (so existing clients and
// installers keep working), data must persist, and a machine bootstrapped after
// the restart must still get a working client.
func TestPostgresRestartKeepsKeysAndBootstrap(t *testing.T) {
	opts := Options{Orgs: []string{"acme"}, EnforceACL: true, Storage: "postgres", DB: pgtest.NewDatabase(t)}
	srv1, err := New(opts)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	if err := srv1.Start(); err != nil {
		t.Fatal(err)
	}
	adminKey := append([]byte(nil), srv1.AdminKey()...)
	validatorKey := append([]byte(nil), srv1.ValidatorKey("acme")...)
	base1 := srv1.URL() + "/organizations/acme"
	key1 := createClientAndKey(t, srv1, base1, "before")
	mustStatus(t, signedAs(t, "before", key1, "POST", base1+"/nodes", `{"name":"before"}`), 201)
	stopServer(t, srv1)

	srv2, err := New(opts)
	if err != nil {
		t.Fatalf("restart New on existing database: %v", err)
	}
	if err := srv2.Start(); err != nil {
		t.Fatal(err)
	}
	defer stopServer(t, srv2)
	base := srv2.URL() + "/organizations/acme"
	if !bytes.Equal(srv2.AdminKey(), adminKey) {
		t.Fatal("admin key changed across restart; existing admin clients would break")
	}
	if !bytes.Equal(srv2.ValidatorKey("acme"), validatorKey) {
		t.Fatal("validator key changed across restart; installers holding it would get 401")
	}
	// The pre-restart client still works on its own node.
	mustStatus(t, signedAs(t, "before", key1, "PUT", base+"/nodes/before", `{"name":"before","normal":{"n":2}}`), 200)
	// And a brand-new machine bootstraps end to end after the restart.
	key2 := createClientAndKey(t, srv2, base, "after")
	mustStatus(t, signedAs(t, "after", key2, "POST", base+"/nodes", `{"name":"after"}`), 201)
}

// TestPostgresManyClientsBootstrap registers a batch of clients concurrently, as
// a fleet rollout does, and checks every one of them can create its node: group
// membership must not be lost to concurrent writes.
func TestPostgresManyClientsBootstrap(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true, Storage: "postgres", DB: pgtest.NewDatabase(t)})
	base := srv.URL() + "/organizations/acme"
	const n = 12
	type res struct {
		name string
		key  []byte
	}
	out := make(chan res, n)
	for i := range n {
		go func() {
			name := "fleet" + string(rune('a'+i))
			out <- res{name, createClientAndKey(t, srv, base, name)}
		}()
	}
	for range n {
		r := <-out
		mustStatus(t, signedAs(t, r.name, r.key, "POST", base+"/nodes", `{"name":"`+r.name+`"}`), 201)
	}
	members := groupClients(t, srv, base, "clients")
	for i := range n {
		if name := "fleet" + string(rune('a'+i)); !slices.Contains(members, name) {
			t.Errorf("client %s missing from the clients group", name)
		}
	}
}

// groupClients returns the clients listed by GET /groups/<group>, as the admin.
func groupClients(t *testing.T, srv *Server, base, group string) []string {
	t.Helper()
	resp, err := http.DefaultClient.Do(signed(t, srv, "GET", base+"/groups/"+group, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET group %s = %d: %s", group, resp.StatusCode, b)
	}
	var g struct {
		Clients []string `json:"clients"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("decode group: %v", err)
	}
	return g.Clients
}

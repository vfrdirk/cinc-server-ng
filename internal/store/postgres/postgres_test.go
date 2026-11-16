package postgres

import (
	"database/sql"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/backendtest"
	"github.com/cinc-project/cinc-server-ng/internal/store/postgres/pgtest"
)

// testDSN returns a fresh database's DSN (see pgtest.NewDatabase).
func testDSN(t *testing.T) string { return pgtest.NewDatabase(t) }

func open(t *testing.T, dsn string) *Backend {
	t.Helper()
	b, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func TestConformance(t *testing.T) {
	backendtest.Run(t, func(t *testing.T) store.Backend {
		return open(t, testDSN(t))
	})
}

func TestPersistsAcrossReopen(t *testing.T) {
	dsn := testDSN(t)
	b, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Put("acme", "nodes", "web", []byte(`{"n":1}`), store.Stamp{}); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b2 := open(t, dsn)
	got, ok, err := b2.Get("acme", "nodes", "web")
	if err != nil || !ok || string(got) != `{"n":1}` {
		t.Fatalf("after reopen: got=%q ok=%v err=%v", got, ok, err)
	}
}

// When the database is unusable, methods must return an error rather than
// report not-found (which would read as "no such node" to a client).
func TestErrorPropagatesAfterClose(t *testing.T) {
	b, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Get("acme", "nodes", "web"); err == nil {
		t.Error("Get after Close: want error, got nil")
	}
	if err := b.Put("acme", "nodes", "web", []byte(`{}`), store.Stamp{}); err == nil {
		t.Error("Put after Close: want error, got nil")
	}
	if _, err := b.HasOrg("acme"); err == nil {
		t.Error("HasOrg after Close: want error, got nil")
	}
}

func TestOpenUnreachableFails(t *testing.T) {
	_, err := Open("postgres://nobody:secret@127.0.0.1:1/none?connect_timeout=2")
	if err == nil {
		t.Fatal("Open of an unreachable server: want error")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("connection error leaks the password: %v", err)
	}
}

// A database created by the earlier, uncommitted PostgreSQL port: the version-1
// tables with the database's default collation, version 1 recorded, real rows,
// and a table plus trigger owned by another application (SereneDB's
// node_attributes feed). Open must adopt it as is: apply migration 2, keep every
// row, order keys correctly despite the collation, and leave the foreign trigger
// working.
func TestAdoptsPrototypeSchema(t *testing.T) {
	dsn := testDSN(t)
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	mustExec(t, raw, `
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
INSERT INTO schema_migrations VALUES (1);
CREATE TABLE objects (org TEXT NOT NULL, collection TEXT NOT NULL, key TEXT NOT NULL, body BYTEA NOT NULL, PRIMARY KEY (org, collection, key));
CREATE TABLE blobs (org TEXT NOT NULL, checksum TEXT NOT NULL, content BYTEA NOT NULL, PRIMARY KEY (org, checksum));
CREATE TABLE orgs (name TEXT PRIMARY KEY);
INSERT INTO orgs VALUES ('peach');
INSERT INTO objects VALUES ('peach','nodes','web01','{"name":"web01"}'), ('peach','nodes','Zeta','{}'), ('peach','nodes','alpha','{}');
INSERT INTO blobs VALUES ('peach','abc123','file');
CREATE TABLE node_attributes (node_name TEXT, refreshed_at TIMESTAMPTZ);
CREATE FUNCTION objects_node_attributes_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.collection = 'nodes' THEN INSERT INTO node_attributes VALUES (NEW.key, now()); END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER objects_node_attributes_sync AFTER INSERT OR UPDATE ON objects FOR EACH ROW EXECUTE FUNCTION objects_node_attributes_sync();`)

	b := open(t, dsn)
	if v, err := b.Version(); err != nil || v != 2 {
		t.Fatalf("Version = %d, %v; want 2", v, err)
	}
	got, ok, err := b.Get("peach", "nodes", "web01")
	if err != nil || !ok || string(got) != `{"name":"web01"}` {
		t.Fatalf("existing node lost: %q %v %v", got, ok, err)
	}
	if m, ok, err := b.Meta("peach", "nodes", "web01"); err != nil || !ok || !m.CreatedAt.IsZero() || m.UpdatedBy != "" {
		t.Fatalf("pre-migration row should have unknown meta, got %+v %v %v", m, ok, err)
	}
	if c, ok, err := b.Blob("peach", "abc123"); err != nil || !ok || string(c) != "file" {
		t.Fatalf("existing blob lost: %q %v %v", c, ok, err)
	}
	keys, err := b.Keys("peach", "nodes")
	if err != nil {
		t.Fatal(err)
	}
	if !sort.StringsAreSorted(keys) || len(keys) != 3 {
		t.Fatalf("Keys not in byte order on a default-collation table: %v", keys)
	}
	if err := b.Put("peach", "nodes", "web01", []byte(`{"name":"web01","v":2}`), store.Stamp{At: time.Now(), By: "clients/web01"}); err != nil {
		t.Fatal(err)
	}
	var fired int
	if err := raw.QueryRow(`SELECT count(*) FROM node_attributes WHERE node_name='web01'`).Scan(&fired); err != nil || fired != 1 {
		t.Fatalf("foreign trigger did not fire after migration: count=%d err=%v", fired, err)
	}
}

// Servers sharing a database may start together; each runs migrations on Open.
// The advisory lock must make that safe: every Open succeeds and each migration
// is recorded once.
func TestConcurrentOpenMigratesOnce(t *testing.T) {
	dsn := testDSN(t)
	const servers = 6
	var wg sync.WaitGroup
	errs := make(chan error, servers)
	for range servers {
		wg.Go(func() {
			b, err := Open(dsn)
			if err == nil {
				b.Close()
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Open: %v", err)
		}
	}
	b := open(t, dsn)
	var rows int
	if err := b.db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&rows); err != nil || rows != len(migrations) {
		t.Fatalf("schema_migrations rows = %d (%v), want %d", rows, err, len(migrations))
	}
}

func TestRejectsNewerSchema(t *testing.T) {
	dsn := testDSN(t)
	b := open(t, dsn)
	mustExec(t, b.db, `INSERT INTO schema_migrations VALUES (999)`)
	if _, err := Open(dsn); err == nil || !strings.Contains(err.Error(), "999") {
		t.Fatalf("Open of a newer schema: want version error, got %v", err)
	}
}

func TestTxNotReentrant(t *testing.T) {
	b := open(t, testDSN(t))
	err := b.Tx(func(tx store.Backend) error {
		return tx.Tx(func(store.Backend) error { return nil })
	})
	if err == nil {
		t.Fatal("nested Tx: want error")
	}
}

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"postgres://app:s3cret@db.example:5432/cinc_ng?sslmode=require": "postgres://app:xxxxx@db.example:5432/cinc_ng?sslmode=require",
		"postgres://app@db.example/cinc_ng":                             "postgres://app@db.example/cinc_ng",
		"postgres://db.example/cinc_ng?password=s3cret&sslmode=disable": "postgres://db.example/cinc_ng?password=xxxxx&sslmode=disable",
		"host=db user=app password=s3cret dbname=cinc_ng":               "(postgres connection string not shown)",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("exec: %v", err)
	}
}

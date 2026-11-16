// Package pgtest gives tests a fresh, throwaway PostgreSQL database.
//
// Tests that need one call NewDatabase; it skips the test unless
// CINC_SERVER_NG_TEST_POSTGRES names a PostgreSQL server (a postgres:// URL with
// rights to CREATE DATABASE), so `make test` still passes without PostgreSQL.
// CI sets the variable. Each database uses an ICU en-US collation, deliberately
// not byte order, so code that forgets COLLATE "C" fails ordering tests rather
// than passing by luck, and it is dropped when the test ends.
package pgtest

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // "pgx" database/sql driver
)

// EnvVar names the variable holding the server DSN.
const EnvVar = "CINC_SERVER_NG_TEST_POSTGRES"

var seq atomic.Int64

// NewDatabase creates an empty database and returns its DSN.
func NewDatabase(t testing.TB) string {
	t.Helper()
	admin := os.Getenv(EnvVar)
	if admin == "" {
		t.Skip("set " + EnvVar + " to a PostgreSQL DSN to run the postgres backend tests")
	}
	db, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	name := fmt.Sprintf("cincng_test_%d_%d", time.Now().UnixNano(), seq.Add(1))
	if _, err := db.Exec(`CREATE DATABASE ` + name + ` TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER icu ICU_LOCALE 'en-US' LOCALE 'C.UTF-8'`); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`); err != nil {
			t.Logf("drop test database %s: %v", name, err)
		}
	})
	return WithDatabase(t, admin, name)
}

// WithDatabase returns the URL DSN with its database name replaced.
func WithDatabase(t testing.TB, dsn, name string) string {
	t.Helper()
	i := strings.Index(dsn, "://")
	if i < 0 {
		t.Fatalf("%s must be a postgres:// URL, got a key=value DSN", EnvVar)
	}
	hostAndRest := dsn[i+3:]
	query := ""
	if j := strings.IndexByte(hostAndRest, '?'); j >= 0 {
		hostAndRest, query = hostAndRest[:j], hostAndRest[j:]
	}
	if k := strings.IndexByte(hostAndRest, '/'); k >= 0 {
		hostAndRest = hostAndRest[:k]
	}
	return dsn[:i+3] + hostAndRest + "/" + name + query
}

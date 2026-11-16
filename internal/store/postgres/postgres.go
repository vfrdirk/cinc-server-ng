// Package postgres is the durable store.Backend backed by PostgreSQL via the
// pure-Go pgx driver (no cgo). Like the SQLite backend it stores object bodies
// and blob contents opaquely, so the schema is invariant to Chef object shapes,
// and it keeps the same tables and columns, so the two backends describe server
// state the same way.
//
// Where it differs from SQLite, and why:
//
//   - Ordering. Keys, collections and org names must sort as Go's sort.Strings
//     does (byte order). PostgreSQL sorts text by the database collation, which
//     for a typical en_US database is not byte order, so every ORDER BY names
//     COLLATE "C" explicitly rather than trusting the database default.
//   - Concurrency. PostgreSQL admits many concurrent writers, so there is no
//     single-writer pool and no group-commit coalescer; each write is one
//     statement in autocommit, and Tx is a real transaction on one connection.
//   - NUL bytes. PostgreSQL text cannot hold U+0000, but object keys can: the
//     api layer joins group-membership keys with "\x00". Keys, collections
//     and org names are therefore stored through an order-preserving escape
//     (see encodeName), which leaves every name without \x00 or \x01 as is.
//   - Migrations. Two servers can reach one database at once (a failover
//     overlap, a deploy), so migrations run under a session advisory lock:
//     whichever gets there first migrates, the other waits and then finds the
//     work already done. Note that the api layer's search index and group cache
//     are per process, so only one server should be active on a database.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// migrationLock is the advisory-lock key that serializes schema migrations
// across every server sharing a database ("cincng" in ASCII).
const migrationLock int64 = 0x63696e636e67

// A migration is a single, ordered, forward-only schema change. The list is
// APPEND-ONLY: once a version ships, a database somewhere has run it, so it is
// never edited; a mistake is fixed by a new migration. up runs inside a
// transaction.
type migration struct {
	version int
	name    string
	up      func(q querier) error
}

// migrations mirrors the SQLite backend's history version for version, so the
// schema_migrations number means the same thing on both.
var migrations = []migration{
	{
		version: 1,
		name:    "initial schema",
		up: func(q querier) error {
			// Text keys use the "C" collation so the primary-key index is already
			// in byte order. Databases created before this backend (by an earlier
			// PostgreSQL port with the default collation) are not rewritten; the
			// queries below collate explicitly, which is correct for both.
			_, err := q.Exec(`
CREATE TABLE objects (
  org TEXT COLLATE "C" NOT NULL, collection TEXT COLLATE "C" NOT NULL, key TEXT COLLATE "C" NOT NULL,
  body BYTEA NOT NULL, PRIMARY KEY (org, collection, key));
CREATE TABLE blobs (
  org TEXT COLLATE "C" NOT NULL, checksum TEXT COLLATE "C" NOT NULL, content BYTEA NOT NULL,
  PRIMARY KEY (org, checksum));
CREATE TABLE orgs (name TEXT COLLATE "C" PRIMARY KEY);`)
			return err
		},
	},
	{
		version: 2,
		name:    "object times and last actor",
		up: func(q querier) error {
			// Nullable: rows from before this migration have no known times and get
			// none invented (store.Meta reads NULL as unknown). Times are UTC Unix
			// nanoseconds, as in the SQLite backend.
			_, err := q.Exec(`
ALTER TABLE objects ADD COLUMN IF NOT EXISTS created_at BIGINT;
ALTER TABLE objects ADD COLUMN IF NOT EXISTS updated_at BIGINT;
ALTER TABLE objects ADD COLUMN IF NOT EXISTS updated_by TEXT;`)
			return err
		},
	},
}

// querier is the subset of *sql.DB / *sql.Tx / *sql.Conn the data methods use,
// so the same method bodies run directly or inside a transaction.
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

// Backend is a PostgreSQL-backed store.Backend. q is the pool (*sql.DB), or the
// *sql.Tx inside Tx so a transaction reads its own writes. inTx marks that
// transaction view.
type Backend struct {
	db   *sql.DB
	q    querier
	inTx bool
}

// Option configures an optional Backend behavior at Open time.
type Option func(*config)

type config struct {
	maxConns int
}

// WithMaxConns caps the connection pool (default 16). Each server needs few
// connections; the cap keeps a fleet of servers inside the database's
// max_connections.
func WithMaxConns(n int) Option { return func(c *config) { c.maxConns = n } }

// Open connects to the PostgreSQL database named by dsn (a postgres:// URL or a
// libpq key=value string), checks it is reachable, and applies migrations.
func Open(dsn string, opts ...Option) (*Backend, error) {
	cfg := config{maxConns: 16}
	for _, o := range opts {
		o(&cfg)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	db.SetMaxOpenConns(cfg.maxConns)
	db.SetMaxIdleConns(cfg.maxConns)
	db.SetConnMaxIdleTime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close() // already failing; a close error adds nothing
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	b := &Backend{db: db, q: db}
	if err := applyMigrations(db, migrations); err != nil {
		_ = db.Close()
		return nil, err
	}
	return b, nil
}

// Redact returns dsn with any password replaced, for logging. It handles URL
// DSNs; for anything it cannot parse as a URL it returns a fixed placeholder
// rather than risk printing a key=value DSN with its password.
func Redact(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "(postgres connection string not shown)"
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
	}
	q := u.Query()
	if q.Has("password") {
		q.Set("password", "xxxxx")
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// Version returns the database's current schema version (0 if unmigrated).
func (b *Backend) Version() (int, error) { return schemaVersion(b.db) }

func schemaVersion(q querier) (int, error) {
	var v int
	err := q.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&v)
	return v, err
}

// applyMigrations runs every migration in migs newer than the database's
// recorded version, each in its own transaction that also records the version.
// The whole run holds a session advisory lock on one connection, so servers
// starting together migrate one at a time and later ones find nothing to do. A
// database recorded at a higher version than migs knows is rejected (no silent
// downgrade). migs is a parameter so tests can drive synthetic histories.
func applyMigrations(db *sql.DB, migs []migration) error {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("postgres: migrate: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); err != nil {
		return fmt.Errorf("postgres: migration lock: %w", err)
	}
	defer conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, migrationLock) //nolint:errcheck // released with the session anyway

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return fmt.Errorf("schema_migrations: %w", err)
	}
	var current int
	if err := conn.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	last := 0
	if len(migs) > 0 {
		last = migs[len(migs)-1].version
	}
	if current > last {
		return fmt.Errorf("database schema is version %d but this cinc-server-ng only knows up to %d; upgrade the binary", current, last)
	}
	for _, m := range migs {
		if m.version <= current {
			continue
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if err := m.up(tx); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version) VALUES ($1)`, m.version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// encodeName makes s storable in a PostgreSQL text column, which rejects NUL.
// It escapes the two lowest bytes with a prefix code: \x00 becomes \x01\x01
// and \x01 becomes \x01\x02. The mapping is reversible and preserves byte
// order (the code words sort below every other byte, in the same order as the
// bytes they replace, and none is a prefix of another), so ORDER BY ... COLLATE
// "C" on encoded values is sort.Strings order on the originals. Names with
// neither byte, which is every name a Chef client can send, are unchanged, so a
// database written before this escape existed needs no rewrite.
func encodeName(s string) string {
	if !strings.ContainsAny(s, "\x00\x01") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case 0x00:
			b.WriteString("\x01\x01")
		case 0x01:
			b.WriteString("\x01\x02")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// decodeName reverses encodeName. A stored value with a dangling or unknown
// escape cannot have come from encodeName and is returned as an error.
func decodeName(s string) (string, error) {
	if !strings.Contains(s, "\x01") {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != 0x01 {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("postgres: corrupt stored name %q (dangling escape)", s)
		}
		i++
		switch s[i] {
		case 0x01:
			b.WriteByte(0x00)
		case 0x02:
			b.WriteByte(0x01)
		default:
			return "", fmt.Errorf("postgres: corrupt stored name %q (unknown escape)", s)
		}
	}
	return b.String(), nil
}

// body returns val as a non-nil slice: an empty body is a valid object, and a
// nil []byte would be sent as NULL into a NOT NULL column.
func body(val []byte) []byte {
	if val == nil {
		return []byte{}
	}
	return val
}

func (b *Backend) Get(org, coll, key string) ([]byte, bool, error) {
	org, coll, key = encodeName(org), encodeName(coll), encodeName(key)
	var out []byte
	err := b.q.QueryRow(`SELECT body FROM objects WHERE org=$1 AND collection=$2 AND key=$3`, org, coll, key).Scan(&out)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func (b *Backend) Put(org, coll, key string, val []byte, st store.Stamp) error {
	org, coll, key = encodeName(org), encodeName(coll), encodeName(key)
	at, by := nanos(st.At), text(st.By)
	// An update keeps created_at: only a new row takes the stamp as its creation.
	_, err := b.q.Exec(`INSERT INTO objects(org,collection,key,body,created_at,updated_at,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (org,collection,key) DO UPDATE SET body=EXCLUDED.body, updated_at=EXCLUDED.updated_at, updated_by=EXCLUDED.updated_by`,
		org, coll, key, body(val), at, at, by)
	return err
}

func (b *Backend) Create(org, coll, key string, val []byte, st store.Stamp) error {
	org, coll, key = encodeName(org), encodeName(coll), encodeName(key)
	at, by := nanos(st.At), text(st.By)
	res, err := b.q.Exec(`INSERT INTO objects(org,collection,key,body,created_at,updated_at,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (org,collection,key) DO NOTHING`, org, coll, key, body(val), at, at, by)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrConflict
	}
	return nil
}

func (b *Backend) Delete(org, coll, key string) ([]byte, bool, error) {
	org, coll, key = encodeName(org), encodeName(coll), encodeName(key)
	var old []byte
	err := b.q.QueryRow(`DELETE FROM objects WHERE org=$1 AND collection=$2 AND key=$3 RETURNING body`, org, coll, key).Scan(&old)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return old, true, nil
}

func (b *Backend) Keys(org, coll string) ([]string, error) {
	org, coll = encodeName(org), encodeName(coll)
	rows, err := b.q.Query(`SELECT key FROM objects WHERE org=$1 AND collection=$2 ORDER BY key COLLATE "C"`, org, coll)
	if err != nil {
		return nil, err
	}
	return scanStrings(rows)
}

func (b *Backend) Range(org, coll string, fn func(key string, raw []byte) bool) error {
	org, coll = encodeName(org), encodeName(coll)
	rows, err := b.q.Query(`SELECT key, body FROM objects WHERE org=$1 AND collection=$2 ORDER BY key COLLATE "C"`, org, coll)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var raw []byte
		if err := rows.Scan(&k, &raw); err != nil {
			return err
		}
		if k, err = decodeName(k); err != nil {
			return err
		}
		if !fn(k, raw) {
			return nil
		}
	}
	return rows.Err()
}

func (b *Backend) Collections(org string) ([]string, error) {
	org = encodeName(org)
	rows, err := b.q.Query(`SELECT DISTINCT collection COLLATE "C" AS c FROM objects WHERE org=$1 ORDER BY c`, org)
	if err != nil {
		return nil, err
	}
	return scanStrings(rows)
}

func (b *Backend) Meta(org, coll, key string) (store.Meta, bool, error) {
	org, coll, key = encodeName(org), encodeName(coll), encodeName(key)
	var created, updated sql.NullInt64
	var by sql.NullString
	err := b.q.QueryRow(`SELECT created_at, updated_at, updated_by FROM objects WHERE org=$1 AND collection=$2 AND key=$3`,
		org, coll, key).Scan(&created, &updated, &by)
	if errors.Is(err, sql.ErrNoRows) {
		return store.Meta{}, false, nil
	}
	if err != nil {
		return store.Meta{}, false, err
	}
	return store.Meta{CreatedAt: fromNanos(created), UpdatedAt: fromNanos(updated), UpdatedBy: by.String}, true, nil
}

func (b *Backend) SetMeta(org, coll, key string, m store.Meta) error {
	org, coll, key = encodeName(org), encodeName(coll), encodeName(key)
	res, err := b.q.Exec(`UPDATE objects SET created_at=$1, updated_at=$2, updated_by=$3 WHERE org=$4 AND collection=$5 AND key=$6`,
		nanos(m.CreatedAt), nanos(m.UpdatedAt), text(m.UpdatedBy), org, coll, key)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (b *Backend) PutBlob(org, checksum string, data []byte) error {
	org, checksum = encodeName(org), encodeName(checksum)
	_, err := b.q.Exec(`INSERT INTO blobs(org,checksum,content) VALUES($1,$2,$3)
ON CONFLICT (org,checksum) DO UPDATE SET content=EXCLUDED.content`, org, checksum, body(data))
	return err
}

func (b *Backend) Blob(org, checksum string) ([]byte, bool, error) {
	org, checksum = encodeName(org), encodeName(checksum)
	var content []byte
	err := b.q.QueryRow(`SELECT content FROM blobs WHERE org=$1 AND checksum=$2`, org, checksum).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return content, true, nil
}

func (b *Backend) HasBlob(org, checksum string) (bool, error) {
	org, checksum = encodeName(org), encodeName(checksum)
	var one int
	err := b.q.QueryRow(`SELECT 1 FROM blobs WHERE org=$1 AND checksum=$2`, org, checksum).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (b *Backend) DeleteBlob(org, checksum string) error {
	org, checksum = encodeName(org), encodeName(checksum)
	_, err := b.q.Exec(`DELETE FROM blobs WHERE org=$1 AND checksum=$2`, org, checksum)
	return err
}

func (b *Backend) CreateOrg(name string) error {
	name = encodeName(name)
	res, err := b.q.Exec(`INSERT INTO orgs(name) VALUES($1) ON CONFLICT (name) DO NOTHING`, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrConflict
	}
	return nil
}

// DeleteOrg removes the org and everything in it in one transaction, so a
// failure partway cannot leave objects behind an org that no longer exists.
func (b *Backend) DeleteOrg(name string) (bool, error) {
	name = encodeName(name)
	var existed bool
	err := b.atomic(func(q querier) error {
		res, err := q.Exec(`DELETE FROM orgs WHERE name=$1`, name)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if _, err := q.Exec(`DELETE FROM objects WHERE org=$1`, name); err != nil {
			return err
		}
		if _, err := q.Exec(`DELETE FROM blobs WHERE org=$1`, name); err != nil {
			return err
		}
		existed = true
		return nil
	})
	return existed, err
}

func (b *Backend) ListOrgs() ([]string, error) {
	rows, err := b.q.Query(`SELECT name FROM orgs ORDER BY name COLLATE "C"`)
	if err != nil {
		return nil, err
	}
	return scanStrings(rows)
}

func (b *Backend) HasOrg(name string) (bool, error) {
	name = encodeName(name)
	var one int
	err := b.q.QueryRow(`SELECT 1 FROM orgs WHERE name=$1`, name).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Tx runs fn inside a single SQL transaction: returning nil commits, returning a
// non-nil error rolls back and propagates it. The Backend passed to fn routes
// every read and write through the transaction, so it observes its own writes
// and nothing it writes is visible to other connections until commit.
func (b *Backend) Tx(fn func(tx store.Backend) error) error {
	if b.inTx {
		return errors.New("postgres: Tx must not be entered recursively")
	}
	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(&Backend{db: b.db, q: tx, inTx: true}); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// atomic runs fn in a transaction, or directly on the current one when the
// Backend is already a transaction view.
func (b *Backend) atomic(fn func(q querier) error) error {
	if b.inTx {
		return fn(b.q)
	}
	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (b *Backend) Close() error {
	if b.inTx {
		return nil // the transaction view does not own the pool
	}
	return b.db.Close()
}

func scanStrings(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		d, err := decodeName(s)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// nanos stores t as UTC Unix nanoseconds, and the zero time (unknown) as NULL.
func nanos(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixNano()
}

func fromNanos(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(0, n.Int64).UTC()
}

// text stores an empty actor as NULL.
func text(s string) any {
	if s == "" {
		return nil
	}
	return s
}

var _ store.Backend = (*Backend)(nil)

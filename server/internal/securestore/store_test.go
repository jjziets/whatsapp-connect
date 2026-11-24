//go:build libsqlite3

package securestore

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type memoryKeys struct {
	key  []byte
	err  error
	adds int
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func (m *memoryKeys) Get(service, account string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.key == nil {
		return nil, ErrKeyNotFound
	}
	return append([]byte(nil), m.key...), nil
}

func (m *memoryKeys) Add(service, account string, key []byte) error {
	m.adds++
	if m.key != nil {
		return ErrKeyExists
	}
	m.key = append([]byte(nil), key...)
	return nil
}

func TestProfileKeyLifecycle(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "archive.db")
	keys := &memoryKeys{}
	db, err := OpenProfile(path, false, true, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('private-marker-529ef45c')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if len(keys.key) != 32 || keys.adds != 1 {
		t.Fatal("new profile did not create exactly one 256-bit key")
	}
	db, err = OpenProfile(path, true, false, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value string
	if err := db.QueryRow(`SELECT value FROM sample`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "private-marker-529ef45c" || keys.adds != 1 {
		t.Fatal("reopening changed key or content")
	}
}

func TestEncryptedDatabaseRoundTripAndWrongKey(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "archive.db")
	key := bytes.Repeat([]byte{0x6a}, 32)
	db, err := Open(path, false, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('secret-content-a7cd12')`); err != nil {
		t.Fatal(err)
	}
	var mode, cipher string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatal("supported write mode must be WAL")
	}
	if err := db.QueryRow("PRAGMA cipher_version").Scan(&cipher); err != nil || cipher == "" {
		t.Fatal("encrypted engine not active")
	}
	wal, err := os.ReadFile(path + "-wal")
	if err != nil || len(wal) == 0 {
		t.Fatal("test did not exercise a nonempty WAL")
	}
	// Check live WAL as well as the main file; no synthetic marker may be persisted in plaintext.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, readErr := os.ReadFile(path + suffix)
		if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatal(readErr)
		}
		if bytes.Contains(data, []byte("secret-content-a7cd12")) || (suffix == "" && bytes.HasPrefix(data, []byte("SQLite format 3"))) {
			t.Fatal("database or journal contains plaintext")
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	plain := exec.Command("/usr/bin/sqlite3", path, "SELECT value FROM sample")
	if data, err := plain.CombinedOutput(); err == nil || bytes.Contains(data, []byte("secret-content-a7cd12")) {
		t.Fatal("stock SQLite read the encrypted archive")
	}
	if wrong, err := Open(path, true, bytes.Repeat([]byte{0x9c}, 32)); err == nil {
		wrong.Close()
		t.Fatal("wrong key opened encrypted archive")
	}
	db, err = Open(path, true, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value string
	if err := db.QueryRow(`SELECT value FROM sample`).Scan(&value); err != nil || value != "secret-content-a7cd12" {
		t.Fatal("encrypted round trip failed")
	}
}

func TestExistingArchiveNeverReplacesMissingOrDeniedKey(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "archive.db")
	key := bytes.Repeat([]byte{0x5d}, 32)
	db, err := Open(path, false, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE sample(value TEXT)`); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	snapshot := func() map[string][]byte {
		t.Helper()
		out := map[string][]byte{}
		for _, suffix := range []string{"", "-wal", "-shm"} {
			data, err := os.ReadFile(path + suffix)
			if err != nil {
				t.Fatal("expected live archive sidecar:", suffix, err)
			}
			out[suffix] = data
		}
		return out
	}
	before := snapshot()
	unchanged := func() {
		t.Helper()
		after := snapshot()
		for suffix, data := range before {
			if !bytes.Equal(data, after[suffix]) {
				t.Fatal("failed credential access changed archive/sidecar:", suffix)
			}
		}
	}
	for _, keyErr := range []error{ErrKeyNotFound, errors.New("Keychain access denied")} {
		keys := &memoryKeys{err: keyErr}
		if got, err := OpenProfile(path, false, true, keys); err == nil {
			got.Close()
			t.Fatal("existing archive opened without its key")
		}
		if keys.adds != 0 {
			t.Fatal("existing archive triggered replacement key creation")
		}
		unchanged()
	}
	for _, badKey := range [][]byte{[]byte("short"), bytes.Repeat([]byte{0x7f}, 32)} {
		keys := &memoryKeys{key: badKey}
		if got, err := OpenProfile(path, false, true, keys); err == nil {
			got.Close()
			t.Fatal("invalid key opened existing archive")
		}
		if keys.adds != 0 {
			t.Fatal("invalid key triggered replacement creation")
		}
		unchanged()
	}
}

func TestReadNeverCreatesMissingProfile(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "archive.db")
	keys := &memoryKeys{}
	if db, err := OpenProfile(path, true, false, keys); err == nil {
		db.Close()
		t.Fatal("read created missing profile")
	}
	if keys.adds != 0 {
		t.Fatal("read created a key")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("read created archive")
	}
}

func TestInvalidKeyRejectedBeforeCreatingDatabase(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "archive.db")
	if db, err := Open(path, false, []byte("short")); err == nil {
		db.Close()
		t.Fatal("short key accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid key created archive")
	}
}

type indexedKeys struct {
	items map[string][]byte
	adds  int
	race  bool
}

func (m *indexedKeys) Get(service, account string) ([]byte, error) {
	key, ok := m.items[service+"/"+account]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return append([]byte(nil), key...), nil
}
func (m *indexedKeys) Add(service, account string, key []byte) error {
	m.adds++
	index := service + "/" + account
	if _, ok := m.items[index]; ok {
		return ErrKeyExists
	}
	if m.race {
		m.items[index] = bytes.Repeat([]byte{0x29}, 32)
		return ErrKeyExists
	}
	m.items[index] = append([]byte(nil), key...)
	return nil
}

func TestProfilesUseDistinctKeychainItems(t *testing.T) {
	keys := &indexedKeys{items: map[string][]byte{}}
	for _, name := range []string{"first.db", "second.db"} {
		db, err := OpenProfile(filepath.Join(privateTempDir(t), name), false, true, keys)
		if err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
	if len(keys.items) != 2 || keys.adds != 2 {
		t.Fatal("profiles shared a keychain item")
	}
	var values [][]byte
	for _, key := range keys.items {
		values = append(values, key)
	}
	if bytes.Equal(values[0], values[1]) {
		t.Fatal("profiles shared a key")
	}
}

func TestDuplicateCreationUsesWinningKey(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "archive.db")
	keys := &indexedKeys{items: map[string][]byte{}, race: true}
	db, err := OpenProfile(path, false, true, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE sample(value TEXT)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = OpenProfile(path, true, false, keys)
	if err != nil {
		t.Fatal("duplicate-add winner could not reopen archive:", err)
	}
	db.Close()
	if keys.adds != 1 {
		t.Fatal("duplicate-add race created extra keys")
	}
}

// REQ-WC-002/003: preserve a safe numeric cause without exporting engine text.
func TestEncryptedOpenFailureDiagnostic(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "private-diagnostic.db")
	key := bytes.Repeat([]byte{0x42}, 32)
	db, err := Open(path, false, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE private_marker(value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Repeat([]byte{0x43}, 32)
	opened, err := Open(path, true, bad)
	if err == nil {
		opened.Close()
		t.Fatal("wrong key accepted")
	}
	for _, secret := range []string{path, "PRAGMA", "private_marker", strings.Repeat("43", 32)} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("encrypted open error leaked private detail")
		}
	}
	// Structural accessor is deliberate: baseline compiles, then fails on lost cause.
	var diagnostic interface{ SQLiteDiagnostic() (string, int, int) }
	if !errors.As(err, &diagnostic) {
		t.Fatal("encrypted open discarded safe stage and numeric SQLite cause")
	}
	stage, primary, extended := diagnostic.SQLiteDiagnostic()
	if stage != "cipher_verify" || primary != 26 || extended != 26 {
		t.Fatalf("stage=%q primary=%d extended=%d", stage, primary, extended)
	}
}

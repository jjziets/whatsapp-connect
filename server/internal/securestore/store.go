// Package securestore opens encrypted local archives with keys supplied by a secret store.
package securestore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	sqlite "github.com/mattn/go-sqlite3"
)

const keychainService = "com.github.jjziets.whatsapp-connect.archive"

var (
	ErrKeyNotFound       = errors.New("archive key not found in Keychain")
	ErrKeyExists         = errors.New("archive key already exists in Keychain")
	ErrCipherUnavailable = errors.New("SQLCipher is unavailable; use the WhatsApp Connect encrypted build")
)

// KeyStore is a native secret-store boundary; implementations must not log key values.
type KeyStore interface {
	Get(service, account string) ([]byte, error)
	Add(service, account string, key []byte) error
}

// WC-HISTORY-REPAIR-01: preserve only a fixed public message and numeric cause.
// Deliberately retain no underlying error: engine strings can contain private
// SQL, paths or key material, even when a caller formats the error in detail.
type cipherFailure struct {
	stage, message    string
	primary, extended int
}

func (e *cipherFailure) Error() string { return e.message }
func (e *cipherFailure) SQLiteDiagnostic() (string, int, int) {
	return e.stage, e.primary, e.extended
}
func cipherError(stage, message string, cause error) error {
	e := &cipherFailure{stage: stage, message: message}
	var sqlErr sqlite.Error
	if errors.As(cause, &sqlErr) {
		e.primary, e.extended = int(sqlErr.Code), int(sqlErr.ExtendedCode)
	}
	return e
}

// OpenProfile never creates a replacement key for an existing archive.
// The caller may allow a new key only for an explicit new-profile login.
func OpenProfile(path string, readOnly, allowCreate bool, keys KeyStore) (*sql.DB, error) {
	if err := requireCipher(); err != nil {
		return nil, err
	}
	canonical, exists, err := archivePath(path)
	if err != nil {
		return nil, err
	}
	if !exists && (readOnly || !allowCreate) {
		return nil, errors.New("archive is not initialized; run WhatsApp Connect login first")
	}
	if keys == nil {
		return nil, errors.New("native Keychain store is unavailable")
	}
	profile := sha256.Sum256([]byte(canonical))
	account := hex.EncodeToString(profile[:])
	key, err := keys.Get(keychainService, account)
	if errors.Is(err, ErrKeyNotFound) && !exists && allowCreate && !readOnly {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, errors.New("could not generate archive encryption key")
		}
		if err = keys.Add(keychainService, account, key); errors.Is(err, ErrKeyExists) {
			key, err = keys.Get(keychainService, account)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("cannot access archive key; unlock/allow Keychain access and retry; do not delete the archive: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("stored archive key is invalid; preserve the database and restore its Keychain key")
	}
	return Open(canonical, readOnly, key)
}

// Open uses an explicit key for encrypted-engine integration and synthetic tests.
// Production callers obtain the key through OpenProfile; no CLI/env key option exists.
func Open(path string, readOnly bool, key []byte) (*sql.DB, error) {
	if len(key) != 32 {
		return nil, errors.New("archive encryption requires a 256-bit key")
	}
	if err := requireCipher(); err != nil {
		return nil, err
	}
	canonical, exists, err := archivePath(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		if readOnly {
			return nil, errors.New("archive does not exist")
		}
		f, err := os.OpenFile(canonical, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("cannot create private archive: %w", err)
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	} else {
		// Authenticate the existing main file without SQLite reader locks or SHM
		// writes. A wrong key must not alter the live WAL index before rejection.
		probeURL := url.URL{Scheme: "file", Path: canonical}
		probeURL.RawQuery = "mode=ro&immutable=1"
		probeDriver := &sqlite.SQLiteDriver{PreConnectHook: func(c *sqlite.SQLiteConn) error {
			return unlockConnection(c, key)
		}}
		probe, err := probeDriver.Open(probeURL.String())
		if err != nil {
			return nil, err
		}
		if err := probe.Close(); err != nil {
			return nil, err
		}
	}
	// A private copy keeps the driver independent of mutable caller buffers.
	key = append([]byte(nil), key...)
	d := &sqlite.SQLiteDriver{PreConnectHook: func(c *sqlite.SQLiteConn) error {
		if err := unlockConnection(c, key); err != nil {
			return err
		}
		for _, pragma := range []string{"PRAGMA cipher_memory_security=ON", "PRAGMA temp_store=MEMORY", "PRAGMA foreign_keys=ON"} {
			if _, err := c.Exec(pragma, nil); err != nil {
				return cipherError("cipher_config", "could not configure encrypted archive", err)
			}
		}
		modeQuery := "PRAGMA journal_mode"
		if !readOnly {
			modeQuery += "=WAL"
		}
		mode, err := singleValue(c, modeQuery)
		if err != nil || strings.ToLower(mode) != "wal" {
			return cipherError("wal_mode", "encrypted archive requires WAL mode", err)
		}
		return nil
	}}
	u := url.URL{Scheme: "file", Path: canonical}
	params := url.Values{"_busy_timeout": {"10000"}}
	if readOnly {
		params.Set("mode", "ro")
		params.Set("_query_only", "on")
	}
	u.RawQuery = params.Encode()
	db := sql.OpenDB(&connector{d: d, dsn: u.String()})
	db.SetMaxOpenConns(4)
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func unlockConnection(c *sqlite.SQLiteConn, key []byte) error {
	// Construct key material only in process memory, never in a DSN or log.
	if _, err := c.Exec(`PRAGMA key = "x'`+hex.EncodeToString(key)+`'"`, nil); err != nil {
		return cipherError("cipher_key", "could not initialize encrypted archive key", err)
	}
	if _, err := singleValue(c, "SELECT count(*) FROM sqlite_master"); err != nil {
		return cipherError("cipher_verify", "archive cannot be decrypted; preserve it and check its Keychain key", err)
	}
	return nil
}

func archivePath(path string) (string, bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false, errors.New("invalid archive path")
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", false, fmt.Errorf("archive directory is unavailable: %w", err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return "", false, errors.New("archive parent must be a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", false, errors.New("archive directory must have owner-only permissions (0700)")
	}
	canonical := filepath.Join(dir, filepath.Base(abs))
	info, err = os.Lstat(canonical)
	if os.IsNotExist(err) {
		return canonical, false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", false, errors.New("archive must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", false, errors.New("archive must have owner-only permissions (0600)")
	}
	return canonical, true, nil
}

func requireCipher() error {
	d := &sqlite.SQLiteDriver{}
	raw, err := d.Open(":memory:")
	if err != nil {
		return ErrCipherUnavailable
	}
	defer raw.Close()
	c, ok := raw.(*sqlite.SQLiteConn)
	if !ok {
		return ErrCipherUnavailable
	}
	version, err := singleValue(c, "PRAGMA cipher_version")
	if err != nil || version == "" {
		return ErrCipherUnavailable
	}
	return nil
}

func singleValue(c *sqlite.SQLiteConn, query string) (string, error) {
	rows, err := c.Query(query, nil)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	values := make([]driver.Value, len(rows.Columns()))
	if err := rows.Next(values); err != nil {
		return "", err
	}
	if len(values) == 0 {
		return "", io.EOF
	}
	switch v := values[0].(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		return fmt.Sprint(v), nil
	}
}

type connector struct {
	d   *sqlite.SQLiteDriver
	dsn string
}

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.d.Open(c.dsn)
}
func (c *connector) Driver() driver.Driver { return c.d }

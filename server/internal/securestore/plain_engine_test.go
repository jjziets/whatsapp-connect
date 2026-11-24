//go:build !libsqlite3

package securestore

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

// This is an explicit negative build lane using the stock bundled SQLite engine.
func TestPlainSQLiteBuildRefusesSecureOpen(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "archive.db"), false, bytes.Repeat([]byte{0x51}, 32))
	if db != nil {
		db.Close()
	}
	if !errors.Is(err, ErrCipherUnavailable) {
		t.Fatalf("ordinary SQLite must be rejected; got %v", err)
	}
}

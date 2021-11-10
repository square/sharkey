package storage

import (
	"database/sql"
	"testing"

	"github.com/square/sharkey/pkg/server/config"
	"github.com/stretchr/testify/require"
)

func purge(t *testing.T, db *sql.DB) {
	_, err := db.Exec("DROP TABLE IF EXISTS hostkeys")
	require.NoError(t, err)
	_, err = db.Exec("DROP TABLE IF EXISTS github_user_mappings")
	require.NoError(t, err)
	_, err = db.Exec("DROP TABLE IF EXISTS goose_db_version")
	require.NoError(t, err)

	rows, err := db.Query("show tables")
	require.NoError(t, err)
	require.False(t, rows.Next(), "All tables should have been cleaned up")
}

// TestMysql verifies the MySQL storage interface is respected.
// Because it requires a running MySQL database, you can skip it with `go test -short`
// It expects a Mysql running on localhost:3306 with the username root, password 'root', and a database
// named sharkey_test, as our CI environment provides.  That database will have its tables dropped.
// Don't run tests in prod, and don't call your prod DB sharkey_test.
func TestMysql(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping tests in MySQL mode")
	} else {
		t.Log("Testing against MySQL in non-short mode: Try `go test -short` to skip this")
	}

	cfg := config.Database{
		Type:     "mysql",
		Schema:   "sharkey_test",
		Username: "root",
		Password: "root",
	}

	storage, err := NewMysql(cfg)
	require.NoError(t, err)

	// Drop data (if left over from previous test runs)
	purge(t, storage.DB)

	// Run migrations.
	require.NoError(t, storage.Migrate("../../../db/mysql/migrations"))

	require.NoError(t, storage.Ping())

	testStorage(t, storage)
	testGitHubStorage(t, storage)

	// Drop data after test finishes
	purge(t, storage.DB)
}

package storage

import (
	"os"
	"testing"

	"github.com/square/sharkey/pkg/server/config"
	"github.com/stretchr/testify/require"
)

func TestSqlite(t *testing.T) {
	dbfile, err := os.CreateTemp("", "sharkey-test-db")
	require.NoError(t, err)
	defer os.Remove(dbfile.Name())

	cfg := config.Database{Address: dbfile.Name()}
	storage, err := NewSqlite(cfg)
	require.NoError(t, err)
	require.NoError(t, storage.Migrate("../../../db/sqlite/migrations"))

	testStorage(t, storage)
	testGitHubStorage(t, storage)
}

package storage

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/square/sharkey/pkg/server/config"
	"github.com/stretchr/testify/require"
)

func TestSqlite(t *testing.T) {
	dbfile, err := ioutil.TempFile("", "sharkey-test-db")
	require.NoError(t, err)
	defer os.Remove(dbfile.Name())

	cfg := config.Database{Address: dbfile.Name()}
	storage, err := NewSqlite(cfg)
	require.NoError(t, err)
	require.NoError(t, storage.Migrate("../../../db/sqlite/migrations"))

	testStorage(t, storage)
}

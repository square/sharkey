package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testStorage validates a Storage implementation.  Used by other tests.
func testStorage(t *testing.T, storage Storage) {
	id1, err := storage.RecordIssuance(ssh.HostCert, "theHostName", "somePubKey")
	require.NoError(t, err)

	id2, err := storage.RecordIssuance(ssh.HostCert, "other", "something")
	require.NoError(t, err)

	assert.NotEqual(t, id1, id2, "Expected different IDs for different hostnames")

	rows, err := storage.QueryHostkeys()
	require.NoError(t, err)
	require.True(t, rows.Next())
	hostname, pubkey, err := rows.Get()
	require.NoError(t, err)
	require.Equal(t, "theHostName", hostname)
	require.Equal(t, "somePubKey", pubkey)

	require.True(t, rows.Next())
	hostname, pubkey, err = rows.Get()
	require.NoError(t, err)
	require.Equal(t, "other", hostname)
	require.Equal(t, "something", pubkey)

	require.False(t, rows.Next())
}

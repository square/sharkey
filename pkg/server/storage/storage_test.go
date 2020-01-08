package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testStorage validates a Storage implementation.  Used by other tests.
func testStorage(t *testing.T, storage Storage) {
	testKeyA, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJRDfioJ5P2ieBb8sqUxDjxuZMjY5l+dEfUVzpSvv1E7 testkey"))
	require.NoError(t, err)
	testKeyB, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHFj3LLnX2LAeYxaXfYQxsCZ8gJaIQB07Rr/OkefJGLjE+xpYb5OJ3t3q2bN9hWfw0C3NTwfaoxQ5B7nvIE7Mq4="))
	require.NoError(t, err)

	id1, err := storage.RecordIssuance(ssh.HostCert, "theHostName", testKeyA)
	require.NoError(t, err)

	id2, err := storage.RecordIssuance(ssh.HostCert, "other", testKeyB)
	require.NoError(t, err)

	assert.NotEqual(t, id1, id2, "Expected different IDs for different hostnames")

	rows, err := storage.QueryHostkeys()
	require.NoError(t, err)
	require.True(t, rows.Next())
	hostname, pubkey, err := rows.Get()
	require.NoError(t, err)
	require.Equal(t, "theHostName", hostname)
	require.Equal(t, testKeyA, pubkey)

	require.True(t, rows.Next())
	hostname, pubkey, err = rows.Get()
	require.NoError(t, err)
	require.Equal(t, "other", hostname)
	require.Equal(t, testKeyB, pubkey)

	require.False(t, rows.Next())
}

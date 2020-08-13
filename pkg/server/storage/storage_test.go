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

func testGitHubStorage(t *testing.T, storage Storage) {
	username1 := "alice"
	gitUsername1 := "alice_git"
	username2 := "bob"
	gitUsername2 := "bob_git"
	initialMapping := map[string]string{
		username1: gitUsername1,
		username2: gitUsername2,
	}
	err := storage.RecordGitHubMapping(initialMapping)
	require.NoError(t, err)

	queriedUsername1, err := storage.QueryGitHubMapping(username1)
	require.NoError(t, err)
	require.Equal(t, queriedUsername1, gitUsername1)

	queriedUsername2, err := storage.QueryGitHubMapping(username2)
	require.NoError(t, err)
	require.Equal(t, queriedUsername2, gitUsername2)

	username3 := "carol"
	gitUsername3 := "carol_git"
	modifiedGitUsername1 := "alice_git_modified"
	updatedMapping := map[string]string{
		username3: gitUsername3,
		username1: modifiedGitUsername1,
	}

	err = storage.RecordGitHubMapping(updatedMapping)
	require.NoError(t, err)

	queriedModifiedUsername1, err := storage.QueryGitHubMapping(username1)
	require.NoError(t, err)
	require.Equal(t, queriedModifiedUsername1, modifiedGitUsername1)

	queriedUsername3, err := storage.QueryGitHubMapping(username3)
	require.NoError(t, err)
	require.Equal(t, queriedUsername3, gitUsername3)
}

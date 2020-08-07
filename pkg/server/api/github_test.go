package api

import (
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/square/sharkey/pkg/server/config"
	"github.com/square/sharkey/pkg/server/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmptyGitHubUser(t *testing.T) {
	hostname := "proxy"
	header := "X-Forwarded-User"
	c, err := generateContext(t)
	require.NoError(t, err)

	// set auth proxy
	c.conf.AuthenticatingProxy = &config.AuthenticatingProxy{
		Hostname:       hostname,
		UsernameHeader: header,
	}
	c.conf.GitHub.Enabled = true

	hook := test.NewLocal(c.logger)

	for i := 0; i < 5; i++ {
		request, err := generateUserRequest(hostname)
		request.Header.Set(header, "alice")
		require.NoError(t, err, "Error reading test ssh key")

		rr := httptest.NewRecorder()
		c.EnrollUser(rr, request)

		assert.Equal(t, 2, len(hook.Entries))
		assert.Equal(t, logrus.ErrorLevel, hook.Entries[0].Level)
		assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
		assert.Equal(t, "call EnrollUser", hook.LastEntry().Message)
		assert.Contains(t, hook.LastEntry().Data, "Type")
		assert.Contains(t, hook.LastEntry().Data, "Public Key")
		assert.Contains(t, hook.LastEntry().Data, "user")
		assert.Contains(t, hook.Entries[0].Message, "no rows in result set")

		res := rr.Result()
		body, err := ioutil.ReadAll(res.Body)
		fmt.Println(string(body))
		require.NoError(t, err, "unexpected error reading body")
		require.Equal(t, 200, res.StatusCode, "failed to enroll user")
		hook.Reset()
	}
}

func TestGitHubUser(t *testing.T) {
	hostname := "proxy"
	header := "X-Forwarded-User"
	c, err := generateContext(t)
	require.NoError(t, err)

	// set auth proxy
	c.conf.AuthenticatingProxy = &config.AuthenticatingProxy{
		Hostname:       hostname,
		UsernameHeader: header,
	}
	c.conf.GitHub.Enabled = true

	sqlite, err := storage.NewSqlite(config.Database{Address: ":memory:"})
	require.NoError(t, err)
	err = sqlite.Migrate("../../../db/sqlite/migrations")
	require.NoError(t, err)
	err = sqlite.RecordGitHubMapping(map[string]string{"alice": "alice"})
	require.NoError(t, err)
	c.storage = sqlite

	hook := test.NewLocal(c.logger)

	for i := 0; i < 5; i++ {
		request, err := generateUserRequest(hostname)
		request.Header.Set(header, "alice")
		require.NoError(t, err, "Error reading test ssh key")

		rr := httptest.NewRecorder()
		c.EnrollUser(rr, request)

		assert.Equal(t, 1, len(hook.Entries))
		assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
		assert.Equal(t, "call EnrollUser", hook.LastEntry().Message)
		assert.Contains(t, hook.LastEntry().Data, "Type")
		assert.Contains(t, hook.LastEntry().Data, "Public Key")
		assert.Contains(t, hook.LastEntry().Data, "user")

		res := rr.Result()
		body, err := ioutil.ReadAll(res.Body)
		fmt.Println(string(body))
		require.NoError(t, err, "unexpected error reading body")
		require.Equal(t, 200, res.StatusCode, "failed to enroll user")
		hook.Reset()
	}
}

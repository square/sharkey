package api

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/armon/go-metrics"
	"github.com/shurcooL/githubv4"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/square/sharkey/pkg/server/config"
	"github.com/square/sharkey/pkg/server/storage"
	"github.com/square/sharkey/pkg/server/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type localRoundTripper struct {
	handler http.Handler
}

func (l localRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	l.handler.ServeHTTP(w, req)
	return w.Result(), nil
}

const sampleGitHubApiResult = `
{
  "data": {
    "organization": {
      "samlIdentityProvider": {
        "externalIdentities": {
          "edges": [
            {
              "node": {
                "guid": "1234567890",
                "samlIdentity": {
                  "nameId": "alice"
                },
                "user": {
                  "login": "alice_git"
                }
              }
            },
            {
              "node": {
                "guid": "1234567891",
                "samlIdentity": {
                  "nameId": "bob"
                },
                "user": {
                  "login": "bob_git"
                }
              }
            },
            {
              "node": {
                "guid": "1234567892",
                "samlIdentity": {
                  "nameId": "carol"
                },
                "user": {
                  "login": "carol_git"
                }
              }
            }
          ],
		  "pageInfo": {
            "hasNextPage": false,
            "endCursor": ""
          }
        }
      }
    }
  }
}
`

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
	c.conf.GitHub.IncludeUserIdentity = true

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

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(body))
		require.NoError(t, err, "unexpected error parsing public key")
		_, ok := pubKey.(*ssh.Certificate).Extensions["login@github.com"]
		assert.Equal(t, ok, false)

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
	c.conf.GitHub.IncludeUserIdentity = true

	sqlite, err := storage.NewSqlite(config.Database{Address: ":memory:"})
	require.NoError(t, err)
	err = sqlite.Migrate("../../../db/sqlite/migrations")
	require.NoError(t, err)
	err = sqlite.RecordGitHubMapping(map[string]string{"alice": "alice_git"})
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

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(body))
		require.NoError(t, err, "unexpected error parsing public key")
		assert.Equal(t, pubKey.(*ssh.Certificate).Extensions["login@github.com"], "alice_git")

		hook.Reset()
	}
}

func TestGitHubFetchMapping(t *testing.T) {
	c, err := generateContext(t)
	require.NoError(t, err)
	c.telemetry = &telemetry.Telemetry{
		Sink: metrics.NewInmemSink(10*time.Second, time.Minute),
	}
	c.gitHubClient = mockGitHubClient(t)

	mapping, err := c.fetchUserMappings()
	require.NoError(t, err, "error fetching github user mappings")
	assert.Equal(t, len(mapping), 3)
	assert.Equal(t, mapping["alice"], "alice_git")

	inMemSink := c.telemetry.Sink.(*metrics.InmemSink)
	assert.Equal(t, len(inMemSink.Data()), 1)
	assert.Equal(t, len(inMemSink.Data()[0].Gauges), 2)
	assert.Equal(t, inMemSink.Data()[0].Gauges["github_fetched_users"].Value, float32(3))
	assert.GreaterOrEqual(t, inMemSink.Data()[0].Gauges["github_fetch_latency"].Value, float32(100))
	assert.Equal(t, len(inMemSink.Data()[0].Counters), 1)
	assert.Equal(t, inMemSink.Data()[0].Counters["github_fetches"].Count, 1)
}

func mockGitHubClient(t *testing.T) *githubv4.Client {
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(100 * time.Millisecond)
		assert.Equal(t, req.Method, http.MethodPost)
		w.Header().Set("Content-Type", "application/json")
		_, err := io.WriteString(w, sampleGitHubApiResult)
		require.NoError(t, err)
	})
	return githubv4.NewClient(&http.Client{Transport: localRoundTripper{handler: mux}})
}

/*-
 * Copyright 2016 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package api

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/square/sharkey/pkg/server/config"
	"github.com/square/sharkey/pkg/server/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	testKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsfClUt72oaV+J4mAe3XK1nPqXn9ISTxRNj" +
		"giXNYhmVvluwrtS5o0Fwc144c1pqW38QilcvCNmaiXvPxdaSyzTnVCg8UGlNsa/Fwz5Lc/hojAoQCitiRxBna81VSGZI" +
		"Ob79JD4lVxGxDOfVykfvjo4KzfDE4stMPixW6grDlpUsb6MVELUB1jcyx+j6RVctPYuRtZKLI/5SX6NGWK3H6P68IhY+" +
		"2MKYIc6+TItabryI0cNTIcjkPyetAo2T1BOl8sPeukIvX3zG2NrxxinXrEWScYpsuoewvuCYdc/+fY2o498PwM+asCpQ" +
		"i+3IRj7siWEDLwK0kga+aYrwyO2/TiB"
)

func TestValidClient(t *testing.T) {
	goodName := "goodname"
	badName := "badname"
	request, err := generateHostRequest()
	require.NoError(t, err, "error reading test ssh key")

	res := clientHostnameMatches(badName, request)
	require.False(t, res, "thought a bad client was valid")

	res = clientHostnameMatches(goodName, request)
	require.True(t, res, "thought a good client was invalid")
}

func TestSignHost(t *testing.T) {
	c, err := generateContext(t)
	require.NoError(t, err)

	data, err := ioutil.ReadFile("testdata/ssh_host_rsa_key.pub")
	require.NoError(t, err)

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	require.NoError(t, err)

	cert, err := c.signHost("hostname.square", 42, pubkey)
	require.NoError(t, err, "SignHost method returned an error")
	require.Equal(t, uint64(42), cert.Serial, "Incorrect cert serial number")
	require.Equal(t, "hostname.square", cert.KeyId, "Cert pubkey doesn't match")
	require.Equal(t, pubkey, cert.Key, "Cert pubkey doesn't match")
	require.Contains(t, cert.ValidPrincipals, "hostname.square")
	require.Contains(t, cert.ValidPrincipals, "alias.square")
}

func TestEnrollHost(t *testing.T) {
	c, err := generateContext(t)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		request, err := generateHostRequest()
		require.NoError(t, err, "Error reading test ssh key")

		_, err = c.EnrollHost("goodname", request)
		require.NoError(t, err, "Error enrolling host")
	}
}

func TestEnrollUser(t *testing.T) {
	hostname := "proxy"
	header := "X-Forwarded-User"
	c, err := generateContext(t)
	require.NoError(t, err)

	// set auth proxy
	c.conf.AuthenticatingProxy = &config.AuthenticatingProxy{
		Hostname:       hostname,
		UsernameHeader: header,
	}

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

func TestEnrollUserNoProxyConfigured(t *testing.T) {
	c, err := generateContext(t)
	require.NoError(t, err)
	hook := test.NewLocal(c.logger)

	request, err := generateUserRequest("proxy")
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	c.EnrollUser(rr, request)

	assert.Equal(t, 1, len(hook.Entries))
	assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
	assert.Equal(t, "logHttpError", hook.LastEntry().Message)
	assert.Equal(t, errors.New("client certificates are unavailable"), hook.LastEntry().Data["error"])
	assert.Contains(t, hook.LastEntry().Data, "method")
	assert.Contains(t, hook.LastEntry().Data, "url")
	assert.Contains(t, hook.LastEntry().Data, "code")

	res := rr.Result()
	_, err = ioutil.ReadAll(res.Body)
	require.NoError(t, err, "unexpected error reading body")
	require.Equal(t, 404, res.StatusCode, "expected 404 for unconfigured proxy")
}

func TestEnrollNoAuthedUser(t *testing.T) {
	hostname := "proxy"
	c, err := generateContext(t)
	require.NoError(t, err)
	hook := test.NewLocal(c.logger)

	// set auth proxy
	c.conf.AuthenticatingProxy = &config.AuthenticatingProxy{
		Hostname: hostname,
	}

	request, err := generateUserRequest(hostname)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	c.EnrollUser(rr, request)

	assert.Equal(t, "logHttpError", hook.LastEntry().Message)
	assert.Equal(t, errors.New("no username supplied"), hook.LastEntry().Data["error"])
	assert.Contains(t, hook.LastEntry().Data, "method")
	assert.Contains(t, hook.LastEntry().Data, "url")
	assert.Contains(t, hook.LastEntry().Data, "code")

	res := rr.Result()
	_, err = ioutil.ReadAll(res.Body)
	require.NoError(t, err, "unexpected error reading body")
	require.Equal(t, 401, res.StatusCode, "expected 401 for unauthed user")
}

func TestEnrollWrongProxyDomain(t *testing.T) {
	hostname := "proxy"
	header := "X-Forwarded-User"
	c, err := generateContext(t)
	require.NoError(t, err)
	hook := test.NewLocal(c.logger)

	// set auth proxy
	c.conf.AuthenticatingProxy = &config.AuthenticatingProxy{
		Hostname:       hostname,
		UsernameHeader: header,
	}

	request, err := generateUserRequest("notproxy.com")
	request.Header.Set(header, "alice")
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	c.EnrollUser(rr, request)

	assert.Equal(t, "logHttpError", hook.LastEntry().Message)
	assert.Equal(t, errors.New("request didn't come from proxy"), hook.LastEntry().Data["error"])
	assert.Contains(t, hook.LastEntry().Data, "method")
	assert.Contains(t, hook.LastEntry().Data, "url")
	assert.Contains(t, hook.LastEntry().Data, "code")

	res := rr.Result()
	_, err = ioutil.ReadAll(res.Body)
	require.NoError(t, err, "unexpected error reading body")
	require.Equal(t, 401, res.StatusCode, "expected 401 for requets not from proxy")
}

func TestGetAuthority(t *testing.T) {
	c, err := generateContext(t)
	require.NoError(t, err)

	req, err := generateHostRequest()
	require.NoError(t, err, "Error reading test ssh key")

	rec := httptest.NewRecorder()
	c.Authority(rec, req)

	rec.Flush()
	require.Equalf(t, 200, rec.Code, "Request to /authority failed with %d", rec.Code)

	body, _ := ioutil.ReadAll(rec.Body)
	expected, err := ioutil.ReadFile("testdata/server_ca.pub")
	require.NoError(t, err, "Error reading testdata")

	require.Equalf(t, []byte(fmt.Sprintf("@cert-authority * %s", expected)), body,
		"Request body from /authority unexpectedly returned '%s'", string(body))
}

func TestGetKnownHosts(t *testing.T) {
	c, err := generateContext(t)
	require.NoError(t, err)

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testKey))
	require.NoError(t, err)

	_, err = c.storage.RecordIssuance(ssh.HostCert, "hostname", pubkey)
	require.NoError(t, err)

	result, err := c.GetKnownHosts()
	require.NoError(t, err)

	results := strings.Split(result, "\n")
	assert.EqualValues(t, 3, len(results))
	assert.Equal(t, "@certificate-authority * pubkey", results[0])
	assert.Equal(t, "hostname "+testKey, results[1])
	assert.Equal(t, "", results[2])
}

func TestStatus(t *testing.T) {
	c, err := generateContext(t)
	require.NoError(t, err)

	req, err := generateHostRequest()
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	c.Status(rec, req)

	rec.Flush()
	require.Equalf(t, 200, rec.Code, "Request to /_status failed with %d", rec.Code)

	body, _ := ioutil.ReadAll(rec.Body)
	expected := []byte(`{"ok":true,"status":"ok","messages":[]}`)

	require.Equalf(t, expected, body,
		"Request body from /_status unexpectedly returned '%s'", string(body))

	require.Equalf(t, "application/json", rec.Header().Get("Content-Type"),
		"Expected Content-Type to be set to 'application/json', but instead got %s", rec.Header().Get("Content-Type"))
}

func generateContext(t *testing.T) (*Api, error) {
	conf := &config.Config{
		SigningKey:       "testdata/server_ca",
		HostCertDuration: "160h",
		UserCertDuration: "8h",
		Aliases: map[string][]string{
			"hostname.square": []string{"alias.square"},
		},
		ExtraKnownHosts: []string{
			"@certificate-authority * pubkey",
		},
	}

	key, err := ioutil.ReadFile(conf.SigningKey)
	require.NoError(t, err)

	signer, err := ssh.ParsePrivateKey(key)
	require.NoError(t, err)

	logger := logrus.New()

	// in-memory sqlite: see https://github.com/mattn/go-sqlite3 for address docs
	sqlite, err := storage.NewSqlite(config.Database{Address: ":memory:"})
	require.NoError(t, err)
	err = sqlite.Migrate("../../../db/sqlite/migrations")
	require.NoError(t, err)

	c := &Api{
		signer:  signer,
		storage: sqlite,
		conf:    conf,
		logger:  logger,
	}

	return c, nil
}

func generateRequest(cn string, body io.ReadCloser) (*http.Request, error) {
	sub := pkix.Name{
		CommonName: cn,
	}
	cert := x509.Certificate{
		Subject: sub,
	}
	chain := [][]*x509.Certificate{{&cert}}
	conn := tls.ConnectionState{
		VerifiedChains: chain,
	}

	request := http.Request{
		TLS:    &conn,
		Body:   body,
		Header: http.Header{},
	}
	return &request, nil
}

func generateUserRequest(commonName string) (*http.Request, error) {
	key, err := os.Open("testdata/ssh_alice_rsa.pub")
	if err != nil {
		return nil, err
	}
	return generateRequest(commonName, ioutil.NopCloser(key))
}

func generateHostRequest() (*http.Request, error) {
	key, err := os.Open("testdata/ssh_host_rsa_key.pub")
	if err != nil {
		return nil, err
	}
	return generateRequest("goodname", ioutil.NopCloser(key))
}

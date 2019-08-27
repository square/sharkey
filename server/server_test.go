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

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/square/sharkey/server/config"
	"github.com/square/sharkey/server/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh"
)

func TestValidClient(t *testing.T) {
	goodName := "goodname"
	badName := "badname"
	request, err := generateRequest()
	if err != nil {
		t.Fatalf("Error reading test ssh key: %s", err.Error())
	}
	if clientHostnameMatches(badName, request) {
		t.Fatalf("thought a bad client was valid")
	}
	if !clientHostnameMatches(goodName, request) {
		t.Fatalf("thought a good client was invalid")
	}
}

func TestSignHost(t *testing.T) {
	c, err := generateContext(t)
	if err != nil {
		t.Fatalf("error generating context: %s", err.Error())
	}
	data, err := ioutil.ReadFile("testdata/ssh_host_rsa_key.pub")
	if err != nil {
		t.Fatalf("error reading test ssh host key: %s", err.Error())
	}
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatalf("error parsing test ssh host key: %s", err.Error())
	}

	cert, err := c.signHost("hostname.square", 42, pubkey)
	if err != nil {
		t.Fatalf("SignHost method returned an error: %s", err.Error())
	}
	if cert.Serial != 42 {
		t.Fatalf("Incorrect cert serial number: %s", err.Error())
	}
	if cert.KeyId != "hostname.square" {
		t.Fatal("Incorrect cert keyId")
	}
	if cert.Key != pubkey {
		t.Fatal("Cert pubkey doesn't match")
	}
	assertPrincipal(t, cert.ValidPrincipals, "hostname.square")
	assertPrincipal(t, cert.ValidPrincipals, "alias.square")
}

func assertPrincipal(t *testing.T, principals []string, expected string) {
	for _, principal := range principals {
		if principal == expected {
			return
		}
	}
	t.Errorf("cert is missing expected principal: %s", expected)
}

func TestEnrollHost(t *testing.T) {
	c, err := generateContext(t)
	if err != nil {
		t.Fatalf("Error generating context: %s", err.Error())
	}

	for i := 0; i < 5; i++ {
		request, err := generateRequest()
		if err != nil {
			t.Fatalf("Error reading test ssh key: %s", err.Error())
		}
		_, err = c.EnrollHost("goodname", request)
		if err != nil {
			t.Fatalf("Error enrolling host: %s", err.Error())
		}
	}
}

func TestGetAuthority(t *testing.T) {
	c, err := generateContext(t)
	if err != nil {
		t.Fatalf("Error generating context: %s", err)
	}

	req, err := generateRequest()
	if err != nil {
		t.Fatalf("Error generating context: %s", err)
	}

	rec := httptest.NewRecorder()
	c.Authority(rec, req)

	rec.Flush()
	if rec.Code != 200 {
		t.Fatalf("Request to /authority failed with %d", rec.Code)
	}

	body, _ := ioutil.ReadAll(rec.Body)
	expected, err := ioutil.ReadFile("testdata/server_ca.pub")
	if err != nil {
		t.Fatalf("Error reading testdata: %s", err)
	}

	if !bytes.Equal(body, []byte(fmt.Sprintf("@cert-authority * %s", expected))) {
		t.Fatalf("Request body from /authority unexpectedly returned '%s'", string(body))
	}
}

const testKey string = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsfClUt72oaV+J4mAe3XK1nPqXn9ISTxRNj" +
	"giXNYhmVvluwrtS5o0Fwc144c1pqW38QilcvCNmaiXvPxdaSyzTnVCg8UGlNsa/Fwz5Lc/hojAoQCitiRxBna81VSGZI" +
	"Ob79JD4lVxGxDOfVykfvjo4KzfDE4stMPixW6grDlpUsb6MVELUB1jcyx+j6RVctPYuRtZKLI/5SX6NGWK3H6P68IhY+" +
	"2MKYIc6+TItabryI0cNTIcjkPyetAo2T1BOl8sPeukIvX3zG2NrxxinXrEWScYpsuoewvuCYdc/+fY2o498PwM+asCpQ" +
	"i+3IRj7siWEDLwK0kga+aYrwyO2/TiB"

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

	req, err := generateRequest()
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	c.Status(rec, req)

	rec.Flush()
	if rec.Code != 200 {
		t.Fatalf("Request to /_status failed with %d", rec.Code)
	}

	body, _ := ioutil.ReadAll(rec.Body)
	expected := []byte(`{"ok":true,"status":"ok","messages":[]}`)

	if !bytes.Equal(body, expected) {
		t.Fatalf("Request body from /_status unexpectedly returned '%s'", string(body))
	}

	if contentType := rec.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("Expected Content-Type to be set to 'application/json', but instead got %s", contentType)
	}
}

func generateContext(t *testing.T) (*context, error) {
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

	// in-memory sqlite: see https://github.com/mattn/go-sqlite3 for address docs
	sqlite, err := storage.NewSqlite(config.Database{Address: ":memory:"})
	require.NoError(t, err)
	err = sqlite.Migrate("../db/sqlite/migrations")
	require.NoError(t, err)

	c := &context{
		signer:  signer,
		storage: sqlite,
		conf:    conf,
	}

	return c, nil
}

func generateRequest() (*http.Request, error) {
	sub := pkix.Name{
		CommonName: "goodname",
	}
	cert := x509.Certificate{
		Subject: sub,
	}
	chain := [][]*x509.Certificate{{&cert}}
	conn := tls.ConnectionState{
		VerifiedChains: chain,
	}
	key, err := os.Open("testdata/ssh_host_rsa_key.pub")
	if err != nil {
		return nil, err
	}
	readCloser := ioutil.NopCloser(key)
	request := http.Request{
		TLS:  &conn,
		Body: readCloser,
	}
	return &request, nil
}

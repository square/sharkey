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
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

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
	c, err := generateContext()
	if err != nil {
		t.Fatalf("error generating context: %s", err.Error())
	}
	defer c.db.Close()
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
	c, err := generateContext()
	if err != nil {
		t.Fatalf("Error generating context: %s", err.Error())
	}
	defer c.db.Close()

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
	c, err := generateContext()
	if err != nil {
		t.Fatalf("Error generating context: %s", err)
	}
	defer c.db.Close()

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

func TestGetKnownHosts(t *testing.T) {
	c, err := generateContext()
	if err != nil {
		t.Fatalf("Error generating context: %s", err.Error())
	}
	defer c.db.Close()
	result, err := c.GetKnownHosts()
	if err != nil {
		t.Fatal("Error getting known hosts")
	}
	results := strings.Split(result, "\n")
	if results[0] != "@certificate-authority * pubkey" {
		t.Fatal("Incorrect known hosts format")
	}
	if results[1] != "hostname pubkey" {
		t.Fatal("Incorrect known hosts format")
	}
}

func TestStatus(t *testing.T) {
	c, err := generateContext()
	if err != nil {
		t.Fatalf("Error generating context: %s", err)
	}
	defer c.db.Close()

	req, err := generateRequest()
	if err != nil {
		t.Fatalf("Error generating context: %s", err)
	}

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

func generateContext() (*context, error) {
	db, err := generateDB()
	if err != nil {
		return nil, err
	}
	conf := &config{
		SigningKey:   "testdata/server_ca",
		CertDuration: "160h",
		Aliases: map[string][]string{
			"hostname.square": []string{"alias.square"},
		},
		ExtraKnownHosts: []string{
			"@certificate-authority * pubkey",
		},
	}

	key, err := ioutil.ReadFile(conf.SigningKey)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	c := &context{
		signer: signer,
		db:     db,
		conf:   conf,
	}
	return c, nil
}

func generateDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "testdata/test.db")
	if err != nil {
		return nil, err
	}
	_, err = db.Exec("DROP TABLE IF EXISTS hostkeys")
	if err != nil {
		return nil, err
	}
	_, err = db.Exec("CREATE TABLE hostkeys(id INTEGER PRIMARY KEY AUTOINCREMENT, hostname VARCHAR(191) NOT NULL UNIQUE, pubkey BLOB NOT NULL)")
	if err != nil {
		return nil, err
	}
	_, err = db.Exec("INSERT INTO hostkeys(hostname, pubkey) VALUES('hostname','pubkey')")
	if err != nil {
		fmt.Println("bleh")
		return nil, err
	}
	return db, nil
}

func generateRequest() (*http.Request, error) {
	sub := pkix.Name{
		CommonName: "goodname",
	}
	cert := x509.Certificate{
		Subject: sub,
	}
	chain := [][]*x509.Certificate{[]*x509.Certificate{&cert}}
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

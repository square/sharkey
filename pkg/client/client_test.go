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

package client

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestEnroll(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Test response")
	}))
	c, err := generateClient(ts.URL)
	if err != nil {
		t.Fatalf("error generating Client: %s", err.Error())
	}
	defer cleanup(c)
	defer ts.Close()
	c.enroll(c.conf.HostKeys[0].HostKey, c.conf.HostKeys[0].SignedCert)
	data, err := ioutil.ReadFile(c.conf.HostKeys[0].SignedCert)
	if err != nil {
		t.Fatalf("error reading signed cert: %s", err.Error())
	}
	if string(data) != "Test response\n" {
		t.Fatalf("signed cert contains wrong info: %s", string(data))
	}
}

func TestKnownHosts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Test response")
	}))
	c, err := generateClient(ts.URL)
	if err != nil {
		t.Fatalf("error generating Client: %s", err.Error())
	}
	defer cleanup(c)
	defer ts.Close()
	c.makeKnownHosts()
	data, err := ioutil.ReadFile(c.conf.KnownHosts)
	if err != nil {
		t.Fatalf("error reading signed cert: %s", err.Error())
	}
	if string(data) != "Test response\n" {
		t.Fatalf("signed cert contains wrong info: %s", string(data))
	}
}

func generateClient(url string) (*Client, error) {
	signedCertTmp, err := ioutil.TempFile("", "sharkey-test")
	if err != nil {
		panic(err)
	}

	knownHostsTmp, err := ioutil.TempFile("", "sharkey-test")
	if err != nil {
		panic(err)
	}

	conf := Config{
		RequestAddr: url,
		HostKeys: []hostKey{
			{"testdata/ssh_host_rsa_key.pub", signedCertTmp.Name()},
		},
		KnownHosts: knownHostsTmp.Name(),
	}
	return &Client{
		conf:   &conf,
		client: &http.Client{},
	}, nil
}

func cleanup(c *Client) {
	os.Remove(c.conf.SignedCert)
	os.Remove(c.conf.KnownHosts)
}

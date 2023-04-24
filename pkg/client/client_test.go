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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestEnroll(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Test response")
	}))
	c, err := generateClient(ts.URL)
	if err != nil {
		t.Fatalf("error generating Client: %s", err.Error())
	}
	hook := test.NewLocal(c.logger)
	defer cleanup(c)
	defer ts.Close()
	c.enroll(c.conf.HostKeys[0].HostKey, c.conf.HostKeys[0].SignedCert)
	assert.Equal(t, 2, len(hook.Entries))
	assert.Equal(t, logrus.InfoLevel, hook.Entries[0].Level)
	assert.Equal(t, logrus.InfoLevel, hook.Entries[1].Level)
	assert.Equal(t, "Installing updated SSH certificate", hook.Entries[0].Message)
	assert.Equal(t, "calling exec on commands", hook.Entries[1].Message)
	assert.Contains(t, hook.Entries[0].Data, "signedCert")
	assert.Contains(t, hook.Entries[1].Data, "commands")
	data, err := os.ReadFile(c.conf.HostKeys[0].SignedCert)
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
	hook := test.NewLocal(c.logger)
	defer cleanup(c)
	defer ts.Close()
	c.makeKnownHosts()
	data, err := os.ReadFile(c.conf.KnownHosts)
	if err != nil {
		t.Fatalf("error reading signed cert: %s", err.Error())
	}
	if string(data) != "Test response\n" {
		t.Fatalf("signed cert contains wrong info: %s", string(data))
	}
	assert.Equal(t, 2, len(hook.Entries))
	assert.Equal(t, logrus.InfoLevel, hook.Entries[0].Level)
	assert.Equal(t, logrus.InfoLevel, hook.Entries[1].Level)
	assert.Equal(t, "Installing known_hosts file", hook.Entries[0].Message)
	assert.Equal(t, "calling exec on commands", hook.Entries[1].Message)
	assert.Contains(t, hook.Entries[0].Data, "KnownHosts")
	assert.Contains(t, hook.Entries[1].Data, "commands")
}

func generateClient(url string) (*Client, error) {
	signedCertTmp, err := os.CreateTemp("", "sharkey-test")
	if err != nil {
		panic(err)
	}

	knownHostsTmp, err := os.CreateTemp("", "sharkey-test")
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

	logger, _ := test.NewNullLogger()

	return &Client{
		conf:   &conf,
		client: &http.Client{},
		logger: logger,
	}, nil
}

func cleanup(c *Client) {
	os.Remove(c.conf.SignedCert)
	os.Remove(c.conf.KnownHosts)
}

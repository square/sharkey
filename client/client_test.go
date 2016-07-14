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
	c, err := generateContext(ts.URL)
	if err != nil {
		t.Fatalf("error generating context: %s", err.Error())
	}
	defer ts.Close()
	c.enroll()
	data, err := ioutil.ReadFile("signedCert.pub")
	if err != nil {
		t.Fatalf("error reading signed cert: %s", err.Error())
	}
	if string(data) != "Test response\n" {
		t.Fatalf("signed cert contains wrong info: %s", string(data))
	}
	if err = os.Remove("signedCert.pub"); err != nil {
		t.Fatalf("error deleting signed cert: %s", err.Error())
	}
}

func TestKnownHosts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Test response")
	}))
	c, err := generateContext(ts.URL)
	if err != nil {
		t.Fatalf("error generating context: %s", err.Error())
	}
	defer ts.Close()
	c.makeKnownHosts()
	data, err := ioutil.ReadFile("knownhosts.pub")
	if err != nil {
		t.Fatalf("error reading signed cert: %s", err.Error())
	}
	if string(data) != "Test response\n" {
		t.Fatalf("signed cert contains wrong info: %s", string(data))
	}
	if err = os.Remove("knownhosts.pub"); err != nil {
		t.Fatalf("error deleting signed cert: %s", err.Error())
	}
}

func generateContext(url string) (*context, error) {
	conf := &config{
		RequestAddr: url,
		HostKey:     "client_test.go",
		SignedCert:  "signedCert.pub",
		KnownHosts:  "knownhosts.pub",
	}
	c := &context{
		conf:   conf,
		client: &http.Client{},
	}
	return c, nil
}

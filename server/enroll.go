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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/square/sharkey/server/config"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/ssh"
)

func logHttpError(r *http.Request, w http.ResponseWriter, err error, code int) {
	// Log an error response:
	// POST /enroll/example.com: 404 some message
	log.Printf("%s %s: %d %s", r.Method, r.URL, code, err.Error())

	http.Error(w, err.Error(), code)
}

func (c *context) Enroll(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hostname := vars["hostname"]

	if !clientAuthenticated(r) {
		http.Error(w, "no client certificate provided", http.StatusUnauthorized)
		return
	}
	if !clientHostnameMatches(hostname, r) {
		http.Error(w, "hostname does not match certificate", http.StatusForbidden)
		return
	}

	cert, err := c.EnrollHost(hostname, r)
	if err != nil {
		log.Print("internal error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(cert))
}

// Read a public key off the wire
func readPubkey(r *http.Request) (ssh.PublicKey, error) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	return pubkey, err
}

func encodeCert(certificate *ssh.Certificate) (string, error) {
	certString := base64.StdEncoding.EncodeToString(certificate.Marshal())
	return fmt.Sprintf("%s-cert-v01@openssh.com %s\n", certificate.Key.Type(), certString), nil
}

func (c *context) EnrollHost(hostname string, r *http.Request) (string, error) {
	pubkey, err := readPubkey(r)
	if err != nil {
		return "", err
	}

	// Update table with host
	id, err := c.storage.RecordIssuance(ssh.HostCert, hostname, pubkey)
	if err != nil {
		return "", err
	}

	signedCert, err := c.signHost(hostname, id, pubkey)
	if err != nil {
		return "", err
	}

	return encodeCert(signedCert)
}

func clientAuthenticated(r *http.Request) bool {
	return len(r.TLS.VerifiedChains) > 0
}

func clientHostnameMatches(hostname string, r *http.Request) bool {
	conn := r.TLS
	if len(conn.VerifiedChains) == 0 {
		return false
	}
	cert := conn.VerifiedChains[0][0]
	return cert.VerifyHostname(hostname) == nil
}

func (c *context) signHost(hostname string, serial uint64, pubkey ssh.PublicKey) (*ssh.Certificate, error) {
	principals := []string{hostname}
	if c.conf.StripSuffix != "" && strings.HasSuffix(hostname, c.conf.StripSuffix) {
		principals = append(principals, strings.TrimSuffix(hostname, c.conf.StripSuffix))
	}
	if aliases, ok := c.conf.Aliases[hostname]; ok {
		principals = append(principals, aliases...)
	}
	return c.sign(hostname, principals, serial, ssh.HostCert, pubkey)
}

func (c *context) sign(keyId string, principals []string, serial uint64, certType uint32, pubkey ssh.PublicKey) (*ssh.Certificate, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	startTime := time.Now()
	duration, err := time.ParseDuration(c.conf.CertDuration)
	if err != nil {
		return nil, err
	}
	endTime := startTime.Add(duration)
	template := ssh.Certificate{
		Nonce:           nonce,
		Key:             pubkey,
		Serial:          serial,
		CertType:        certType,
		KeyId:           keyId,
		ValidPrincipals: principals,
		ValidAfter:      (uint64)(startTime.Unix()),
		ValidBefore:     (uint64)(endTime.Unix()),
	}

	err = template.SignCert(rand.Reader, c.signer)
	if err != nil {
		return nil, err
	}
	return &template, nil
}

// This assumes there's an authenticating proxy which provides the user in a header, configurable.
// We identify the proxy with its TLS client cert
func proxyAuthenticated(ap *config.AuthenticatingProxy, requestedUser string, w http.ResponseWriter, r *http.Request) bool {
	if !(clientAuthenticated(r) && clientHostnameMatches(ap.Hostname, r)) {
		logHttpError(r, w, fmt.Errorf("request didn't come from proxy"), http.StatusUnauthorized)
		return false
	}

	userAuthed := r.Header.Get(ap.UsernameHeader)
	if userAuthed == "" { // Shouldn't happen
		logHttpError(r, w, errors.New("no username supplied"), http.StatusUnauthorized)
		return false
	}

	if requestedUser != userAuthed {
		logHttpError(r, w, fmt.Errorf("%s cannot request client cert for %s", userAuthed, requestedUser), http.StatusForbidden)
		return false
	}

	// We've got a valid connection from the authenticating proxy, and the username matches the requested one.
	return true
}

func (c *context) EnrollUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	user := vars["user"]

	if c.conf.AuthenticatingProxy == nil {
		// Client certificates are not configured
		logHttpError(r, w, errors.New("client certificates are unavailable"), http.StatusNotFound)
		return
	}

	if !proxyAuthenticated(c.conf.AuthenticatingProxy, user, w, r) {
		// proxyAuthenticated sets http status & logs message
		return
	}

	pk, err := readPubkey(r)
	if err != nil {
		logHttpError(r, w, err, http.StatusBadRequest)
		return
	}

	id, err := c.storage.RecordIssuance(ssh.UserCert, user, pk)
	if err != nil {
		logHttpError(r, w, err, http.StatusInternalServerError)
		return
	}

	certificate, err := c.sign(user, []string{user}, id, ssh.UserCert, pk)
	if err != nil {
		logHttpError(r, w, err, http.StatusInternalServerError)
		return
	}

	certString, err := encodeCert(certificate)
	if err != nil {
		logHttpError(r, w, err, http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(certString))
}

// Issue a user certificate
func (c *context) IssueUser(user string, pubkey string) error {
	//
	return fmt.Errorf("not yet")
}

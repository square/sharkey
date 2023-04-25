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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/square/sharkey/pkg/server/cert"
	"github.com/square/sharkey/pkg/server/config"
	"golang.org/x/crypto/ssh"
)

func logHttpError(r *http.Request, w http.ResponseWriter, err error, code int, logger *logrus.Logger) {
	// Log an error response:
	// POST /enroll/example.com: 404 some message
	logger.WithFields(logrus.Fields{
		"method": r.Method,
		"url":    r.URL,
		"code":   code,
	}).WithError(err).Error("logHttpError")

	http.Error(w, err.Error(), code)
}

func (c *Api) Enroll(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hostname := vars["hostname"]

	if !clientAuthenticated(r) {
		http.Error(w, "no client certificate provided", http.StatusUnauthorized)
		return
	}

	hostnameMatches, err := clientHostnameMatches(hostname, r)
	if !hostnameMatches {
		if err != nil {
			c.logger.Error(err)
		}

		http.Error(w, "hostname does not match certificate", http.StatusForbidden)
		return
	}

	cert, err := c.EnrollHost(hostname, r)
	if err != nil {
		c.logger.Error("internal error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(cert))
}

// Read a public key off the wire
func readPubkey(r *http.Request) (ssh.PublicKey, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	return pubkey, err
}

func (c *Api) EnrollHost(hostname string, r *http.Request) (string, error) {
	pubkey, err := readPubkey(r)
	if err != nil {
		return "", err
	}

	signedCert, err := c.signHost(hostname, pubkey)
	if err != nil {
		return "", err
	}

	return cert.EncodeCert(signedCert)
}

func clientAuthenticated(r *http.Request) bool {
	return len(r.TLS.VerifiedChains) > 0
}

func clientHostnameMatches(hostname string, r *http.Request) (bool, error) {
	conn := r.TLS
	if len(conn.VerifiedChains) == 0 {
		return false, fmt.Errorf("length of TLS chain is zero")
	}
	cert := conn.VerifiedChains[0][0]

	err := cert.VerifyHostname(hostname)
	if err != nil {
		return false, fmt.Errorf("hostname failed to verify: %w", err)
	}

	return true, nil
}

func clientSpiffeIdMatches(expected []spiffeid.ID, r *http.Request) (bool, error) {
	conn := r.TLS
	if len(conn.VerifiedChains) == 0 {
		return false, fmt.Errorf("length of TLS chain is zero")
	}

	cert := conn.VerifiedChains[0][0]

	// Get the SPIFFE ID from the presented certificate
	actualId, err := x509svid.IDFromCert(cert)
	if err != nil {
		return false, fmt.Errorf("bad spiffe ID from cert: %w", err)
	}

	matcher := spiffeid.MatchOneOf(expected...)

	validationFailed := matcher(actualId)
	if validationFailed != nil {
		return false, fmt.Errorf("failed validation of spiffe ID presented from cert: %w", validationFailed)
	}

	return true, nil
}

func (c *Api) signHost(hostname string, pubkey ssh.PublicKey) (*ssh.Certificate, error) {
	principals := []string{hostname}
	if c.conf.StripSuffix != "" && strings.HasSuffix(hostname, c.conf.StripSuffix) {
		principals = append(principals, strings.TrimSuffix(hostname, c.conf.StripSuffix))
	}
	if aliases, ok := c.conf.Aliases[hostname]; ok {
		principals = append(principals, aliases...)
	}

	return c.signer.Sign(hostname, principals, ssh.HostCert, pubkey, map[string]string{})
}

// This assumes there's an authenticating proxy which provides the user in a header, configurable.
// We identify the proxy with its TLS client cert
func proxyAuthenticated(ap *config.AuthenticatingProxy, w http.ResponseWriter, r *http.Request, logger *logrus.Logger) (string, bool) {
	if ap == nil {
		// Client certificates are not configured
		logHttpError(r, w, errors.New("client certificates are unavailable"), http.StatusNotFound, logger)
		return "", false
	}

	// Host name matching
	hostnameMatches, hostnameErr := clientHostnameMatches(ap.Hostname, r)

	// SPIFFE ID matching
	spiffeIdMatches, spiffeIdErr := clientSpiffeIdMatches(ap.AllowedSpiffeIds, r)

	// Matching fails case
	if !(hostnameMatches || spiffeIdMatches) {
		logger.WithError(fmt.Errorf("hostname error: %v. spiffe id error: %v", hostnameErr, spiffeIdErr))
		logHttpError(r, w, fmt.Errorf("request didn't come from proxy"), http.StatusUnauthorized, logger)
		return "", false
	}

	user := r.Header.Get(ap.UsernameHeader)
	if user == "" { // Shouldn't happen
		logHttpError(r, w, errors.New("no username supplied"), http.StatusUnauthorized, logger)
		return "", false
	}

	// We've got a valid connection from the authenticating proxy.
	return user, true
}

func (c *Api) EnrollUser(w http.ResponseWriter, r *http.Request) {
	user, ok := proxyAuthenticated(c.conf.AuthenticatingProxy, w, r, c.logger)
	if !ok {
		// proxyAuthenticated sets http status & logs message
		return
	}

	pk, err := readPubkey(r)
	if err != nil {
		logHttpError(r, w, err, http.StatusBadRequest, c.logger)
		return
	}

	extensions := map[string]string{}
	if c.conf.GitHub.IncludeUserIdentity {
		username, err := c.RetrieveGitHubUsername(user)
		if err != nil {
			c.logger.Error(err)
		} else if username != "" {
			// If no error in retrieval and username not empty string then add github extension
			extensions["login@github.com"] = username
		}
	}

	certificate, err := c.signer.Sign(user, []string{user}, ssh.UserCert, pk, extensions)
	if err != nil {
		logHttpError(r, w, err, http.StatusInternalServerError, c.logger)
		return
	}

	certString, err := cert.EncodeCert(certificate)
	if err != nil {
		logHttpError(r, w, err, http.StatusInternalServerError, c.logger)
		return
	}

	_, _ = w.Write([]byte(certString))

	encodedPublicKey := base64.StdEncoding.EncodeToString(pk.Marshal())
	c.logger.WithFields(logrus.Fields{
		"Type":       pk.Type(),
		"Public Key": encodedPublicKey,
		"user":       user,
	}).Println("call EnrollUser")
}

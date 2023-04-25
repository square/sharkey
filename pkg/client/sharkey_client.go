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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type tlsConfig struct {
	Ca, Cert, Key string
}

type hostKey struct {
	HostKey    string `yaml:"plain"`
	SignedCert string `yaml:"signed"`
}

type Config struct {
	TLS                       tlsConfig `yaml:"tls"`
	RequestAddr               string    `yaml:"request_addr"`
	HostKey                   string    `yaml:"host_key"`    // deprecated
	SignedCert                string    `yaml:"signed_cert"` // deprecated
	HostKeys                  []hostKey `yaml:"host_keys"`
	KnownHosts                string    `yaml:"known_hosts"`
	KnownHostsAuthoritiesOnly bool      `yaml:"known_hosts_authorities_only"`
	Sleep                     string    `yaml:"sleep"`
	Sudo                      string    `yaml:"sudo"`
	SSHReload                 []string  `yaml:"ssh_reload"`
}

type Client struct {
	conf   *Config
	client *http.Client
	logger *logrus.Logger
}

func Run(conf *Config, logger *logrus.Logger) {
	c := &Client{
		conf:   conf,
		logger: logger,
	}

	if len(c.conf.HostKeys) == 0 {
		// Support old host_key/signed_cert options
		c.conf.HostKeys = []hostKey{
			{c.conf.HostKey, c.conf.SignedCert},
		}
	} else if c.conf.HostKey != "" || c.conf.SignedCert != "" {
		c.logger.Fatal("Options host_key/signed_cert and host_keys are mutually exclusive")
	}

	if err := c.GenerateClient(); err != nil {
		c.logger.WithError(err).Fatalln("Error generating http client")
	}

	c.logger.Println("Fetching updated SSH certificate from server")
	for _, entry := range c.conf.HostKeys {
		c.enroll(entry.HostKey, entry.SignedCert)
	}
	c.makeKnownHosts()
	c.reloadSSH()

	if c.conf.Sleep != "" {
		sleep, err := time.ParseDuration(c.conf.Sleep)
		if err != nil {
			logger.WithError(err).Fatalln("Error parsing sleep duration")
		}
		ticker := time.NewTicker(sleep)
		for range ticker.C {
			if err = c.GenerateClient(); err != nil {
				logger.WithError(err).Fatalln("Error generating http client")
			}

			logger.Println("Fetching updated SSH certificate from server")
			for _, entry := range c.conf.HostKeys {
				c.enroll(entry.HostKey, entry.SignedCert)
			}
			c.makeKnownHosts()
			c.reloadSSH()
		}
	}
}

func (c *Client) enroll(hostKey string, signedCert string) {
	hostname, err := os.Hostname()
	if err != nil {
		// Should be impossible
		panic(err)
	}
	url := c.conf.RequestAddr + "/enroll/" + hostname // host name of machine running on
	hostkey, err := os.ReadFile(hostKey)              // path to host key
	if err != nil {
		c.logger.WithFields(logrus.Fields{
			"hostkey": hostKey,
			"error":   err,
		}).Print("Error reading host key")
		return
	}
	resp, err := c.client.Post(url, "text/plain", bytes.NewReader(hostkey))
	if err != nil {
		c.logger.WithError(err).Println("Error talking to backend")
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.WithError(err).Errorln("Error reading response from server")
		return
	}
	if resp.StatusCode != 200 {
		c.logger.WithField("body", string(body)).Errorln("Error retrieving signed cert from server")
		return
	}
	tmp, err := os.CreateTemp("", "sharkey-signed-cert")
	if err != nil {
		c.logger.WithError(err).Errorln("Error creating temp file")
		return
	}
	defer os.Remove(tmp.Name())
	err = os.Chmod(tmp.Name(), 0644)
	if err != nil {
		c.logger.WithError(err).WithField("tmpName", tmp.Name()).Errorln("Error calling chmod")
		return
	}
	err = os.WriteFile(tmp.Name(), body, 0644)
	if err != nil {
		c.logger.WithError(err).WithField("tmpName", tmp.Name()).Errorln("Error writing file")
		return
	}

	c.logger.WithField("signedCert", signedCert).Println("Installing updated SSH certificate")
	c.shellOut([]string{"/bin/mv", tmp.Name(), signedCert})
}

func (c *Client) reloadSSH() {
	c.logger.Println("Restarting SSH daemon to make it pick up new certificate")
	c.shellOut(c.conf.SSHReload)
}

func (c *Client) makeKnownHosts() {
	var knownHosts string
	if c.conf.KnownHostsAuthoritiesOnly {
		knownHosts = "/authority"
	} else {
		knownHosts = "/known_hosts"
	}
	url := c.conf.RequestAddr + knownHosts
	resp, err := c.client.Get(url)
	if err != nil {
		c.logger.WithError(err).Errorln("Error talking to backend")
		return
	}
	defer resp.Body.Close()
	str, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.WithError(err).Errorln("Error reading response body")
		return
	}
	if resp.StatusCode != 200 {
		c.logger.WithField("StatusCode", resp.StatusCode).Errorln("Error retrieving known hosts file from server")
		return
	}
	tmp, err := os.CreateTemp("", "sharkey-known-hosts")
	if err != nil {
		c.logger.WithError(err).Errorln("Error creating temp file")
		return
	}
	defer os.Remove(tmp.Name())
	err = os.Chmod(tmp.Name(), 0644)
	if err != nil {
		c.logger.WithError(err).WithField("tmpName", tmp.Name()).Errorln("Error calling chmod")
		return
	}
	err = os.WriteFile(tmp.Name(), str, 0644)
	if err != nil {
		c.logger.WithError(err).WithField("tmpName", tmp.Name()).Errorln("Error writing file")
		return
	}

	c.logger.WithField("KnownHosts", c.conf.KnownHosts).Println("Installing known_hosts file")
	c.shellOut([]string{"/bin/mv", tmp.Name(), c.conf.KnownHosts})
}

func (c *Client) GenerateClient() error {
	if c.client != nil {
		c.client.CloseIdleConnections()
	}

	tlsConfig, err := buildConfig(c.conf.TLS.Ca)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(c.conf.TLS.Cert, c.conf.TLS.Key)
	if err != nil {
		return err
	}
	tlsConfig.Certificates = []tls.Certificate{cert}
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	c.client = &http.Client{Transport: tr}
	return nil
}

// buildConfig reads command-line options and builds a tls.Config
func buildConfig(caBundlePath string) (*tls.Config, error) {
	caBundleBytes, err := os.ReadFile(caBundlePath)
	if err != nil {
		return nil, err
	}

	caBundle := x509.NewCertPool()
	caBundle.AppendCertsFromPEM(caBundleBytes)

	return &tls.Config{
		// Certificates
		RootCAs:    caBundle,
		ClientCAs:  caBundle,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			// P-256 has an ASM implementation, others do not (as of 2016-12-19).
			tls.CurveP256,
		},
	}, nil
}

func (c *Client) shellOut(command []string) {
	if len(command) == 0 {
		return
	}
	if c.conf.Sudo != "" {
		command = append([]string{c.conf.Sudo}, command...)
	}
	cmd := exec.Cmd{
		Path: command[0],
		Args: command,
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	c.logger.WithField("commands", strings.Join(command, " ")).Println("calling exec on commands")

	err := cmd.Run()
	if err != nil {
		c.logger.WithError(err).WithField("command", command).Errorln("Failed to execute command")
		if len(stdout.Bytes()) > 0 {
			c.logger.WithField("stdout", stdout.Bytes()).Println("Printing Stdout")
		}
		if len(stderr.Bytes()) > 0 {
			c.logger.WithField("stderr", stderr.Bytes()).Errorln("Printing Stderr")
		}
	}
}

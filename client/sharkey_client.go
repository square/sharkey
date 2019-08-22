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
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/pkg/errors"
	"github.com/square/ghostunnel/certloader"
)

var (
	app        = kingpin.New("sharkey-client", "Certificate client of the ssh-ca system.")
	configPath = kingpin.Flag("config", "Path to config file for client.").Required().String()
)

type context struct {
	conf   *config
	client *http.Client
}

func main() {
	log.Println("Starting client")
	kingpin.Version("0.0.1")
	kingpin.Parse()

	log.Println("Loading config from ", *configPath)
	conf, err := newConfigFromFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	c := &context{conf: conf}

	if err = c.GenerateClient(); err != nil {
		log.Fatalf("Error generating http client: %s\n", err)
	}

	log.Println("Fetching updated SSH certificate from server")
	for _, entry := range c.conf.HostKeys {
		c.enroll(entry.HostKey, entry.SignedCert)
	}
	c.makeKnownHosts()
	c.reloadSSH()

	if c.conf.Sleep != "" {
		sleep, err := time.ParseDuration(c.conf.Sleep)
		if err != nil {
			log.Fatalf("Error parsing sleep duration: %s\n", err)
		}
		ticker := time.NewTicker(sleep)
		for range ticker.C {
			if err = c.GenerateClient(); err != nil {
				log.Fatalf("Error generating http client: %s\n", err)
			}

			log.Println("Fetching updated SSH certificate from server")
			for _, entry := range c.conf.HostKeys {
				c.enroll(entry.HostKey, entry.SignedCert)
			}
			c.makeKnownHosts()
			c.reloadSSH()
		}
	}
}

func (c *context) enroll(hostKey string, signedCert string) {
	hostname, err := os.Hostname()
	if err != nil {
		// Should be impossible
		panic(err)
	}
	url := c.conf.RequestAddr + "/enroll/" + hostname // host name of machine running on
	hostkey, err := ioutil.ReadFile(hostKey)          // path to host key
	if err != nil {
		log.Printf("Error reading host key at %s: %s", hostKey, err)
		return
	}
	resp, err := c.client.Post(url, "text/plain", bytes.NewReader(hostkey))
	if err != nil {
		log.Printf("Error talking to backend: %s\n", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response from server: %s\n", err)
		return
	}
	if resp.StatusCode != 200 {
		log.Printf("Error retrieving signed cert from server: %s\n", string(body))
		return
	}
	tmp, err := ioutil.TempFile("", "sharkey-signed-cert")
	if err != nil {
		log.Printf("Error creating temp file: %s\n", err)
		return
	}
	defer os.Remove(tmp.Name())
	err = os.Chmod(tmp.Name(), 0666)
	if err != nil {
		log.Printf("Error calling chmod on %s: %s\n", tmp.Name(), err)
		return
	}
	err = ioutil.WriteFile(tmp.Name(), body, 0666)
	if err != nil {
		log.Printf("Error writing to %s: %s\n", tmp.Name(), err)
		return
	}

	log.Printf("Installing updated SSH certificate into %s\n", signedCert)
	c.shellOut([]string{"/bin/mv", tmp.Name(), signedCert})
}

func (c *context) reloadSSH() {
	log.Println("Restarting SSH daemon to make it pick up new certificate")
	c.shellOut(c.conf.SSHReload)
}

func (c *context) makeKnownHosts() {
	var knownHosts string
	if c.conf.KnownHostsAuthoritiesOnly {
		knownHosts = "/authority"
	} else {
		knownHosts = "/known_hosts"
	}
	url := c.conf.RequestAddr + knownHosts
	resp, err := c.client.Get(url)
	if err != nil {
		log.Printf("Error talking to backend: %s\n", err)
		return
	}
	defer resp.Body.Close()
	str, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %s\n", err)
		return
	}
	if resp.StatusCode != 200 {
		log.Printf("Error retrieving known hosts file from server (got status %d)\n", resp.StatusCode)
		return
	}
	tmp, err := ioutil.TempFile("", "sharkey-known-hosts")
	if err != nil {
		log.Printf("Error creating temp file: %s\n", err)
		return
	}
	defer os.Remove(tmp.Name())
	err = os.Chmod(tmp.Name(), 0666)
	if err != nil {
		log.Printf("Error calling chmod on %s: %s\n", tmp.Name(), err)
		return
	}
	err = ioutil.WriteFile(tmp.Name(), str, 0666)
	if err != nil {
		log.Printf("Error writing to %s: %s\n", tmp.Name(), err)
		return
	}

	log.Printf("Installing known_hosts file into %s\n", c.conf.KnownHosts)
	c.shellOut([]string{"/bin/mv", tmp.Name(), c.conf.KnownHosts})
}

func (c *context) GenerateClient() error {
	baseConfig, err := c.buildBaseTLSConfig()
	if err != nil {
		log.Fatal(err)
	}

	var clientConfig certloader.TLSClientConfig
	if c.conf.SPIFFE.Enabled {
		clientConfig, err = c.buildSPIFFETLSConfig(baseConfig)
	} else {
		clientConfig, err = c.buildTLSConfig(baseConfig)
	}
	if err != nil {
		log.Fatal(err)
	}

	var dialer certloader.Dialer = &net.Dialer{Timeout: timeoutDuration}
	tlsDialer := certloader.DialerWithCertificate(clientConfig, timeoutDuration, dialer)

	tr := &http.Transport{DialTLS: tlsDialer.Dial}
	c.client = &http.Client{Transport: tr}
	return nil
}

// buildConfig reads command-line options and builds a tls.Config
func (c *context) buildBaseTLSConfig() (*tls.Config, error) {
	uri, err := url.Parse(c.conf.RequestAddr)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// ServerName is needed, since we're using custom dialer via DialTLS
		ServerName: uri.Hostname(),
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

func (c *context) buildTLSConfig(base *tls.Config) (certloader.TLSClientConfig, error) {
	cert, err := certloader.CertificateFromPEMFiles(c.conf.TLS.Cert, c.conf.TLS.Key, c.conf.TLS.Ca)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load certificate")
	}

	config := certloader.TLSConfigSourceFromCertificate(cert)

	clientConfig, err := config.GetClientConfig(base)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build client TLS config from base")
	}

	return clientConfig, nil
}

func (c *context) buildSPIFFETLSConfig(base *tls.Config) (certloader.TLSClientConfig, error) {
	logger := log.New(os.Stdout, "", log.Flags())
	source, err := certloader.TLSConfigSourceFromWorkloadAPI(c.conf.SPIFFE.WorkloadAPI, logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to the SPIFFE Workload API")
	}

	return source.GetClientConfig(base)
}

func (c *context) shellOut(command []string) {
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

	log.Printf("exec: '%s'\n", strings.Join(command, " "))

	err := cmd.Run()
	if err != nil {
		log.Printf("Failed to execute command %s, failed with %s\n", command, err)
		if len(stdout.Bytes()) > 0 {
			log.Printf("Stdout: %s\n", stdout.Bytes())
		}
		if len(stderr.Bytes()) > 0 {
			log.Printf("Stderr: %s\n", stderr.Bytes())
		}
	}
}

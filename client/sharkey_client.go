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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
)

var (
	app        = kingpin.New("sharkey-client", "Certificate client of the ssh-ca system.")
	configPath = kingpin.Flag("config", "Path to config file for client.").Required().String()
)

type tlsConfig struct {
	Ca, Cert, Key string
}

type config struct {
	TLS         tlsConfig `yaml:"tls"`
	RequestAddr string    `yaml:"request_addr"`
	HostKey     string    `yaml:"host_key"`
	SignedCert  string    `yaml:"signed_cert"`
	KnownHosts  string    `yaml:"known_hosts"`
	Sleep       string
}

type context struct {
	conf   *config
	client *http.Client
}

func main() {
	log.Print("Starting client")
	kingpin.Version("0.0.1")
	kingpin.Parse()
	data, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("error reading config file: %s", err.Error())
	} else {
		log.Print("Read in config file")
	}

	var conf config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		log.Fatalf("error parsing config file: %s", err.Error())
	} else {
		log.Print("Unmarshalled yaml config")
	}
	c := &context{
		conf: &conf,
	}
	if err = c.GenerateClient(); err != nil {
		log.Fatalf("error generating http client: %s", err.Error())
	} else {
		log.Print("Generated http client")
	}

	log.Print("Pinging server")
	c.enroll()
	c.makeKnownHosts()

	if c.conf.Sleep != "" {
		sleep, err := time.ParseDuration(c.conf.Sleep)
		if err != nil {
			log.Fatalf("error parsing sleep duration: %s", err.Error())
		}
		ticker := time.NewTicker(sleep)
		for range ticker.C {
			log.Print("Pinging server")
			c.enroll()
			c.makeKnownHosts()
		}
	}
}

func (c *context) enroll() {
	hostname, err := os.Hostname()
	if err != nil {
		log.Println(err)
		return
	}
	url := c.conf.RequestAddr + "/enroll/" + hostname //host name of machine running on
	hostkey, err := ioutil.ReadFile(c.conf.HostKey)   //path to host key
	if err != nil {
		log.Println(err)
		return
	}
	resp, err := c.client.Post(url, "text/plain", bytes.NewReader(hostkey))
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	str, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}
	if resp.StatusCode != 200 {
		log.Println("error retrieving signed cert from server")
		log.Println(string(str))
		return
	}
	tmp, err := ioutil.TempFile("", "sharkey-signed-cert")
	if err != nil {
		log.Println(err)
		return
	}
	defer os.Remove(tmp.Name())
	err = os.Chmod(tmp.Name(), 0666)
	if err != nil {
		log.Println(err)
		return
	}
	err = ioutil.WriteFile(tmp.Name(), str, 0666)
	if err != nil {
		log.Println(err)
		return
	}
	raw, err := exec.Command("/usr/bin/sudo", "/bin/mv", tmp.Name(), c.conf.SignedCert).CombinedOutput()
	if err != nil {
		// Capture stdout/stderr for debugging errors
		var output string
		if raw != nil {
			output = string(raw)
		} else {
			output = "no output"
		}
		log.Printf("Failed to move file: %s (output: %s)", err, output)
		return
	}
}

func (c *context) makeKnownHosts() {
	url := c.conf.RequestAddr + "/known_hosts"
	resp, err := c.client.Get(url)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	str, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}
	if resp.StatusCode != 200 {
		log.Println("error retrieving known hosts file from server")
		log.Println(string(str))
		return
	}
	tmp, err := ioutil.TempFile("", "sharkey-known-hosts")
	if err != nil {
		log.Println(err)
		return
	}
	defer os.Remove(tmp.Name())
	err = os.Chmod(tmp.Name(), 0666)
	if err != nil {
		log.Println(err)
		return
	}
	err = ioutil.WriteFile(tmp.Name(), str, 0666)
	if err != nil {
		log.Println(err)
		return
	}
	raw, err := exec.Command("/usr/bin/sudo", "/bin/mv", tmp.Name(), c.conf.KnownHosts).CombinedOutput()
	if err != nil {
		// Capture stdout/stderr for debugging errors
		var output string
		if raw != nil {
			output = string(raw)
		} else {
			output = "no output"
		}
		log.Printf("Failed to move file: %s (output: %s)", err, output)
		return
	}
}

func (c *context) GenerateClient() error {
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
	caBundleBytes, err := ioutil.ReadFile(caBundlePath)
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
	}, nil
}

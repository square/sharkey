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
	"io/ioutil"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

const (
	timeoutDuration = 10 * time.Second
)

type tlsConfig struct {
	Ca, Cert, Key string
}

type hostKey struct {
	HostKey    string `yaml:"plain"`
	SignedCert string `yaml:"signed"`
}

type spiffeConfig struct {
	Enabled     bool     `yaml:"enabled"`
	AllowedURIs []string `yaml:"allowed_uris"`
	WorkloadAPI string   `yaml:"workload_api"`
}

type config struct {
	TLS                       tlsConfig    `yaml:"tls"`
	RequestAddr               string       `yaml:"request_addr"`
	HostKey                   string       `yaml:"host_key"`    // deprecated
	SignedCert                string       `yaml:"signed_cert"` // deprecated
	HostKeys                  []hostKey    `yaml:"host_keys"`
	KnownHosts                string       `yaml:"known_hosts"`
	KnownHostsAuthoritiesOnly bool         `yaml:"known_hosts_authorities_only"`
	Sleep                     string       `yaml:"sleep"`
	Sudo                      string       `yaml:"sudo"`
	SSHReload                 []string     `yaml:"ssh_reload"`
	SPIFFE                    spiffeConfig `yaml:"spiffe"`
}

func newConfigFromFile(filepath string) (*config, error) {
	data, err := ioutil.ReadFile(*configPath)
	if err != nil {
		return nil, errors.Wrap(err, "error reading config file")
	}

	var conf config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, errors.Wrap(err, "error parsing config file")
	}

	if len(conf.HostKeys) == 0 {
		// Support old host_key/signed_cert options
		conf.HostKeys = []hostKey{
			{conf.HostKey, conf.SignedCert},
		}
	} else if conf.HostKey != "" || conf.SignedCert != "" {
		return nil, errors.New("options host_key/signed_cert and host_keys are mutually exclusive")
	}

	return &conf, nil
}

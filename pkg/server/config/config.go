package config

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

func Load(file string) (conf Config, err error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	if err = yaml.Unmarshal(data, &conf); err != nil {
		return
	}

	return
}

type Config struct {
	Database            Database             `yaml:"db"`
	TLS                 TLS                  `yaml:"tls"`
	SigningKey          string               `yaml:"signing_key"`
	HostCertDuration    string               `yaml:"host_cert_duration"`
	UserCertDuration    string               `yaml:"user_cert_duration"`
	ListenAddr          string               `yaml:"listen_addr"`
	StripSuffix         string               `yaml:"strip_suffix"`
	Aliases             map[string][]string  `yaml:"aliases"`
	ExtraKnownHosts     []string             `yaml:"extra_known_hosts"`
	AuthenticatingProxy *AuthenticatingProxy `yaml:"auth_proxy"`
	SSH                 SSH                  `yaml:"ssh"`
	GitHub              GitHub               `yaml:"github"`
}

type SSH struct {
	UserCertExtensions []string `yaml:"user_cert_extensions"`
}

type TLS struct {
	CA   string
	Cert string
	Key  string
}

type Database struct {
	Username string
	Password string
	Address  string
	Schema   string
	Type     string
	TLS      *TLS
}

type AuthenticatingProxy struct {
	Hostname       string `yaml:"hostname"`
	UsernameHeader string `yaml:"username_header"`
}

type GitHub struct {
	Enabled          bool   `yaml:"enabled"`
	AppId            int64  `yaml:"app_id"`
	InstallationId   int64  `yaml:"installation_id"`
	PrivateKeyPath   string `yaml:"private_key_path"`
	OrganizationName string `yaml:"organization_name"`
	SyncInterval     string `yaml:"sync_interval"`
}

// buildConfig reads command-line options and builds a tls.Config
func BuildTLS(opts TLS) (*tls.Config, error) {
	caBundleBytes, err := ioutil.ReadFile(opts.CA)
	if err != nil {
		return nil, err
	}

	caBundle := x509.NewCertPool()
	caBundle.AppendCertsFromPEM(caBundleBytes)

	config := &tls.Config{
		RootCAs:    caBundle,
		ClientCAs:  caBundle,
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS11,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CurvePreferences: []tls.CurveID{
			// P-256 has an ASM implementation, others do not (as of 2016-12-19).
			tls.CurveP256,
		},
	}

	if opts.Cert != "" {
		// Setup client certificates
		certs, err := tls.LoadX509KeyPair(opts.Cert, opts.Key)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{certs}
	}

	return config, nil
}

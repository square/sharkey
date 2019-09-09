package config

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/square/ghostunnel/certloader"
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
	SPIFFE              SPIFFE               `yaml:"spiffe"`
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

type SPIFFE struct {
	WorkloadAPI string `yaml:"workload_api"`
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
		RootCAs:            caBundle,
		ClientCAs:          caBundle,
		ClientAuth:         tls.VerifyClientCertIfGiven,
		MinVersion:         tls.VersionTLS11,
		InsecureSkipVerify: true,
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

// buildConfig reads command-line options and builds a tls.Config
func buildBaseTLSConfig() *tls.Config {
	return &tls.Config{
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
	}
}

func buildTLSConfig(opts TLS) (certloader.TLSServerConfig, error) {
	cert, err := certloader.CertificateFromPEMFiles(opts.Cert, opts.Key, opts.CA)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load certificate")
	}

	config := certloader.TLSConfigSourceFromCertificate(cert)

	serverConfig, err := config.GetServerConfig(buildBaseTLSConfig())
	if err != nil {
		return nil, errors.Wrap(err, "failed to build client TLS config from base")
	}

	return serverConfig, nil
}

func BuildSPIFFETLS(opts SPIFFE) (certloader.TLSServerConfig, error) {
	logger := log.New(os.Stdout, "", log.Flags())
	source, err := certloader.TLSConfigSourceFromWorkloadAPI(opts.WorkloadAPI, logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to the SPIFFE Workload API")
	}

	return source.GetServerConfig(buildBaseTLSConfig())
}

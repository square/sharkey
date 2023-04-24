package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"gopkg.in/yaml.v2"
)

func Load(file string) (conf Config, err error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}

	if err = yaml.Unmarshal(data, &conf); err != nil {
		// Ensure we can and should inspect the AuthenticatingProxy member
		if conf.AuthenticatingProxy != nil && len(conf.AuthenticatingProxy.AllowedSpiffeIds) > 0 {

			// Make sure the spiffe IDs we wanted were valid
			spiffeErr := conf.AuthenticatingProxy.validateSpiffeIds()

			// Report the invalid ones if they are invalid
			if spiffeErr != nil {
				err = fmt.Errorf("spiffe error: %w: %v", spiffeErr, err)
			}
		}
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
	ExtraAuthorities    []string             `yaml:"extra_authorities"`
	ExtraKnownHosts     []string             `yaml:"extra_known_hosts"`
	AuthenticatingProxy *AuthenticatingProxy `yaml:"auth_proxy"`
	SSH                 SSH                  `yaml:"ssh"`
	GitHub              GitHub               `yaml:"github"`
	Telemetry           Telemetry            `yaml:"telemetry"`
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

// An AuthenticatingProxy represents a known entity that will perform
// authentication of incoming requests to Sharkey.
//
// The authenticating proxy connection can be validated with either
// a hostname in the TLS connection OR by a SPIFFE ID contained in
// the certificate used for the TLS connection.
type AuthenticatingProxy struct {
	Hostname         string        `yaml:"hostname"`           // Expected hostname of the authenticating proxy
	UsernameHeader   string        `yaml:"username_header"`    // Username header key the authenticating proxy will use
	AllowedSpiffeIds []spiffeid.ID `yaml:"allowed_spiffe_ids"` // A list of SPIFFE IDs that can be used for authentcation
}

type GitHub struct {
	IncludeUserIdentity bool          `yaml:"include_user_identity"`
	AppId               int64         `yaml:"app_id"`
	InstallationId      int64         `yaml:"installation_id"`
	PrivateKeyPath      string        `yaml:"private_key_path"`
	OrganizationName    string        `yaml:"organization_name"`
	SyncInterval        time.Duration `yaml:"sync_interval"`
	SyncEnabled         bool          `yaml:"sync_enabled"`
}

type Telemetry struct {
	Address string `yaml:"address"`
}

// buildConfig reads command-line options and builds a tls.Config
func BuildTLS(opts TLS) (*tls.Config, error) {
	caBundleBytes, err := os.ReadFile(opts.CA)
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

// Validate the configured SPIFFE IDs by index since they get
// configured as empty by the parser. The "omitempty" flag
// does not appear to work with spiffeid.ID.isZero()
func (ap *AuthenticatingProxy) validateSpiffeIds() error {
	var failedSpiffeIds []int
	for index, value := range ap.AllowedSpiffeIds {
		if value.IsZero() {
			failedSpiffeIds = append(failedSpiffeIds, index)
		}
	}

	// If there was an error, report  the indices.
	if len(failedSpiffeIds) > 0 {
		return fmt.Errorf("indices of spiffe ids that failed to parse: %v", failedSpiffeIds)
	}

	return nil
}

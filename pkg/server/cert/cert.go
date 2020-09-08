package cert

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/square/sharkey/pkg/server/config"
	"github.com/square/sharkey/pkg/server/storage"
	"golang.org/x/crypto/ssh"
)

type Signer struct {
	signer  ssh.Signer
	conf    *config.Config
	storage storage.Storage
}

func NewSigner(signer ssh.Signer, conf *config.Config, storage storage.Storage) *Signer {
	return &Signer{
		signer:  signer,
		conf:    conf,
		storage: storage,
	}
}

func (s *Signer) Sign(keyId string, principals []string, certType uint32, pubkey ssh.PublicKey, extensions map[string]string) (*ssh.Certificate, error) {
	serial, err := s.storage.RecordIssuance(certType, keyId, pubkey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	startTime := time.Now()
	duration, err := getDurationForCertType(s.conf, certType)
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
		Permissions:     getPermissionsForCertType(&s.conf.SSH, certType),
	}

	if template.Extensions == nil {
		template.Extensions = extensions
	} else {
		for key, val := range extensions {
			template.Extensions[key] = val
		}
	}

	err = template.SignCert(rand.Reader, s.signer)
	if err != nil {
		return nil, err
	}
	return &template, nil
}

func (s *Signer) PublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}

func getPermissionsForCertType(cfg *config.SSH, certType uint32) (perms ssh.Permissions) {
	switch certType {
	case ssh.UserCert:
		if cfg != nil && len(cfg.UserCertExtensions) > 0 {
			perms.Extensions = make(map[string]string, len(cfg.UserCertExtensions))
			for _, ext := range cfg.UserCertExtensions {
				perms.Extensions[ext] = ""
			}
		}
	}
	return
}

func getDurationForCertType(cfg *config.Config, certType uint32) (time.Duration, error) {
	var duration time.Duration
	var err error

	switch certType {
	case ssh.HostCert:
		duration, err = time.ParseDuration(cfg.HostCertDuration)
	case ssh.UserCert:
		duration, err = time.ParseDuration(cfg.UserCertDuration)
	default:
		err = fmt.Errorf("unknown cert type %d", certType)
	}

	return duration, err
}

func EncodeCert(certificate *ssh.Certificate) (string, error) {
	certString := base64.StdEncoding.EncodeToString(certificate.Marshal())
	return fmt.Sprintf("%s-cert-v01@openssh.com %s\n", certificate.Key.Type(), certString), nil
}

package storage

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/ssh"

	"bitbucket.org/liamstask/goose/lib/goose"

	_ "github.com/mattn/go-sqlite3"
	"github.com/square/sharkey/server/config"
)

// SqliteStorage implements the storage interface, using Sqlite for storage.
type SqliteStorage struct {
	*sql.DB
}

const (
	// following https://godoc.org/golang.org/x/crypto/ssh#pkg-constants conventions
	sqliteHostCert = 2
	sqliteUserCert = 1
)

var _ Storage = &SqliteStorage{}

func (s *SqliteStorage) RecordIssuance(certType uint32, principal string, pubkey ssh.PublicKey) (uint64, error) {
	pkdata := ssh.MarshalAuthorizedKey(pubkey)

	typ, err := certTypeToSQLite(certType)
	if err != nil {
		return 0, err
	}

	result, err := s.DB.Exec(
		"INSERT OR REPLACE INTO hostkeys (hostname, pubkey, cert_type) VALUES (?, ?, ?)",
		principal, pkdata, typ)
	if err != nil {
		return 0, fmt.Errorf("error recording issuance: %s", err.Error())
	}

	id, err := result.LastInsertId()
	return uint64(id), err
}

func (s *SqliteStorage) QueryHostkeys() (ResultIterator, error) {
	rows, err := s.DB.Query("select hostname, pubkey from hostkeys")
	if err != nil {
		return &SqlResultIterator{}, err
	}
	return &SqlResultIterator{Rows: rows}, nil
}

func (s *SqliteStorage) Migrate(migrationsDir string) error {
	gooseConf := goose.DBConf{
		MigrationsDir: migrationsDir,
		Env:           "sharkey",
		Driver: goose.DBDriver{
			Name:    "sqlite",
			Import:  "github.com/go-sql-driver/mysql",
			Dialect: goose.Sqlite3Dialect{},
		},
	}

	desiredVersion, err := goose.GetMostRecentDBVersion(migrationsDir)
	if err != nil {
		return fmt.Errorf("unable to run migrations: %s", err)
	}

	err = goose.RunMigrationsOnDb(&gooseConf, migrationsDir, desiredVersion, s.DB)
	if err != nil {
		return fmt.Errorf("unable to run migrations: %s", err)
	}

	return nil
}

func NewSqlite(cfg config.Database) (*SqliteStorage, error) {
	db, err := sql.Open("sqlite3", cfg.Address)

	return &SqliteStorage{DB: db}, err
}

// certTypeToSQLite converts the certType uint32 into a valid SQLite value
// or returns error
func certTypeToSQLite(certType uint32) (int, error) {
	switch certType {
	case ssh.HostCert:
		return sqliteHostCert, nil
	case ssh.UserCert:
		return sqliteUserCert, nil
	default:
		return -1, fmt.Errorf("storage: unknown ssh cert type: %d", certType)
	}
}

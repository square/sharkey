package storage

import (
	"database/sql"
	"fmt"

	"golang.org/x/crypto/ssh"

	"bitbucket.org/liamstask/goose/lib/goose"
	"github.com/go-sql-driver/mysql"
	"github.com/square/sharkey/server/config"
)

// MysqlStorage implements the storage interface, using Mysql for storage.
type MysqlStorage struct {
	*sql.DB
}

var _ Storage = &MysqlStorage{}

func (my *MysqlStorage) RecordIssuance(certType uint32, principal string, pubkey ssh.PublicKey) (uint64, error) {
	pkdata := ssh.MarshalAuthorizedKey(pubkey)

	result, err := my.DB.Exec(
		"INSERT INTO hostkeys (hostname, pubkey) VALUES (?, ?) ON DUPLICATE KEY UPDATE pubkey = ?",
		principal, pkdata, pkdata)
	if err != nil {
		return 0, fmt.Errorf("error recording issuance: %s", err.Error())

	}

	// TODO: This is broken!  It doesn't work in the ON DUPLICATE KEY case.
	id, err := result.LastInsertId()
	return uint64(id), err
}

func (my *MysqlStorage) QueryHostkeys() (ResultIterator, error) {
	rows, err := my.DB.Query("select hostname, pubkey from hostkeys")
	if err != nil {
		return &SqlResultIterator{}, err
	}
	return &SqlResultIterator{Rows: rows}, nil
}

// Migrate runs any pending migrations
func (my *MysqlStorage) Migrate(migrationsDir string) error {
	gooseConf := goose.DBConf{
		MigrationsDir: migrationsDir,
		Env:           "sharkey",
		Driver: goose.DBDriver{
			Name:    "mysql",
			Import:  "github.com/go-sql-driver/mysql",
			Dialect: goose.MySqlDialect{},
		},
	}

	desiredVersion, err := goose.GetMostRecentDBVersion(migrationsDir)
	if err != nil {
		return fmt.Errorf("unable to run migrations: %s", err)
	}

	err = goose.RunMigrationsOnDb(&gooseConf, migrationsDir, desiredVersion, my.DB)
	if err != nil {
		return fmt.Errorf("unable to run migrations: %s", err)
	}

	return nil
}

func NewMysql(cfg config.Database) (*MysqlStorage, error) {
	url := cfg.Username
	if cfg.Password != "" {
		url += ":" + cfg.Password
	}
	url += "@tcp(" + cfg.Address + ")/" + cfg.Schema

	// Setup TLS (if configured)
	if cfg.TLS != nil {
		tlsConfig, err := config.BuildTLS(*cfg.TLS)
		if err != nil {
			return nil, err
		}
		err = mysql.RegisterTLSConfig("sharkey", tlsConfig)
		if err != nil {
			return nil, err
		}
		url += "?tls=sharkey"
	}

	db, err := sql.Open("mysql", url)
	return &MysqlStorage{DB: db}, err
}

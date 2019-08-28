package storage

import (
	"database/sql"
	"fmt"

	"bitbucket.org/liamstask/goose/lib/goose"

	_ "github.com/mattn/go-sqlite3"
	"github.com/square/sharkey/server/config"
)

// SqliteStorage implements the storage interface, using Sqlite for storage.
type SqliteStorage struct {
	*sql.DB
}

var _ Storage = &SqliteStorage{}

func (s *SqliteStorage) RecordIssuance(certType uint32, principal string, pubkey string) (int64, error) {
	result, err := s.DB.Exec(
		"INSERT OR REPLACE INTO hostkeys (hostname, pubkey) VALUES (?, ?)",
		principal, pubkey)
	if err != nil {
		return 0, fmt.Errorf("error recording issuance: %s", err.Error())
	}

	return result.LastInsertId()
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

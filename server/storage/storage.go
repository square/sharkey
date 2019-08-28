// Package storage provides a storage backend for the Sharkey server.
// It provides an API for recording issuance of certificates.
// By default it is backed by a SQL database, but you could swap this package out for another
// one if you prefer something else -- many key-value stores would probably work.
package storage

import (
	"database/sql"
	"errors"

	"github.com/square/sharkey/server/config"
)

type Storage interface {
	// Record an issuance of type (host or client) to principal with pubkey string
	// Returns an integer ID for the record (ie, database row primary key)
	RecordIssuance(certType uint32, principal string, pubkey string) (int64, error)

	// Query all hostkeys
	QueryHostkeys() (ResultIterator, error)

	// Takes a path to DB migration locations
	Migrate(string) error

	Ping() error
	Close() error
}

// ResultIterator works like a typed sql.Rows: Call Next() and then Get() until Next() returns false
type ResultIterator interface {
	Next() bool
	Get() (principal string, key string, err error)
}

// Given a database configuration, return an appropriate Storage interface
func FromConfig(cfg config.Database) (Storage, error) {
	var storage Storage
	var err error

	switch cfg.Type {
	case "sqlite":
		storage, err = NewSqlite(cfg)
	case "mysql":
		storage, err = NewMysql(cfg)
	default:
		return nil, errors.New("Unknown database type: " + cfg.Type)
	}

	if err != nil {
		return nil, err
	}

	err = storage.Ping()
	if err != nil {
		return nil, err
	}
	return storage, nil
}

// This is shared between sqlite & mysql
type SqlResultIterator struct {
	*sql.Rows
}

var _ ResultIterator = &SqlResultIterator{}

func (r *SqlResultIterator) Next() bool {
	return r.Rows.Next()
}

func (r *SqlResultIterator) Get() (string, string, error) {
	var hostname, pubkey string
	err := r.Rows.Scan(&hostname, &pubkey)
	return hostname, pubkey, err
}

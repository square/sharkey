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
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/ssh"

	"bitbucket.org/liamstask/goose/lib/goose"

	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

var (
	app        = kingpin.New("sharkey-server", "Certificate issuer of the ssh-ca system.")
	configPath = app.Flag("config", "Path to config file for server.").Required().ExistingFile()

	// Start server
	startCmd = app.Command("start", "Run the sharkey server.")

	// Run migrations
	migrateCmd    = app.Command("migrate", "Set up database/run migrations.")
	migrationsDir = migrateCmd.Flag("migrations", "Path to migrations directory.").ExistingDir()
)

type databaseConfig struct {
	Username, Password, Address, Schema, Type string
	TLS                                       *tlsConfig `yaml:"tls"`
}

type tlsConfig struct {
	Ca, Cert, Key string
}

type config struct {
	Database        databaseConfig      `yaml:"db"`
	TLS             tlsConfig           `yaml:"tls"`
	SigningKey      string              `yaml:"signing_key"`
	CertDuration    string              `yaml:"cert_duration"`
	ListenAddr      string              `yaml:"listen_addr"`
	StripSuffix     string              `yaml:"strip_suffix"`
	Aliases         map[string][]string `yaml:"aliases"`
	ExtraKnownHosts []string            `yaml:"extra_known_hosts"`
}

type statusResponse struct {
	Ok       bool     `json:"ok"`
	Status   string   `json:"status"`
	Messages []string `json:"messages"`
}

type context struct {
	signer ssh.Signer
	db     *sql.DB
	conf   *config
}

func main() {
	log.Print("Starting server")
	app.Version("0.0.1")
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	data, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatal("error reading config file")
	} else {
		log.Print("Read in config file")
	}

	var conf config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		log.Fatal("error parsing config file")
	} else {
		log.Print("Unmarshalled yaml config")
	}

	switch command {
	case startCmd.FullCommand():
		startServer(&conf)
	case migrateCmd.FullCommand():
		migrate(&conf)
	}
}

func migrate(conf *config) {
	log.Print("Migrating database")
	db, err := conf.getDB()
	if err != nil {
		log.Fatalf("unable to open database: %s\n", err)
	}
	defer db.Close()

	driver := goose.DBDriver{
		Name: conf.Database.Type,
	}

	switch conf.Database.Type {
	case "mysql":
		driver.Import = "github.com/go-sql-driver/mysql"
		driver.Dialect = &goose.MySqlDialect{}
	case "sqlite":
		driver.Import = "github.com/mattn/go-sqlite3"
		driver.Dialect = &goose.Sqlite3Dialect{}
	default:
		log.Fatalf("unknown database type %s", conf.Database.Type)
	}

	gooseConf := goose.DBConf{
		MigrationsDir: *migrationsDir,
		Env:           "sharkey",
		Driver:        driver,
	}

	desiredVersion, err := goose.GetMostRecentDBVersion(*migrationsDir)
	if err != nil {
		log.Fatalf("unable to run migrations: %s\n", err)
	}

	err = goose.RunMigrationsOnDb(&gooseConf, *migrationsDir, desiredVersion, db)
	if err != nil {
		log.Fatalf("unable to run migrations: %s\n", err)
	}
}

func startServer(conf *config) {
	log.Print("Starting http server")
	c := &context{
		conf: conf,
	}

	privateKey, err := ioutil.ReadFile(c.conf.SigningKey)
	if err != nil {
		log.Fatalf("unable to read signing key file: %s\n", err)
	}

	c.signer, err = ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatalf("unable to parse signing key data: %s\n", err)
	}

	c.db, err = conf.getDB()
	if err != nil {
		log.Fatalf("unable to open database: %s\n", err)
	}

	defer c.db.Close()

	handler := mux.NewRouter()
	handler.Path("/enroll/{hostname}").Methods("POST").HandlerFunc(c.Enroll)
	handler.Path("/known_hosts").Methods("GET").HandlerFunc(c.KnownHosts)
	handler.Path("/authority").Methods("GET").HandlerFunc(c.Authority)
	handler.Path("/_status").Methods("HEAD", "GET").HandlerFunc(c.Status)
	loggingHandler := handlers.LoggingHandler(os.Stderr, handler)
	tlsConfig, err := buildConfig(conf.TLS)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:      conf.ListenAddr,
		TLSConfig: tlsConfig,
		Handler:   loggingHandler,
	}

	log.Fatal(server.ListenAndServeTLS(conf.TLS.Cert, conf.TLS.Key))
}

func (c *context) Status(w http.ResponseWriter, r *http.Request) {
	resp := statusResponse{
		Ok:       true,
		Status:   "ok",
		Messages: []string{},
	}
	err := c.db.Ping()
	if err != nil {
		resp.Ok = false
		resp.Status = "critical"
		resp.Messages = append(resp.Messages, err.Error())
	}
	out, err := json.Marshal(resp)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	if !resp.Ok {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	w.Write(out)
}

func (c *config) getDB() (*sql.DB, error) {
	var db *sql.DB
	var err error

	switch c.Database.Type {
	case "sqlite":
		if c.Database.TLS != nil {
			return nil, errors.New("TLS not supported with sqlite")
		}
		db, err = sql.Open("sqlite3", c.Database.Address)
	case "mysql":
		db, err = c.getMySQL()
	default:
		return nil, errors.New("Unknown database type: " + c.Database.Type)
	}

	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (c *config) getMySQL() (*sql.DB, error) {
	url := c.Database.Username
	if c.Database.Password != "" {
		url += ":" + c.Database.Password
	}
	url += "@tcp(" + c.Database.Address + ")/" + c.Database.Schema

	// Setup TLS (if configured)
	if c.Database.TLS != nil {
		tlsConfig, err := buildConfig(*c.Database.TLS)
		if err != nil {
			return nil, err
		}
		mysql.RegisterTLSConfig("sharkey", tlsConfig)
		url += "?tls=sharkey"
	}

	return sql.Open("mysql", url)
}

// buildConfig reads command-line options and builds a tls.Config
func buildConfig(opts tlsConfig) (*tls.Config, error) {
	caBundleBytes, err := ioutil.ReadFile(opts.Ca)
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

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
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/square/sharkey/server/config"
	"github.com/square/sharkey/server/storage"

	_ "bitbucket.org/liamstask/goose/lib/goose"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/square/ghostunnel/certloader"
	"golang.org/x/crypto/ssh"

	"gopkg.in/alecthomas/kingpin.v2"
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

type statusResponse struct {
	Ok       bool     `json:"ok"`
	Status   string   `json:"status"`
	Messages []string `json:"messages"`
}

type context struct {
	signer  ssh.Signer
	storage storage.Storage
	conf    *config.Config
}

func main() {
	log.Print("Starting server")
	app.Version("0.0.1")
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	conf, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Error loading configuration file: %v", err)
	}

	switch command {
	case startCmd.FullCommand():
		startServer(&conf)
	case migrateCmd.FullCommand():
		migrate(*migrationsDir, &conf)
	}
}

func startServer(conf *config.Config) {
	log.Print("Starting http server")
	c := &context{
		conf: conf,
	}

	privateKey, err := ioutil.ReadFile(c.conf.SigningKey)
	if err != nil {
		log.Fatalf("unable to read signing key file: %s", err)
	}

	c.signer, err = ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatalf("unable to parse signing key data: %s", err)
	}

	c.storage, err = storage.FromConfig(c.conf.Database)
	if err != nil {
		log.Fatalf("unable to setup database: %s", err)
	}
	defer c.storage.Close()

	handler := mux.NewRouter()
	handler.Path("/enroll/{hostname}").Methods("POST").HandlerFunc(c.Enroll)
	handler.Path("/enroll_user/{user}").Methods("POST").HandlerFunc(c.EnrollUser)
	handler.Path("/known_hosts").Methods("GET").HandlerFunc(c.KnownHosts)
	handler.Path("/authority").Methods("GET").HandlerFunc(c.Authority)
	handler.Path("/_status").Methods("HEAD", "GET").HandlerFunc(c.Status)
	loggingHandler := handlers.LoggingHandler(os.Stderr, handler)

	/*
		tlsConfig, err := config.BuildTLS(conf.TLS)
		if err != nil {
			log.Fatal(err)
		}

		cert, err := certloader.CertificateFromPEMFiles(conf.TLS.Cert, conf.TLS.Key, conf.TLS.CA)
		if err != nil {
			log.Fatal(err)
		}

		config := certloader.TLSConfigSourceFromCertificate(cert)
		srvConfig, err := config.GetServerConfig(tlsConfig)
		if err != nil {
			log.Fatal(err)
		}
	*/

	srvConfig, err := config.BuildSPIFFETLS(conf.SPIFFE)
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatal(err)
	}

	l := certloader.NewListener(ln, srvConfig)

	server := &http.Server{
		Handler: loggingHandler,
	}

	log.Fatal(server.Serve(l))
}

func migrate(migrationsDir string, conf *config.Config) {
	db, err := storage.FromConfig(conf.Database)
	if err != nil {
		log.Fatalf("unable to setup database: %s", err.Error())
	}
	defer db.Close()

	if err := db.Migrate(migrationsDir); err != nil {
		log.Fatalf("error migrating DB: %s", err.Error())
	}
}

func (c *context) Status(w http.ResponseWriter, r *http.Request) {
	resp := statusResponse{
		Ok:       true,
		Status:   "ok",
		Messages: []string{},
	}
	err := c.storage.Ping()
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
	_, _ = w.Write(out)
}

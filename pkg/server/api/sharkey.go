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

package api

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/square/sharkey/pkg/server/config"
	"github.com/square/sharkey/pkg/server/storage"

	_ "bitbucket.org/liamstask/goose/lib/goose"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh"
)

type statusResponse struct {
	Ok       bool     `json:"ok"`
	Status   string   `json:"status"`
	Messages []string `json:"messages"`
}

type Api struct {
	signer  ssh.Signer
	storage storage.Storage
	conf    *config.Config
}

func Run(conf *config.Config) {
	log.Print("Starting http server")
	privateKey, err := ioutil.ReadFile(conf.SigningKey)
	if err != nil {
		log.Fatalf("unable to read signing key file: %s", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatalf("unable to parse signing key data: %s", err)
	}

	storage, err := storage.FromConfig(conf.Database)
	if err != nil {
		log.Fatalf("unable to setup database: %s", err)
	}
	defer storage.Close()

	c := Api {
		conf: conf,
		signer: signer,
		storage: storage,
	}

	handler := mux.NewRouter()
	handler.Path("/enroll/{hostname}").Methods("POST").HandlerFunc(c.Enroll)
	handler.Path("/enroll_user").Methods("POST").HandlerFunc(c.EnrollUser)
	handler.Path("/known_hosts").Methods("GET").HandlerFunc(c.KnownHosts)
	handler.Path("/authority").Methods("GET").HandlerFunc(c.Authority)
	handler.Path("/_status").Methods("HEAD", "GET").HandlerFunc(c.Status)
	loggingHandler := handlers.LoggingHandler(os.Stderr, handler)
	tlsConfig, err := config.BuildTLS(conf.TLS)
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

func Migrate(migrationsDir string, conf *config.Config) {
	db, err := storage.FromConfig(conf.Database)
	if err != nil {
		log.Fatalf("unable to setup database: %s", err.Error())
	}
	defer db.Close()

	if err := db.Migrate(migrationsDir); err != nil {
		log.Fatalf("error migrating DB: %s", err.Error())
	}
}

func (c *Api) Status(w http.ResponseWriter, r *http.Request) {
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

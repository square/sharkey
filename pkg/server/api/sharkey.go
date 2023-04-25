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
	"net/http"
	"os"
	"time"

	"github.com/square/sharkey/pkg/server/cert"

	_ "bitbucket.org/liamstask/goose/lib/goose"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/shurcooL/githubv4"
	"github.com/sirupsen/logrus"
	"github.com/square/sharkey/pkg/server/config"
	"github.com/square/sharkey/pkg/server/storage"
	"github.com/square/sharkey/pkg/server/telemetry"
	"golang.org/x/crypto/ssh"
)

type statusResponse struct {
	Ok       bool     `json:"ok"`
	Status   string   `json:"status"`
	Messages []string `json:"messages"`
}

type Api struct {
	signer       *cert.Signer
	storage      storage.Storage
	conf         *config.Config
	logger       *logrus.Logger
	telemetry    *telemetry.Telemetry
	gitHubClient *githubv4.Client
}

func Run(conf *config.Config, logger *logrus.Logger) {
	logger.Print("Starting http server")
	privateKey, err := os.ReadFile(conf.SigningKey)
	if err != nil {
		logger.WithError(err).Fatal("unable to read signing key file")
	}

	storage, err := storage.FromConfig(conf.Database)
	if err != nil {
		logger.WithError(err).Fatal("unable to setup database")
	}
	defer storage.Close()

	sshSigner, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		logger.WithError(err).Fatal("unable to parse signing key data")
	}

	signer := cert.NewSigner(sshSigner, conf, storage)

	c := Api{
		conf:    conf,
		signer:  signer,
		storage: storage,
		logger:  logger,
	}

	if c.conf.Telemetry.Address == "" {
		logger.Warn("Telemetry address not found, using blackhole metrics sink")
	}
	telemetryImpl, err := telemetry.CreateTelemetry(c.conf.Telemetry.Address)
	if err != nil {
		logger.WithError(err).Fatal("unable to setup telemetry")
	}
	c.telemetry = telemetryImpl

	metricsMiddlware := telemetry.NewMetricsMiddleware(c.telemetry)

	handler := mux.NewRouter()
	handler.Use(metricsMiddlware.InstrumentHTTPEndpointStats)
	handler.Path("/enroll/{hostname}").Methods("POST").HandlerFunc(c.Enroll)
	handler.Path("/enroll_user").Methods("POST").HandlerFunc(c.EnrollUser)
	handler.Path("/known_hosts").Methods("GET").HandlerFunc(c.KnownHosts)
	handler.Path("/authority").Methods("GET").HandlerFunc(c.Authority)
	handler.Path("/_status").Methods("HEAD", "GET").HandlerFunc(c.Status)
	loggingHandler := handlers.LoggingHandler(logger.Writer(), handler)
	tlsConfig, err := config.BuildTLS(conf.TLS)
	if err != nil {
		logger.WithError(err).Fatal("issue with BuildTLS")
	}
	server := &http.Server{
		Addr:        conf.ListenAddr,
		TLSConfig:   tlsConfig,
		Handler:     loggingHandler,
		IdleTimeout: time.Minute * 5,
	}

	if c.conf.GitHub.SyncEnabled {
		c.gitHubClient = c.CreateGitHubClient()
		if err := c.StartGitHubUserMappingSyncJob(); err != nil {
			logger.WithError(err)
		}
	}

	err = server.ListenAndServeTLS(conf.TLS.Cert, conf.TLS.Key)
	logger.WithError(err).Fatal("issue with ListenAndServeTLS")
}

func Migrate(migrationsDir string, conf *config.Config, logger *logrus.Logger) {
	db, err := storage.FromConfig(conf.Database)
	if err != nil {
		logger.WithError(err).Fatal("unable to setup database")
	}
	defer db.Close()

	if err := db.Migrate(migrationsDir); err != nil {
		logger.WithError(err).Fatal("error migrating database")
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

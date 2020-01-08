package cli

import (
	"log"

	"github.com/square/sharkey/pkg/server/api"
	"github.com/square/sharkey/pkg/server/config"

	"gopkg.in/alecthomas/kingpin.v2"
)

// Run is the main entry point to the server.  It parses command line flags and config file.
func Run(args []string) {
	app := kingpin.New("sharkey-server", "Certificate issuer of the ssh-ca system.")
	app.Version("0.0.1")

	configPath := app.Flag("config", "Path to config file for server.").Required().ExistingFile()

	startCmd := app.Command("start", "Run the sharkey server.")

	migrateCmd := app.Command("migrate", "Set up database/run migrations.")
	migrationsDir := migrateCmd.Flag("migrations", "Path to migrations directory.").ExistingDir()

	command := kingpin.MustParse(app.Parse(args))

	conf, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Error loading configuration file: %v", err)
	}

	switch command {
	case startCmd.FullCommand():
		api.Run(&conf)
	case migrateCmd.FullCommand():
		api.Migrate(*migrationsDir, &conf)
	}
}

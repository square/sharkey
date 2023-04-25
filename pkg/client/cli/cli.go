package cli

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/square/sharkey/pkg/client"
	"github.com/square/sharkey/pkg/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
)

func Run(args []string, logger *logrus.Logger) {
	logger.Println("Starting client")

	app := kingpin.New("sharkey-client", "Certificate client of the ssh-ca system.")
	configPath := app.Flag("config", "Path to config file for client.").Required().String()
	app.Version(version.Version())

	kingpin.MustParse(app.Parse(args))

	data, err := os.ReadFile(*configPath)
	if err != nil {
		logger.WithError(err).Fatalln("Error reading config file")
	}

	var conf client.Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		logger.WithError(err).Fatalln("Error parsing config file")
	}

	client.Run(&conf, logger)
}

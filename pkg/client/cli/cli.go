package cli

import (
	"github.com/square/sharkey/pkg/client"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

func Run(args []string) {
	log.Println("Starting client")

	app := kingpin.New("sharkey-client", "Certificate client of the ssh-ca system.")
	configPath := app.Flag("config", "Path to config file for client.").Required().String()
	app.Version("0.0.1")

	kingpin.MustParse(app.Parse(args))

	data, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Error reading config file: %s\n", err)
	}

	var conf client.Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		log.Fatalf("Error parsing config file: %s\n", err)
	}

	client.Run(&conf)
}

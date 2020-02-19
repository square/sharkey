package main

import (
	"github.com/sirupsen/logrus"
	"os"

	"github.com/square/sharkey/pkg/client/cli"
)

func main() {
	var logger = logrus.New()
	cli.Run(os.Args[1:], logger)
}

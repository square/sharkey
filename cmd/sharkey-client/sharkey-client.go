package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/square/sharkey/pkg/client/cli"
)

func main() {
	//Random comment for testing
	var logger = logrus.New()
	cli.Run(os.Args[1:], logger)
}

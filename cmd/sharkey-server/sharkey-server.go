package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/square/sharkey/pkg/server/cli"
)

func main() {
	var logger = logrus.New()
	cli.Run(os.Args[1:], logger)
}

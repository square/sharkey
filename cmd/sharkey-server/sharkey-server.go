package main

import (
	"os"

	"github.com/square/sharkey/pkg/server/cli"
)

func main() {
	cli.Run(os.Args[1:])
}

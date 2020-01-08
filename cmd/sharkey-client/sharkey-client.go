package main

import (
	"os"

	"github.com/square/sharkey/pkg/client/cli"
)

func main() {
	cli.Run(os.Args[1:])
}

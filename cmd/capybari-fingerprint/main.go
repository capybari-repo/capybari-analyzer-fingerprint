// Command capybari-fingerprint runs this capability on its own.
package main

import (
	fingerprint "github.com/capybari-repo/capybari-analyzer-fingerprint"
	"github.com/capybari-repo/capybari-core/standalone"
)

var version = "dev"

func main() { standalone.Main(version, fingerprint.New()) }

// Command name-guard is the CI check that keeps the names of real
// installations out of this public repository (the secrets job).
package main

import (
	"os"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/nameguard"
)

func main() {
	os.Exit(nameguard.Run(os.Getenv("NAME_GUARD_WORDS"), os.Getenv("NAME_GUARD_ROOT"),
		os.Getenv("NAME_GUARD_BASE"), os.Getenv("NAME_GUARD_HEAD"), os.Stdout))
}

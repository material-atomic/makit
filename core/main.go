// makit-core: the compiled half of makit (`makit top`, `makit scan`). The makit shell CLI execs it.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/material-atomic/makit/core/scan"
	"github.com/material-atomic/makit/core/shield"
	"github.com/material-atomic/makit/core/top"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: makit-core top|scan|shield|version [options]")
		os.Exit(2)
	}
	top.Version, scan.Version, shield.Version = version, version, version
	sub, args := os.Args[1], os.Args[2:]
	switch sub {
	case "version", "--version":
		fmt.Println("makit-core", version)
	case "top":
		fs := flag.NewFlagSet("top", flag.ExitOnError)
		interval := fs.Duration("interval", time.Second, "refresh interval (e.g. 1s, 500ms)")
		_ = fs.Parse(args)
		makit := os.Getenv("MAKIT_BIN")
		if makit == "" {
			makit, _ = exec.LookPath("makit")
		}
		if err := top.Run(makit, *interval); err != nil {
			fmt.Fprintln(os.Stderr, "makit top:", err)
			os.Exit(1)
		}
	case "scan":
		os.Exit(scan.Main(args))
	case "shield":
		os.Exit(shield.Main(args, scan.CatalogDirs()))
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", sub)
		os.Exit(2)
	}
}

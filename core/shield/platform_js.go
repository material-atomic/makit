//go:build js

package shield

import "os"

// In the browser (the config playground) nothing is locked or signalled; these keep the package building.
func lockFile(*os.File) error { return nil }

var reloadSignal os.Signal = os.Interrupt

//go:build !js

package shield

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive lock on f (released when it is closed).
func lockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

// reloadSignal makes the gate reload its config and state.
var reloadSignal os.Signal = syscall.SIGHUP

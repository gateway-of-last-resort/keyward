package keys

import (
	"os"
	"runtime"
)

// syncDir fsyncs a directory so a rename or create within it survives a crash.
// Windows has no directory fsync (Open+Sync returns "Access is denied"), so it's
// skipped there; the rename is still atomic.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

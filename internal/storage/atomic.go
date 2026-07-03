package storage

import (
	"os"
	"path/filepath"
)

// atomicWriteFile durably writes data to path: it creates a temp file in the
// same directory, fsyncs it, chmods it, renames it over path, then fsyncs the
// directory so the rename itself survives a crash. Without the fsyncs a rename
// can outlive a power loss while the data blocks don't, leaving a zero-length
// or truncated file. On any error the temp file is removed and path is left
// untouched. Callers that keep a .bak for rollback wrap this call.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	// chmod the temp before the rename so the file appears at its final path
	// already carrying the intended permissions.
	if err := os.Chmod(tmpPath, perm); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so that an entry rename/create within it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

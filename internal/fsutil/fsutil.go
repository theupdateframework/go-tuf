// Package fsutil defiens a set of internal utility functions used to
// interact with the file system.
package fsutil

import (
	"os"
	"path/filepath"
)

// IsMetaFile tests wheter a DirEntry appears to be a metaddata file or not.
func IsMetaFile(e os.DirEntry) (bool, error) {
	if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
		return false, nil
	}

	info, err := e.Info()
	if err != nil {
		return false, err
	}

	return info.Mode().IsRegular(), nil
}

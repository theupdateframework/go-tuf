// Package fsutil defiens a set of internal utility functions used to
// interact with the file system.
package fsutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

var ErrPermission = errors.New("unexpected permission")

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

// EnsurePemissions tests the provided file info to make sure the
// permission bits matches the provided.
func EnsurePermission(fi os.FileInfo, perm os.FileMode) error {
	// Clear all bits which are note related to the permission.
	mode := fi.Mode() & fs.ModePerm
	mask := ^perm
	if (mode & mask) != 0 {
		return ErrPermission
	}

	return nil
}

//go:build !windows
// +build !windows

package fsutil

import (
	"io/fs"
	"os"
)

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

package fsutil

import (
	"os"
)

// EnsureMaxPermissions tests the provided file info to make sure the
// permission bits matches the provided.
// On Windows system the permission bits are not really compatible with
// UNIX-like permission bits.
// Currently this method will always return nil.
func EnsureMaxPermissions(fi os.FileInfo, perm os.FileMode) error {
	return nil
}

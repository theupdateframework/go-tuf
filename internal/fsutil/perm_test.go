//go:build !windows
// +build !windows

package fsutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnsureMaxPermissions(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "file.txt")

	// Start with 0644 and change using os.Chmod so umask doesn't interfere.
	err := os.WriteFile(p, []byte(`AAA`), 0644)
	assert.NoError(t, err)

	// Check matching (1)
	err = os.Chmod(p, 0464)
	assert.NoError(t, err)
	fi, err := os.Stat(p)
	assert.NoError(t, err)
	err = EnsureMaxPermissions(fi, os.FileMode(0464))
	assert.NoError(t, err)

	// Check matching (2)
	err = os.Chmod(p, 0642)
	assert.NoError(t, err)
	fi, err = os.Stat(p)
	assert.NoError(t, err)
	err = EnsureMaxPermissions(fi, os.FileMode(0642))
	assert.NoError(t, err)

	// Check matching with file mode bits
	err = os.Chmod(p, 0444)
	assert.NoError(t, err)
	fi, err = os.Stat(p)
	assert.NoError(t, err)
	err = EnsureMaxPermissions(fi, os.ModeSymlink|os.ModeAppend|os.FileMode(0444))
	assert.NoError(t, err)

	// Check not matching (1)
	err = os.Chmod(p, 0444)
	assert.NoError(t, err)
	fi, err = os.Stat(p)
	assert.NoError(t, err)
	err = EnsureMaxPermissions(fi, os.FileMode(0400))
	assert.Error(t, err)

	// Check not matching (2)
	err = os.Chmod(p, 0444)
	assert.NoError(t, err)
	fi, err = os.Stat(p)
	assert.NoError(t, err)
	err = EnsureMaxPermissions(fi, os.FileMode(0222))
	assert.Error(t, err)

	// Check matching due to more restrictive perms on file
	err = os.Chmod(p, 0444)
	assert.NoError(t, err)
	fi, err = os.Stat(p)
	assert.NoError(t, err)
	err = EnsureMaxPermissions(fi, os.FileMode(0666))
	assert.NoError(t, err)
}

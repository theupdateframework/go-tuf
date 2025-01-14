package updater

import (
	"io"
	"os"
)

// CrossMoveFile is a verbose implementation of os.Rename() that enables cross-filesystem moves
func crossMoveFile(source *os.File, dest string, removeSource bool, overwrite bool) error {
	var flag int
	// Set flag according to overwrite preference
	if overwrite {
		flag = os.O_RDWR | os.O_CREATE | os.O_TRUNC
	} else {
		flag = os.O_RDWR | os.O_CREATE | os.O_EXCL
	}
	// Open the destination
	destFil, err := os.OpenFile(dest, flag, 0644)
	if err != nil {
		return err
	}
	// Copy !
	_, err = io.Copy(destFil, source)
	if err != nil {
		return err
	}
	// Belt and braces
	err = destFil.Sync()
	if err != nil {
		return err
	}
	// Remove source if requested
	if removeSource {
		// Remember the name
		sourceName := source.Name()
		// Close before removing !
		err = source.Close()
		if err != nil {
			return err
		}
		err = os.Remove(sourceName)
		if err != nil {
			return err
		}
	} else {
		err = source.Close()
		if err != nil {
			return err
		}
	}
	// We are done
	return destFil.Close()
}

// This helper command identifies duplicated metadata across multiple test
// stages, and replaces them with symlinks in order to make changes to them
// easier to read.

package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

func main() {
	for _, consistentSnapshot := range []bool{false, true} {
		err := linkifyDir(fmt.Sprintf("consistent-snapshot-%t", consistentSnapshot))
		if err != nil {
			log.Fatal(err)
		}
	}
}

func linkifyDir(rootDir string) error {
	stepDirs, err := readStepDirs(rootDir)
	if err != nil {
		return err
	}

	oldDir := stepDirs[0]
	oldHashes := computeHashes(oldDir)

	for _, dir := range stepDirs[1:] {
		log.Printf("checking: %s", dir)

		hashes := computeHashes(dir)

		for path, hash := range hashes {
			if oldHashes[path] == hash {
				newPath := filepath.Join(dir, path)
				oldPath := filepath.Join(oldDir, path)
				if err = linkifyPath(oldPath, newPath); err != nil {
					return err
				}
			}
		}

		oldDir = dir
		oldHashes = hashes
		log.Printf("-----")
	}

	return nil
}

func readStepDirs(rootDir string) ([]string, error) {
	dirEntries, err := ioutil.ReadDir(rootDir)
	if err != nil {
		return []string{}, err
	}

	// We only want to consider linkifying directories.
	var dirs []string
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			dirs = append(dirs, filepath.Join(rootDir, dirEntry.Name()))
		}
	}

	return dirs, nil
}

func computeHashes(dir string) map[string][32]byte {
	hashes := make(map[string][32]byte)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}

		bytes, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		hashes[path[len(dir)+1:]] = sha256.Sum256(bytes)

		return nil
	})
	if err != nil {
		log.Fatalf("failed to linkify: %s", err)
	}

	return hashes
}

func linkifyPath(oldPath string, newPath string) error {
	p, err := filepath.Rel(filepath.Dir(newPath), oldPath)
	if err != nil {
		return err
	}
	log.Printf("symlinking %s to %s", newPath, p)

	if err = os.Remove(newPath); err != nil {
		return err
	}
	if err = os.Symlink(p, newPath); err != nil {
		return err
	}

	return nil
}

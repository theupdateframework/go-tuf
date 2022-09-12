package generator

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"

	tuf "github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/pkg/keys"
)

var expirationDate = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)

type persistedKeys struct {
	Encrypted bool               `json:"encrypted"`
	Data      []*data.PrivateKey `json:"data"`
}

func assertNoError(err error) {
	if err != nil {
		panic(fmt.Sprintf("assertion failed: %s", err))
	}
}

// copyRepo recursively copies all regular files and directories under src
// to dst.  In the case where any destination file/directory exists
// (including dst itself), an error is returned.
func copyRepo(src string, dst string) error {
	copyToDest := func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		mode := info.Mode()
		if mode.IsDir() {
			return os.Mkdir(target, mode.Perm())
		} else if mode.IsRegular() {
			sfile, err := os.Open(path)
			if err != nil {
				return err
			}
			defer sfile.Close()
			dfile, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
			if err != nil {
				return err
			}
			defer dfile.Close()
			if _, err := io.Copy(dfile, sfile); err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf("unknown mode %v", mode)
	}
	return filepath.Walk(src, copyToDest)
}

func newRepo(dir string) *tuf.Repo {
	repo, err := tuf.NewRepoIndent(tuf.FileSystemStore(dir, nil), "", "\t")
	assertNoError(err)

	return repo
}

func commit(dir string, repo *tuf.Repo) {
	assertNoError(repo.SnapshotWithExpires(expirationDate))
	assertNoError(repo.TimestampWithExpires(expirationDate))
	assertNoError(repo.Commit())

	// Remove the keys directory to make sure we don't accidentally use a key.
	assertNoError(os.RemoveAll(filepath.Join(dir, "keys")))
}

func addKeys(repo *tuf.Repo, roleKeys map[string][]*data.PrivateKey) {
	for role, keyList := range roleKeys {
		for _, key := range keyList {
			signer, err := keys.GetSigner(key)
			assertNoError(err)
			assertNoError(repo.AddPrivateKeyWithExpires(role, signer, expirationDate))
		}
	}
}

func addTargets(repo *tuf.Repo, dir string, files map[string][]byte) {
	paths := []string{}
	for file, data := range files {
		path := filepath.Join(dir, "staged", "targets", file)
		assertNoError(os.MkdirAll(filepath.Dir(path), 0755))
		assertNoError(os.WriteFile(path, data, 0644))
		paths = append(paths, file)
	}
	assertNoError(repo.AddTargetsWithExpires(paths, nil, expirationDate))
}

func revokeKeys(repo *tuf.Repo, role string, keyList []*data.PrivateKey) {
	for _, key := range keyList {
		signer, err := keys.GetSigner(key)
		assertNoError(err)
		assertNoError(repo.RevokeKeyWithExpires(role, signer.PublicData().IDs()[0], expirationDate))
	}
}

func generateRepos(dir string, roleKeys map[string][][]*data.PrivateKey, consistentSnapshot bool) {
	// Collect all the initial keys we'll use when creating repositories.
	// We'll modify this to reflect rotated keys.
	keys := map[string][]*data.PrivateKey{
		"root":      roleKeys["root"][0],
		"targets":   roleKeys["targets"][0],
		"snapshot":  roleKeys["snapshot"][0],
		"timestamp": roleKeys["timestamp"][0],
	}

	// Create the initial repo.
	dir0 := filepath.Join(dir, "0")
	repo0 := newRepo(dir0)
	repo0.Init(consistentSnapshot)
	addKeys(repo0, keys)
	addTargets(repo0, dir0, map[string][]byte{"0": []byte("0")})
	commit(dir0, repo0)

	// Rotate all the keys to make sure that works.
	oldDir := dir0
	i := 1
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		// Setup the repo.
		stepName := fmt.Sprintf("%d", i)
		d := filepath.Join(dir, stepName)
		assertNoError(copyRepo(oldDir, d))
		repo := newRepo(d)
		addKeys(repo, keys)

		// Actually rotate the keys
		revokeKeys(repo, role, roleKeys[role][0])
		addKeys(repo, map[string][]*data.PrivateKey{
			role: roleKeys[role][1],
		})
		keys[role] = roleKeys[role][1]

		// Add a target to make sure that works, then commit.
		addTargets(repo, d, map[string][]byte{stepName: []byte(stepName)})
		commit(d, repo)

		i += 1
		oldDir = d
	}

	// Add another target file to make sure the workflow worked.
	stepName := fmt.Sprintf("%d", i)
	d := filepath.Join(dir, stepName)
	assertNoError(copyRepo(oldDir, d))
	repo := newRepo(d)
	addKeys(repo, keys)
	addTargets(repo, d, map[string][]byte{stepName: []byte(stepName)})
	commit(d, repo)
}

func Generate(dir string, keysPath string, consistentSnapshot bool) {
	f, err := os.Open(keysPath)
	assertNoError(err)

	var roleKeys map[string][][]*data.PrivateKey
	assertNoError(json.NewDecoder(f).Decode(&roleKeys))

	log.Printf("generating %s", dir)

	generateRepos(dir, roleKeys, consistentSnapshot)
}

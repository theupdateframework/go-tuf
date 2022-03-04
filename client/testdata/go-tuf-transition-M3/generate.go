package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
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

func copyRepo(src string, dst string) {
	cmd := exec.Command("cp", "-r", src, dst)
	assertNoError(cmd.Run())
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
		assertNoError(ioutil.WriteFile(path, data, 0644))
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

func generateRepos(dir string, consistentSnapshot bool) {
	f, err := os.Open("../keys.json")
	assertNoError(err)

	var roleKeys map[string][][]*data.PrivateKey
	assertNoError(json.NewDecoder(f).Decode(&roleKeys))

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
		copyRepo(oldDir, d)
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
	copyRepo(oldDir, d)
	repo := newRepo(d)
	addKeys(repo, keys)
	addTargets(repo, d, map[string][]byte{stepName: []byte(stepName)})
	commit(d, repo)
}

func main() {
	cwd, err := os.Getwd()
	assertNoError(err)

	for _, consistentSnapshot := range []bool{false, true} {
		name := fmt.Sprintf("consistent-snapshot-%t", consistentSnapshot)
		log.Printf("generating %s", name)
		generateRepos(filepath.Join(cwd, name), consistentSnapshot)
	}

}

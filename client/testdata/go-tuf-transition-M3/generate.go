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

	tuf "github.com/flynn/go-tuf"
	"github.com/flynn/go-tuf/sign"
)

var expirationDate = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)

type persistedKeys struct {
	Encrypted bool               `json:"encrypted"`
	Data      []*sign.PrivateKey `json:"data"`
}

func assertNotNil(err error) {
	if err != nil {
		panic(fmt.Sprintf("assertion failed: %s", err))
	}
}

func copyRepo(src string, dst string) {
	cmd := exec.Command("cp", "-r", src, dst)
	assertNotNil(cmd.Run())
}

func newRepo(dir string) *tuf.Repo {
	repo, err := tuf.NewRepoIndent(tuf.FileSystemStore(dir, nil), "", "\t")
	assertNotNil(err)

	return repo
}

func commit(dir string, repo *tuf.Repo) {
	assertNotNil(repo.SnapshotWithExpires(tuf.CompressionTypeNone, expirationDate))
	assertNotNil(repo.TimestampWithExpires(expirationDate))
	assertNotNil(repo.Commit())

	// Remove the keys directory to make sure we don't accidentally use a key.
	assertNotNil(os.RemoveAll(filepath.Join(dir, "keys")))
}

func addKeys(repo *tuf.Repo, roleKeys map[string][]*sign.PrivateKey) {
	for role, keys := range roleKeys {
		for _, key := range keys {
			assertNotNil(repo.AddPrivateKeyWithExpires(role, key, expirationDate))
		}
	}
}

func addTargets(repo *tuf.Repo, dir string, files map[string][]byte) {
	paths := []string{}
	for file, data := range files {
		path := filepath.Join(dir, "staged", "targets", file)
		assertNotNil(os.MkdirAll(filepath.Dir(path), 0755))
		assertNotNil(ioutil.WriteFile(path, data, 0644))
		paths = append(paths, file)
	}
	assertNotNil(repo.AddTargetsWithExpires(paths, nil, expirationDate))
}

func revokeKeys(repo *tuf.Repo, role string, keys []*sign.PrivateKey) {
	for _, key := range keys {
		assertNotNil(repo.RevokeKeyWithExpires(role, key.PublicData().IDs()[0], expirationDate))
	}
}

func generateRepos(dir string, consistentSnapshot bool) {
	f, err := os.Open("../keys.json")
	assertNotNil(err)

	var roleKeys map[string][][]*sign.PrivateKey
	assertNotNil(json.NewDecoder(f).Decode(&roleKeys))

	// Create the initial repo.
	dir0 := filepath.Join(dir, "0")
	repo0 := newRepo(dir0)
	repo0.Init(consistentSnapshot)
	addKeys(repo0, map[string][]*sign.PrivateKey{
		"root":      roleKeys["root"][0],
		"targets":   roleKeys["targets"][0],
		"snapshot":  roleKeys["snapshot"][0],
		"timestamp": roleKeys["timestamp"][0],
	})
	addTargets(repo0, dir0, map[string][]byte{"0": []byte("0")})
	commit(dir0, repo0)

	// Rotate the timestamp keys.
	dir1 := filepath.Join(dir, "1")
	copyRepo(dir0, dir1)
	repo1 := newRepo(dir1)
	addKeys(repo1, map[string][]*sign.PrivateKey{
		"root":      roleKeys["root"][0],
		"targets":   roleKeys["targets"][0],
		"snapshot":  roleKeys["snapshot"][0],
		"timestamp": roleKeys["timestamp"][0],
	})
	revokeKeys(repo1, "timestamp", roleKeys["timestamp"][0])
	addKeys(repo1, map[string][]*sign.PrivateKey{
		"timestamp": roleKeys["timestamp"][1],
	})
	addTargets(repo1, dir1, map[string][]byte{"1": []byte("1")})
	commit(dir1, repo1)

	// Rotate the root keys.
	dir2 := filepath.Join(dir, "2")
	copyRepo(dir1, dir2)
	repo2 := newRepo(dir2)
	addKeys(repo2, map[string][]*sign.PrivateKey{
		"root":      roleKeys["root"][0],
		"targets":   roleKeys["targets"][0],
		"snapshot":  roleKeys["snapshot"][0],
		"timestamp": roleKeys["timestamp"][1],
	})
	revokeKeys(repo2, "root", roleKeys["root"][0])
	addKeys(repo2, map[string][]*sign.PrivateKey{
		"root": roleKeys["root"][1],
	})
	addTargets(repo2, dir2, map[string][]byte{"2": []byte("2")})
	commit(dir2, repo2)

	// Add another target file to make sure the workflow worked.
	dir3 := filepath.Join(dir, "3")
	copyRepo(dir2, dir3)
	repo3 := newRepo(dir3)
	addKeys(repo3, map[string][]*sign.PrivateKey{
		"root":      roleKeys["root"][1],
		"targets":   roleKeys["targets"][0],
		"snapshot":  roleKeys["snapshot"][0],
		"timestamp": roleKeys["timestamp"][1],
	})
	addTargets(repo3, dir3, map[string][]byte{"3": []byte("3")})
	commit(dir3, repo3)
}

func main() {
	cwd, err := os.Getwd()
	assertNotNil(err)

	for _, consistentSnapshot := range []bool{false, true} {
		name := fmt.Sprintf("consistent-snapshot-%t", consistentSnapshot)
		log.Printf("generating %s", name)
		generateRepos(filepath.Join(cwd, name), consistentSnapshot)
	}

}

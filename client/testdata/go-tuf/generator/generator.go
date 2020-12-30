package generator

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	tuf "github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/sign"
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

func generateRepos(dir string, roleKeys map[string][][]*sign.PrivateKey, consistentSnapshot bool) {
	// Collect all the initial keys we'll use when creating repositories.
	// We'll modify this to reflect rotated keys.
	keys := map[string][]*sign.PrivateKey{
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
	i := 1
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		// Setup the repo.
		stepName := fmt.Sprintf("%d", i)
		d := filepath.Join(dir, stepName)
		repo := newRepo(d)
		addKeys(repo, keys)

		// Actually rotate the keys
		revokeKeys(repo, role, roleKeys[role][0])
		addKeys(repo, map[string][]*sign.PrivateKey{
			role: roleKeys[role][1],
		})
		keys[role] = roleKeys[role][1]

		// Add a target to make sure that works, then commit.
		addTargets(repo, d, map[string][]byte{stepName: []byte(stepName)})
		commit(d, repo)

		i++
	}

	// Add another target file to make sure the workflow worked.
	stepName := fmt.Sprintf("%d", i)
	d := filepath.Join(dir, stepName)
	repo := newRepo(d)
	addKeys(repo, keys)
	addTargets(repo, d, map[string][]byte{stepName: []byte(stepName)})
	commit(d, repo)
}

func Generate(dir string, keysPath string, consistentSnapshot bool) {
	f, err := os.Open(keysPath)
	assertNotNil(err)

	var roleKeys map[string][][]*sign.PrivateKey
	assertNotNil(json.NewDecoder(f).Decode(&roleKeys))

	log.Printf("generating %s", dir)

	generateRepos(dir, roleKeys, consistentSnapshot)
}

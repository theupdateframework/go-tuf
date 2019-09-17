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

func commit(repo *tuf.Repo) {
	assertNotNil(repo.SnapshotWithExpires(tuf.CompressionTypeNone, expirationDate))
	assertNotNil(repo.TimestampWithExpires(expirationDate))
	assertNotNil(repo.Commit())
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

// repoFilteredKeys filters out a key to make sure we can't sign with it. This
// is to make sure key rotation worked.
func filterKeys(dir string, role string, keys []*sign.PrivateKey) {
	var ids []string
	for _, key := range keys {
		ids = append(ids, key.PublicData().IDs()...)
	}

	path := filepath.Join(dir, "keys", fmt.Sprintf("%s.json", role))
	b, err := ioutil.ReadFile(path)
	assertNotNil(err)

	persistedKeys := &persistedKeys{}
	assertNotNil(json.Unmarshal(b, persistedKeys))

	newKeys := []*sign.PrivateKey{}
	for _, key := range persistedKeys.Data {
		found := false
		for _, id := range ids {
			if key.PublicData().ContainsID(id) {
				found = true
				break
			}
		}
		if !found {
			newKeys = append(newKeys, key)
		}
	}
	persistedKeys.Data = newKeys

	b, err = json.Marshal(persistedKeys)
	assertNotNil(err)

	err = ioutil.WriteFile(path, b, 0644)
	assertNotNil(err)
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
	commit(repo0)

	// Rotate the timestamp keys.
	dir1 := filepath.Join(dir, "1")
	copyRepo(dir0, dir1)
	repo1 := newRepo(dir1)
	revokeKeys(repo1, "timestamp", roleKeys["timestamp"][0])
	addKeys(repo1, map[string][]*sign.PrivateKey{
		"timestamp": roleKeys["timestamp"][1],
	})
	addTargets(repo1, dir1, map[string][]byte{"1": []byte("1")})
	commit(repo1)

	// Filter out the old timestamp key to make sure we can't use it.
	dir2 := filepath.Join(dir, "2")
	copyRepo(dir1, dir2)
	filterKeys(dir2, "timestamp", roleKeys["timestamp"][0])
	repo2 := newRepo(dir2)
	addTargets(repo2, dir2, map[string][]byte{"2": []byte("2")})
	commit(repo2)

	// Now, actually rotate the root keys.
	dir3 := filepath.Join(dir, "3")
	copyRepo(dir2, dir3)
	repo3 := newRepo(dir3)
	revokeKeys(repo3, "root", roleKeys["root"][0])
	addKeys(repo3, map[string][]*sign.PrivateKey{
		"root": roleKeys["root"][1],
	})
	addTargets(repo3, dir3, map[string][]byte{"3": []byte("3")})
	commit(repo3)

	// Filter out the old root key to make sure we can't use it.
	dir4 := filepath.Join(dir, "4")
	copyRepo(dir3, dir4)
	filterKeys(dir4, "root", roleKeys["root"][0])
	// The only way to force go-tuf to re-sign the root.json is to generate
	// or revoke a key. So why not do both?
	repo4 := newRepo(dir4)
	addKeys(repo4, map[string][]*sign.PrivateKey{
		"snapshot": roleKeys["snapshot"][1],
	})
	revokeKeys(repo4, "snapshot", roleKeys["snapshot"][0])
	addTargets(repo4, dir4, map[string][]byte{"4": []byte("4")})
	commit(repo4)

	// Add another target file to make sure the workflow worked.
	dir5 := filepath.Join(dir, "5")
	copyRepo(dir4, dir5)
	repo5 := newRepo(dir5)
	addTargets(repo5, dir5, map[string][]byte{"5": []byte("5")})
	commit(repo5)
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

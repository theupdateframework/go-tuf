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
	repo, err := tuf.NewRepo(tuf.FileSystemStore(dir, nil))
	assertNotNil(err)

	return repo
}

func commit(repo *tuf.Repo) {
	assertNotNil(repo.SnapshotWithExpires(tuf.CompressionTypeNone, expirationDate))
	assertNotNil(repo.TimestampWithExpires(expirationDate))
	assertNotNil(repo.Commit())
}

func genKeys(repo *tuf.Repo, roles []string) map[string][]string {
	ids := make(map[string][]string)

	for _, role := range roles {
		id, err := repo.GenKeyWithExpires(role, expirationDate)
		assertNotNil(err)
		ids[role] = id
	}

	return ids
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

func revokeKey(repo *tuf.Repo, role string, ids []string) {
	assertNotNil(repo.RevokeKeyWithExpires(role, ids[0], expirationDate))
}

// repoFilteredKeys filters out a key to make sure we can't sign with it. This
// is to make sure key rotation worked.
func filterKeys(dir string, role string, ids []string) {
	path := filepath.Join(dir, "keys", fmt.Sprintf("%s.json", role))
	b, err := ioutil.ReadFile(path)
	assertNotNil(err)

	keys := &persistedKeys{}
	assertNotNil(json.Unmarshal(b, keys))

	newKeys := []*sign.PrivateKey{}
	for _, key := range keys.Data {
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
	keys.Data = newKeys

	b, err = json.Marshal(keys)
	assertNotNil(err)

	err = ioutil.WriteFile(path, b, 0644)
	assertNotNil(err)
}

func generateRepos(dir string) {
	// Create the initial repo.
	dir0 := filepath.Join(dir, "0")
	repo0 := newRepo(dir0)
	ids := genKeys(repo0, []string{"root", "snapshot", "targets", "timestamp"})
	addTargets(repo0, dir0, map[string][]byte{"0": []byte("0")})
	commit(repo0)

	// Rotate the timestamp keys.
	dir1 := filepath.Join(dir, "1")
	copyRepo(dir0, dir1)
	repo1 := newRepo(dir1)
	revokeKey(repo1, "timestamp", ids["timestamp"])
	genKeys(repo1, []string{"timestamp"})
	addTargets(repo1, dir1, map[string][]byte{"1": []byte("1")})
	commit(repo1)

	// Filter out the old timestamp key to make sure we can't use it.
	dir2 := filepath.Join(dir, "2")
	copyRepo(dir1, dir2)
	filterKeys(dir2, "timestamp", ids["timestamp"])
	repo2 := newRepo(dir2)
	addTargets(repo2, dir2, map[string][]byte{"2": []byte("2")})
	commit(repo2)

	// Now, actually rotate the root keys.
	dir3 := filepath.Join(dir, "3")
	copyRepo(dir2, dir3)
	repo3 := newRepo(dir3)
	revokeKey(repo3, "root", ids["root"])
	genKeys(repo3, []string{"root"})
	addTargets(repo3, dir3, map[string][]byte{"3": []byte("3")})
	commit(repo3)

	// Filter out the old root key to make sure we can't use it.
	dir4 := filepath.Join(dir, "4")
	copyRepo(dir3, dir4)
	filterKeys(dir4, "root", ids["root"])
	// The only way to force go-tuf to re-sign the root.json is to generate
	// or revoke a key. So why not do both?
	repo4 := newRepo(dir4)
	ids = genKeys(repo4, []string{"snapshot"})
	revokeKey(repo4, "snapshot", ids["snapshot"])
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
		generateRepos(filepath.Join(cwd, name))
	}

}

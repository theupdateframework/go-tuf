package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/verify"
)

//Initializes a local HTTP server and serves TUF Repo.
func initTestTUFRepoServer(baseDir string, relPath string) (net.Listener, error) {
	serverDir := filepath.Join(baseDir, relPath)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	go http.Serve(l, http.FileServer(http.Dir(serverDir)))
	return l, err
}

// Initializes the client object with local files without fetching
// the latest version from the server.
func (c *Client) initWithLocal(rootKeys []*data.Key, threshold int, localrootpath string) error {
	if len(rootKeys) < threshold {
		return ErrInsufficientKeys
	}
	rootJSON, err := ioutil.ReadFile(localrootpath) //c.downloadMetaUnsafe("root.json", defaultRootDownloadLimit)
	if err != nil {
		return err
	}
	// create a new key database, and add all the public `rootKeys` to it.
	c.db = verify.NewDB()
	rootKeyIDs := make([]string, 0, len(rootKeys))
	for _, key := range rootKeys {
		for _, id := range key.IDs() {
			rootKeyIDs = append(rootKeyIDs, id)
			if err := c.db.AddKey(id, key); err != nil {
				return err
			}
		}
	}

	// add a mock "root" role that trusts the passed in key ids. These keys
	// will be used to verify the `root.json` we just fetched.
	role := &data.Role{Threshold: threshold, KeyIDs: rootKeyIDs}
	if err := c.db.AddRole("root", role); err != nil {
		return err
	}

	// verify that the new root is valid.
	if err := c.decodeRoot(rootJSON); err != nil {
		return err
	}

	return c.local.SetMeta("root.json", rootJSON)
}

//Initializes a TUF Client based on metadata in a given path.
func initTestTUFClient(baseDir string, relPath string, serverAddr string, initWithLocalMetadata bool) (*Client, error) {
	initialStateDir := filepath.Join(baseDir, relPath)
	opts := &HTTPRemoteOptions{
		MetadataPath: "metadata",
		TargetsPath:  "targets",
	}
	rawFile, err := ioutil.ReadFile(initialStateDir + "/" + "root.json")
	if err != nil {
		return nil, err
	}
	s := &data.Signed{}
	root := &data.Root{}
	if err := json.Unmarshal(rawFile, s); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(s.Signed, root); err != nil {
		return nil, err
	}
	var keys []*data.Key
	for _, sig := range s.Signatures {
		k, ok := root.Keys[sig.KeyID]
		if ok {
			keys = append(keys, k)
		}
	}

	remote, err := HTTPRemoteStore(fmt.Sprintf("http://%s/", serverAddr), opts, nil)
	if err != nil {
		return nil, err
	}
	c := NewClient(MemoryLocalStore(), remote)

	if initWithLocalMetadata {
		if err := c.initWithLocal(keys, 1, initialStateDir+"/"+"root.json"); err != nil {
			return nil, err
		}
	} else {
		if err := c.Init(keys, 1); err != nil {
			return nil, err
		}
	}
	files, err := ioutil.ReadDir(initialStateDir)
	if err != nil {
		return nil, err
	}

	// load local files
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		// ignoring consistent snapshot when loading initial state
		if len(strings.Split(name, ".")) == 1 && strings.HasSuffix(name, ".json") {
			rawFile, err := ioutil.ReadFile(initialStateDir + "/" + name)
			if err != nil {
				return nil, err
			}
			if err := c.local.SetMeta(name, rawFile); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

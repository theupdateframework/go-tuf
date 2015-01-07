package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"time"

	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/keys"
	"github.com/flynn/go-tuf/signed"
	"github.com/flynn/go-tuf/util"
)

var (
	ErrNotFound       = errors.New("tuf: file not found")
	ErrLatest         = errors.New("tuf: the current version is the latest")
	ErrWrongSize      = errors.New("tuf: unexpected file size")
	ErrNoRootKeys     = errors.New("tuf: no root keys found in local meta store")
	ErrChecksumFailed = errors.New("tuf: checksum failed")
)

// LocalStore is local storage for downloaded top-level metadata.
type LocalStore interface {
	// GetMeta returns top-level metadata from local storage. The keys are
	// in the form `ROLE.json`, with ROLE being a valid top-level role.
	GetMeta() (map[string]json.RawMessage, error)

	// SetMeta persists the given top-level metadata in local storage, the
	// name taking the same format as the keys returned by GetMeta.
	SetMeta(name string, meta json.RawMessage) error
}

// RemoteStore downloads top-level metadata and target files from a remote
// repository.
type RemoteStore interface {
	// Get downloads the given file from remote storage.
	//
	// `file` should be relative to the root of remote repository (e.g.
	// "root.json" or "targets/path/to/target/file.txt")
	Get(file string, size int64) (io.ReadCloser, error)
}

// Client provides methods for fetching updates from a remote repository and
// downloading remote target files.
type Client struct {
	local  LocalStore
	remote RemoteStore

	// The following four fields represent decoded metatdata from
	// local storage
	root      *data.Root
	targets   *data.Targets
	snapshot  *data.Snapshot
	timestamp *data.Timestamp

	// localMeta is the raw metadata from local storage and is used to
	// check whether remote metadata is present locally
	localMeta map[string]json.RawMessage

	// db is a key DB used for verifying metadata
	db *keys.DB
}

func NewClient(local LocalStore, remote RemoteStore) *Client {
	return &Client{
		local:  local,
		remote: remote,
	}
}

// Init initializes a local repository.
//
// The latest root.json is fetched from remote storage, verified using rootKeys
// and threshold, and then saved in local storage. It is expected that rootKeys
// were securely distributed with the software being updated.
func (c *Client) Init(rootKeys []*data.Key, threshold int) error {
	rootJSON, err := c.downloadMeta("root.json", nil)
	if err != nil {
		return err
	}

	c.db = keys.NewDB()
	rootKeyIDs := make([]string, len(rootKeys))
	for i, key := range rootKeys {
		id := key.ID()
		rootKeyIDs[i] = id
		if err := c.db.AddKey(id, key); err != nil {
			return err
		}
	}
	role := &data.Role{Threshold: threshold, KeyIDs: rootKeyIDs}
	if err := c.db.AddRole("root", role); err != nil {
		return err
	}

	if err := c.verifyRoot(rootJSON); err != nil {
		return err
	}

	return c.local.SetMeta("root.json", rootJSON)
}

// Update downloads and verifies remote metadata and returns updated targets.
//
// It performs the update part of "The client application" workflow from
// section 5.1 of the TUF spec:
//
// https://github.com/theupdateframework/tuf/blob/v0.9.9/docs/tuf-spec.txt#L714
func (c *Client) Update() (data.Files, error) {
	// Always start the update using local metadata
	if err := c.getLocalMeta(); err != nil {
		return nil, err
	}

	// TODO: If we get an invalid signature downloading timestamp.json
	//       or snapshot.json, download root.json and start again.

	// Get timestamp.json, extract snapshot.json file meta and save the
	// timestamp.json locally
	timestampJSON, err := c.downloadMeta("timestamp.json", nil)
	if err != nil {
		return nil, err
	}
	snapshotMeta, err := c.decodeTimestamp(timestampJSON)
	if err != nil {
		return nil, err
	}
	if err := c.local.SetMeta("timestamp.json", timestampJSON); err != nil {
		return nil, err
	}

	// Return ErrLatest if we already have the latest snapshot.json
	if c.hasMeta("snapshot.json", snapshotMeta) {
		return nil, ErrLatest
	}

	// Get snapshot.json, then extract root.json and targets.json file meta.
	//
	// The snapshot.json is only saved locally after checking root.json and
	// targets.json so that it will be re-downloaded on subsequent updates
	// if this update fails.
	snapshotJSON, err := c.downloadMeta("snapshot.json", &snapshotMeta)
	if err != nil {
		return nil, err
	}
	rootMeta, targetsMeta, err := c.decodeSnapshot(snapshotJSON)
	if err != nil {
		return nil, err
	}

	// If we don't have the root.json, download it, save it in local
	// storage and restart the update
	if !c.hasMeta("root.json", rootMeta) {
		rootJSON, err := c.downloadMeta("root.json", &rootMeta)
		if err != nil {
			return nil, err
		}
		if err := c.verifyRoot(rootJSON); err != nil {
			return nil, err
		}
		if err := c.local.SetMeta("root.json", rootJSON); err != nil {
			return nil, err
		}
		return c.Update()
	}

	// If we don't have the targets.json, download it, determine updated
	// targets and save targets.json in local storage
	var updatedTargets data.Files
	if !c.hasMeta("targets.json", targetsMeta) {
		targetsJSON, err := c.downloadMeta("targets.json", &targetsMeta)
		if err != nil {
			return nil, err
		}
		updatedTargets, err = c.decodeTargets(targetsJSON)
		if err != nil {
			return nil, err
		}
		if err := c.local.SetMeta("targets.json", targetsJSON); err != nil {
			return nil, err
		}
	}

	// Save the snapshot.json now it has been processed successfully
	if err := c.local.SetMeta("snapshot.json", snapshotJSON); err != nil {
		return nil, err
	}

	return updatedTargets, nil
}

// getLocalMeta decodes and verifies metadata from local storage.
//
// The verification of local files is purely for consistency, if an attacker
// has compromised the local storage, there is no guarantee it can be trusted.
func (c *Client) getLocalMeta() error {
	meta, err := c.local.GetMeta()
	if err != nil {
		return err
	}

	if rootJSON, ok := meta["root.json"]; ok {
		// unmarshal root.json without verifying as we need the root
		// keys first
		s := &data.Signed{}
		if err := json.Unmarshal(rootJSON, s); err != nil {
			return err
		}
		root := &data.Root{}
		if err := json.Unmarshal(s.Signed, root); err != nil {
			return err
		}
		db := keys.NewDB()
		for id, k := range root.Keys {
			if err := db.AddKey(id, k); err != nil {
				return err
			}
		}
		for name, role := range root.Roles {
			if err := db.AddRole(name, role); err != nil {
				return err
			}
		}
		if err := signed.Verify(s, "root", 0, db); err != nil {
			return err
		}
		c.root = root
		c.db = db
	} else {
		return ErrNoRootKeys
	}

	if snapshotJSON, ok := meta["snapshot.json"]; ok {
		snapshot := &data.Snapshot{}
		if err := signed.Unmarshal(snapshotJSON, snapshot, "snapshot", 0, c.db); err != nil {
			return err
		}
		c.snapshot = snapshot
	}

	if targetsJSON, ok := meta["targets.json"]; ok {
		targets := &data.Targets{}
		if err := signed.Unmarshal(targetsJSON, targets, "targets", 0, c.db); err != nil {
			return err
		}
		c.targets = targets
	}

	if timestampJSON, ok := meta["timestamp.json"]; ok {
		timestamp := &data.Timestamp{}
		if err := signed.Unmarshal(timestampJSON, timestamp, "timestamp", 0, c.db); err != nil {
			return err
		}
		c.timestamp = timestamp
	}

	c.localMeta = meta
	return nil
}

// downloadMeta downloads top-level metadata from remote storage and verifies
// it using the given file metadata.
func (c *Client) downloadMeta(name string, m *data.FileMeta) ([]byte, error) {
	var size int64
	if m != nil {
		size = m.Length
	}
	r, err := c.remote.Get(name, size)
	if err != nil {
		if err == ErrNotFound {
			return nil, ErrMissingRemoteMetadata{name}
		}
		return nil, err
	}
	defer r.Close()

	// if m is nil (e.g. when downloading timestamp.json, which has unknown
	// size), just read the entire stream and return it
	if m == nil {
		b, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
		return b, nil
	}

	// read exactly m.Length bytes from the stream
	buf := make([]byte, m.Length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	// verify buf matches given metadata
	meta, err := util.GenerateFileMeta(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	if !util.FileMetaEqual(meta, *m) {
		return nil, ErrChecksumFailed
	}
	return buf, nil
}

// verifyRoot verifies root metadata.
func (c *Client) verifyRoot(b json.RawMessage) error {
	var minVer int
	if c.root != nil {
		minVer = c.root.Version
	}
	s := &data.Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	return signed.Verify(s, "root", minVer, c.db)
}

// decodeSnapshot decodes and verifies snapshot metadata, and returns the new
// root and targets file meta.
func (c *Client) decodeSnapshot(b json.RawMessage) (data.FileMeta, data.FileMeta, error) {
	var minVer int
	if c.snapshot != nil {
		minVer = c.snapshot.Version
	}
	snapshot := &data.Snapshot{}
	if err := signed.Unmarshal(b, snapshot, "snapshot", minVer, c.db); err != nil {
		return data.FileMeta{}, data.FileMeta{}, err
	}
	return snapshot.Meta["root.json"], snapshot.Meta["targets.json"], nil
}

// decodeTargets decodes and verifies targets metadata, and returns updated
// targets.
func (c *Client) decodeTargets(b json.RawMessage) (data.Files, error) {
	var minVer int
	var currTargets data.Files
	if c.targets != nil {
		minVer = c.targets.Version
		currTargets = c.targets.Targets
	}
	targets := &data.Targets{}
	if err := signed.Unmarshal(b, targets, "targets", minVer, c.db); err != nil {
		return nil, err
	}
	updatedTargets := make(data.Files)
	for path, meta := range targets.Targets {
		if curr, ok := currTargets[path]; ok && util.FileMetaEqual(curr, meta) {
			continue
		}
		updatedTargets[path] = meta
	}
	return updatedTargets, nil
}

// decodeTimestamp decodes and verifies timestamp metadata, and returns the
// new snapshot file meta.
func (c *Client) decodeTimestamp(b json.RawMessage) (data.FileMeta, error) {
	var minVer int
	if c.timestamp != nil {
		minVer = c.timestamp.Version
	}
	timestamp := &data.Timestamp{}
	if err := signed.Unmarshal(b, timestamp, "timestamp", minVer, c.db); err != nil {
		return data.FileMeta{}, err
	}
	return timestamp.Meta["snapshot.json"], nil
}

// hasMeta checks whether local metadata has the given file meta
func (c *Client) hasMeta(name string, m data.FileMeta) bool {
	b, ok := c.localMeta[name]
	if !ok {
		return false
	}
	meta, err := util.GenerateFileMeta(bytes.NewReader(b))
	if err != nil {
		return false
	}
	return util.FileMetaEqual(meta, m)
}

func (c *Client) Expires() time.Time {
	return time.Time{}
}

func (c *Client) Version() int {
	return 0
}

func (c *Client) Files() data.Files {
	return nil
}

type Destination interface {
	io.Writer
	Size() (int, error)
	Delete() error
}

func (c *Client) Download(name string, dest Destination) error {
	/*
		The software update system instructs TUF to download a specific target file.

		TUF downloads and verifies the file and then makes the file available to the
		software update system.
	*/
	return nil
}

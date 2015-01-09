package client

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"time"

	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/keys"
	"github.com/flynn/go-tuf/signed"
	"github.com/flynn/go-tuf/util"
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

	// The following four fields represent the versions of metatdata from
	// local storage
	localRootVer      int
	localTargetsVer   int
	localSnapshotVer  int
	localTimestampVer int

	// targets is the list of available targets, either from local storage
	// or from recently downloaded targets metadata
	targets data.Files

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

	// Return ErrLatestSnapshot if we already have the latest snapshot.json
	if c.hasMeta("snapshot.json", snapshotMeta) {
		return nil, ErrLatestSnapshot{c.localSnapshotVer}
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
		c.localRootVer = root.Version
		c.db = db
	} else {
		return ErrNoRootKeys
	}

	if snapshotJSON, ok := meta["snapshot.json"]; ok {
		snapshot := &data.Snapshot{}
		if err := signed.Unmarshal(snapshotJSON, snapshot, "snapshot", 0, c.db); err != nil {
			return err
		}
		c.localSnapshotVer = snapshot.Version
	}

	if targetsJSON, ok := meta["targets.json"]; ok {
		targets := &data.Targets{}
		if err := signed.Unmarshal(targetsJSON, targets, "targets", 0, c.db); err != nil {
			return err
		}
		c.localTargetsVer = targets.Version
		c.targets = targets.Targets
	}

	if timestampJSON, ok := meta["timestamp.json"]; ok {
		timestamp := &data.Timestamp{}
		if err := signed.Unmarshal(timestampJSON, timestamp, "timestamp", 0, c.db); err != nil {
			return err
		}
		c.localTimestampVer = timestamp.Version
	}

	c.localMeta = meta
	return nil
}

// maxMetaSize is the maximum number of bytes that will be downloaded when
// getting remote metadata without knowing it's length.
const maxMetaSize = 50 * 1024

// downloadMeta downloads top-level metadata from remote storage and verifies
// it using the given file metadata.
func (c *Client) downloadMeta(name string, m *data.FileMeta) ([]byte, error) {
	var size int64
	if m != nil {
		size = m.Length
	}
	r, err := c.remote.Get(name, size)
	if err != nil {
		if IsNotFound(err) {
			return nil, ErrMissingRemoteMetadata{name}
		}
		return nil, err
	}
	defer r.Close()

	// if m is nil (e.g. when downloading timestamp.json, which has unknown
	// size), just read the stream (up to a sane maximum) and return it
	if m == nil {
		b, err := ioutil.ReadAll(io.LimitReader(r, maxMetaSize))
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
	if err := util.FileMetaEqual(meta, *m); err != nil {
		return nil, ErrDownloadFailed{name, err}
	}
	return buf, nil
}

// verifyRoot verifies root metadata.
func (c *Client) verifyRoot(b json.RawMessage) error {
	s := &data.Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	return signed.Verify(s, "root", c.localRootVer, c.db)
}

// decodeSnapshot decodes and verifies snapshot metadata, and returns the new
// root and targets file meta.
func (c *Client) decodeSnapshot(b json.RawMessage) (data.FileMeta, data.FileMeta, error) {
	snapshot := &data.Snapshot{}
	if err := signed.Unmarshal(b, snapshot, "snapshot", c.localSnapshotVer, c.db); err != nil {
		return data.FileMeta{}, data.FileMeta{}, err
	}
	return snapshot.Meta["root.json"], snapshot.Meta["targets.json"], nil
}

// decodeTargets decodes and verifies targets metadata, sets c.targets and
// returns updated targets.
func (c *Client) decodeTargets(b json.RawMessage) (data.Files, error) {
	targets := &data.Targets{}
	if err := signed.Unmarshal(b, targets, "targets", c.localTargetsVer, c.db); err != nil {
		return nil, err
	}
	updatedTargets := make(data.Files)
	for path, meta := range targets.Targets {
		if local, ok := c.targets[path]; ok {
			if err := util.FileMetaEqual(local, meta); err == nil {
				continue
			}
		}
		updatedTargets[path] = meta
	}
	c.targets = targets.Targets
	return updatedTargets, nil
}

// decodeTimestamp decodes and verifies timestamp metadata, and returns the
// new snapshot file meta.
func (c *Client) decodeTimestamp(b json.RawMessage) (data.FileMeta, error) {
	timestamp := &data.Timestamp{}
	if err := signed.Unmarshal(b, timestamp, "timestamp", c.localTimestampVer, c.db); err != nil {
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
	err = util.FileMetaEqual(meta, m)
	return err == nil
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
	Delete() error
}

// Download downloads the given target file from remote storage into dest.
//
// dest will be deleted and an error returned in the following situations:
//
//   * The target does not exist in the local targets.json
//   * The target does not exist in remote storage
//   * Metadata cannot be generated for the downloaded data
//   * Generated metadata does not match local metadata for the given file
func (c *Client) Download(name string, dest Destination) (err error) {
	// delete dest if there is an error
	defer func() {
		if err != nil {
			dest.Delete()
		}
	}()

	// populate c.targets from local storage if not set
	if c.targets == nil {
		if err := c.getLocalMeta(); err != nil {
			return err
		}
	}

	// return ErrNotFound if the file is not in the local targets.json
	localMeta, ok := c.targets[name]
	if !ok {
		return ErrUnknownTarget{name}
	}

	// get the data from remote storage
	r, err := c.remote.Get("targets/"+name, localMeta.Length)
	if err != nil {
		return err
	}
	defer r.Close()

	// wrap the data in a LimitReader so we download at most localMeta.Length bytes
	stream := io.LimitReader(r, localMeta.Length)

	// read the data, simultaneously writing it to dest and generating metadata
	actual, err := util.GenerateFileMeta(io.TeeReader(stream, dest))
	if err != nil {
		return ErrDownloadFailed{name, err}
	}

	// check the data has the correct length and hashes
	if err := util.FileMetaEqual(actual, localMeta); err != nil {
		if err == util.ErrWrongLength {
			return ErrWrongSize{name, actual.Length, localMeta.Length}
		}
		return ErrDownloadFailed{name, err}
	}

	return nil
}

// Targets returns the complete list of available targets.
func (c *Client) Targets() (data.Files, error) {
	// populate c.targets from local storage if not set
	if c.targets == nil {
		if err := c.getLocalMeta(); err != nil {
			return nil, err
		}
	}
	return c.targets, nil
}

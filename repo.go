package tuf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/keys"
	"github.com/flynn/go-tuf/signed"
	"github.com/flynn/go-tuf/util"
)

type CompressionType uint8

const (
	CompressionTypeNone CompressionType = iota
	CompressionTypeGzip
)

// topLevelManifests determines the order signatures are verified when committing.
var topLevelManifests = []string{
	"root.json",
	"targets.json",
	"snapshot.json",
	"timestamp.json",
}

var snapshotManifests = []string{
	"root.json",
	"targets.json",
}

type LocalStore interface {
	GetMeta() (map[string]json.RawMessage, error)
	SetMeta(string, json.RawMessage) error
	GetStagedTarget(string) (io.ReadCloser, error)
	Commit(map[string]json.RawMessage, data.Files) error
	GetKeys(string) ([]*data.Key, error)
	SaveKey(string, *data.Key) error
	Clean() error
}

type Repo struct {
	local LocalStore
	meta  map[string]json.RawMessage
}

func NewRepo(local LocalStore) (*Repo, error) {
	r := &Repo{local: local}

	var err error
	r.meta, err = local.GetMeta()
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Repo) db() (*keys.DB, error) {
	db := keys.NewDB()
	root, err := r.root()
	if err != nil {
		return nil, err
	}
	for id, k := range root.Keys {
		if err := db.AddKey(id, k); err != nil {
			return nil, err
		}
	}
	for name, role := range root.Roles {
		if err := db.AddRole(name, role); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func (r *Repo) root() (*data.Root, error) {
	rootJSON, ok := r.meta["root.json"]
	if !ok {
		return data.NewRoot(), nil
	}
	s := &data.Signed{}
	if err := json.Unmarshal(rootJSON, s); err != nil {
		return nil, err
	}
	root := &data.Root{}
	if err := json.Unmarshal(s.Signed, root); err != nil {
		return nil, err
	}
	return root, nil
}

func (r *Repo) snapshot() (*data.Snapshot, error) {
	snapshotJSON, ok := r.meta["snapshot.json"]
	if !ok {
		return data.NewSnapshot(), nil
	}
	s := &data.Signed{}
	if err := json.Unmarshal(snapshotJSON, s); err != nil {
		return nil, err
	}
	snapshot := &data.Snapshot{}
	if err := json.Unmarshal(s.Signed, snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (r *Repo) targets() (*data.Targets, error) {
	targetsJSON, ok := r.meta["targets.json"]
	if !ok {
		return data.NewTargets(), nil
	}
	s := &data.Signed{}
	if err := json.Unmarshal(targetsJSON, s); err != nil {
		return nil, err
	}
	targets := &data.Targets{}
	if err := json.Unmarshal(s.Signed, targets); err != nil {
		return nil, err
	}
	return targets, nil
}

func (r *Repo) timestamp() (*data.Timestamp, error) {
	timestampJSON, ok := r.meta["timestamp.json"]
	if !ok {
		return data.NewTimestamp(), nil
	}
	s := &data.Signed{}
	if err := json.Unmarshal(timestampJSON, s); err != nil {
		return nil, err
	}
	timestamp := &data.Timestamp{}
	if err := json.Unmarshal(s.Signed, timestamp); err != nil {
		return nil, err
	}
	return timestamp, nil
}

func (r *Repo) GenKey(role string) error {
	return r.GenKeyWithExpires(role, data.DefaultExpires(role))
}

func (r *Repo) GenKeyWithExpires(keyRole string, expires time.Time) error {
	if !keys.ValidRole(keyRole) {
		return ErrInvalidRole{keyRole}
	}

	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	root, err := r.root()
	if err != nil {
		return err
	}

	key, err := keys.NewKey()
	if err != nil {
		return err
	}
	if err := r.local.SaveKey(keyRole, key.SerializePrivate()); err != nil {
		return err
	}

	role, ok := root.Roles[keyRole]
	if !ok {
		role = &data.Role{KeyIDs: []string{}, Threshold: 1}
		root.Roles[keyRole] = role
	}
	role.KeyIDs = append(role.KeyIDs, key.ID)

	root.Keys[key.ID] = key.Serialize()
	root.Expires = expires
	root.Version++

	return r.setMeta("root.json", root)
}

func validExpires(expires time.Time) bool {
	return expires.Sub(time.Now()) > 0
}

func (r *Repo) RootKeys() ([]*data.Key, error) {
	root, err := r.root()
	if err != nil {
		return nil, err
	}
	role, ok := root.Roles["root"]
	if !ok {
		return nil, nil
	}
	rootKeys := make([]*data.Key, len(role.KeyIDs))
	for i, id := range role.KeyIDs {
		key, ok := root.Keys[id]
		if !ok {
			return nil, fmt.Errorf("tuf: invalid root metadata")
		}
		rootKeys[i] = key
	}
	return rootKeys, nil
}

func (r *Repo) setMeta(name string, meta interface{}) error {
	keys, err := r.local.GetKeys(strings.TrimSuffix(name, ".json"))
	if err != nil {
		return err
	}
	s, err := signed.Marshal(meta, keys...)
	if err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	r.meta[name] = b
	return r.local.SetMeta(name, b)
}

func (r *Repo) Sign(name string) error {
	role := strings.TrimSuffix(name, ".json")
	if !keys.ValidRole(role) {
		return ErrInvalidRole{role}
	}

	s, err := r.signedMeta(name)
	if err != nil {
		return err
	}

	keys, err := r.local.GetKeys(role)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return ErrInsufficientKeys{name}
	}
	for _, k := range keys {
		signed.Sign(s, k)
	}

	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	r.meta[name] = b
	return r.local.SetMeta(name, b)
}

func (r *Repo) signedMeta(name string) (*data.Signed, error) {
	b, ok := r.meta[name]
	if !ok {
		return nil, ErrMissingMetadata{name}
	}
	s := &data.Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}

func validManifest(name string) bool {
	for _, m := range topLevelManifests {
		if m == name {
			return true
		}
	}
	return false
}

func (r *Repo) AddTarget(path string, custom map[string]interface{}) error {
	return r.AddTargetWithExpires(path, custom, data.DefaultExpires("targets"))
}

func (r *Repo) AddTargetWithExpires(path string, custom map[string]interface{}, expires time.Time) error {
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	t, err := r.targets()
	if err != nil {
		return err
	}
	target, err := r.local.GetStagedTarget(path)
	if err != nil {
		return err
	}
	defer target.Close()
	t.Targets[path], err = util.GenerateFileMeta(target)
	if err != nil {
		return err
	}
	t.Expires = expires
	t.Version++
	return r.setMeta("targets.json", t)
}

func (r *Repo) RemoveTarget(path string) error {
	return r.RemoveTargetWithExpires(path, data.DefaultExpires("targets"))
}

func (r *Repo) RemoveTargetWithExpires(path string, expires time.Time) error {
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	t, err := r.targets()
	if err != nil {
		return err
	}
	if _, ok := t.Targets[path]; !ok {
		return nil
	}
	delete(t.Targets, path)
	t.Expires = expires
	t.Version++
	return r.setMeta("targets.json", t)
}

func (r *Repo) Snapshot(t CompressionType) error {
	return r.SnapshotWithExpires(t, data.DefaultExpires("snapshot"))
}

func (r *Repo) SnapshotWithExpires(t CompressionType, expires time.Time) error {
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	snapshot, err := r.snapshot()
	if err != nil {
		return err
	}
	db, err := r.db()
	if err != nil {
		return err
	}
	// TODO: generate compressed manifests
	for _, name := range snapshotManifests {
		if err := r.verifySignature(name, db); err != nil {
			return err
		}
		var err error
		snapshot.Meta[name], err = r.fileMeta(name)
		if err != nil {
			return err
		}
	}
	snapshot.Expires = expires
	snapshot.Version++
	return r.setMeta("snapshot.json", snapshot)
}

func (r *Repo) Timestamp() error {
	return r.TimestampWithExpires(data.DefaultExpires("timestamp"))
}

func (r *Repo) TimestampWithExpires(expires time.Time) error {
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	db, err := r.db()
	if err != nil {
		return err
	}
	if err := r.verifySignature("snapshot.json", db); err != nil {
		return err
	}
	timestamp, err := r.timestamp()
	if err != nil {
		return err
	}
	timestamp.Meta["snapshot.json"], err = r.fileMeta("snapshot.json")
	if err != nil {
		return err
	}
	timestamp.Expires = expires
	timestamp.Version++
	return r.setMeta("timestamp.json", timestamp)
}

func (r *Repo) Commit() error {
	// check we have all the metadata
	for _, name := range topLevelManifests {
		if _, ok := r.meta[name]; !ok {
			return ErrMissingMetadata{name}
		}
	}

	// verify hashes in snapshot.json are up to date
	snapshot, err := r.snapshot()
	if err != nil {
		return err
	}
	for _, name := range snapshotManifests {
		expected, ok := snapshot.Meta[name]
		if !ok {
			return fmt.Errorf("tuf: snapshot.json missing hash for %s", name)
		}
		actual, err := r.fileMeta(name)
		if err != nil {
			return err
		}
		if err := util.FileMetaEqual(actual, expected); err != nil {
			return fmt.Errorf("tuf: invalid %s in snapshot.json: %s", name, err)
		}
	}

	// verify hashes in timestamp.json are up to date
	timestamp, err := r.timestamp()
	if err != nil {
		return err
	}
	snapshotMeta, err := r.fileMeta("snapshot.json")
	if err != nil {
		return err
	}
	if err := util.FileMetaEqual(snapshotMeta, timestamp.Meta["snapshot.json"]); err != nil {
		return fmt.Errorf("tuf: invalid snapshot.json in timestamp.json: %s", err)
	}

	// verify all signatures are correct
	db, err := r.db()
	if err != nil {
		return err
	}
	for _, name := range topLevelManifests {
		if err := r.verifySignature(name, db); err != nil {
			return err
		}
	}
	t, err := r.targets()
	if err != nil {
		return err
	}
	return r.local.Commit(r.meta, t.Targets)
}

func (r *Repo) Clean() error {
	return r.local.Clean()
}

func (r *Repo) verifySignature(name string, db *keys.DB) error {
	s, err := r.signedMeta(name)
	if err != nil {
		return err
	}
	role := strings.TrimSuffix(name, ".json")
	if err := signed.Verify(s, role, 0, db); err != nil {
		return ErrInsufficientSignatures{name, err}
	}
	return nil
}

func (r *Repo) fileMeta(name string) (data.FileMeta, error) {
	b, ok := r.meta[name]
	if !ok {
		return data.FileMeta{}, ErrMissingMetadata{name}
	}
	return util.GenerateFileMeta(bytes.NewReader(b))
}

package tuf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	cjson "github.com/tent/canonical-json-go"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/sign"
	"github.com/theupdateframework/go-tuf/util"
	"github.com/theupdateframework/go-tuf/verify"
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

type targetsWalkFunc func(path string, target io.Reader) error

type LocalStore interface {
	GetMeta() (map[string]json.RawMessage, error)
	SetMeta(string, json.RawMessage) error

	// WalkStagedTargets calls targetsFn for each staged target file in paths.
	//
	// If paths is empty, all staged target files will be walked.
	WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error

	Commit(bool, map[string]int, map[string]data.Hashes) error
	GetSigningKeys(string) ([]sign.Signer, error)
	SavePrivateKey(string, *sign.PrivateKey) error
	Clean() error
}

type Repo struct {
	local          LocalStore
	hashAlgorithms []string
	meta           map[string]json.RawMessage
	prefix         string
	indent         string

	// TUF 1.0 requires that the root metadata version numbers in the
	// repository does not have any gaps. To avoid this, we will only
	// increment the number once until we commit.
	versionUpdated map[string]struct{}
}

func NewRepo(local LocalStore, hashAlgorithms ...string) (*Repo, error) {
	return NewRepoIndent(local, "", "", hashAlgorithms...)
}

func NewRepoIndent(local LocalStore, prefix string, indent string, hashAlgorithms ...string) (*Repo, error) {
	r := &Repo{
		local:          local,
		hashAlgorithms: hashAlgorithms,
		prefix:         prefix,
		indent:         indent,
		versionUpdated: make(map[string]struct{}),
	}

	var err error
	r.meta, err = local.GetMeta()
	if err != nil {
		return nil, err
	}
	return r, nil
}

//Init generates a new repository,
//check if some targets already existes
func (r *Repo) Init(consistentSnapshot bool) error {
	t, err := r.targets()
	if err != nil {
		return err
	}
	if len(t.Targets) > 0 {
		return ErrInitNotAllowed
	}
	if len(t.Roles) > 0 {
		return ErrInitNotAllowed
	}
	root := data.NewRoot()
	root.ConsistentSnapshot = consistentSnapshot
	return r.setMeta("root.json", root)
}

//db() creates a database: the root and top target roles
//are acquired, retrive their roles and keys,
//and add into the db,return the db object.
func (r *Repo) db() (*verify.DB, error) {
	db := verify.NewDB()
	root, err := r.root()
	if err != nil {
		return nil, err
	}
	target, err := r.targets()
	if err != nil {
		return nil, err
	}
	for id, k := range root.Keys {
		if err := db.AddKey(id, k); err != nil {
			// TUF is considering in TAP-12 removing the
			// requirement that the keyid hash algorithm be derived
			// from the public key. So to be forwards compatible,
			// we ignore `ErrWrongID` errors.
			//
			// TAP-12: https://github.com/theupdateframework/taps/blob/master/tap12.md
			if _, ok := err.(verify.ErrWrongID); !ok {
				return nil, err
			}
		}
	}
	for name, role := range root.Roles {
		if err := db.AddRole(name, role); err != nil {
			return nil, err
		}
	}
	for id, k := range target.Keys {
		if err := db.AddKey(id, k); err != nil {
			return nil, err
		}
	}
	for name, role := range target.Roles {
		if err := db.AddRole(name, role); err != nil {
			return nil, err
		}
	}
	return db, nil
}

//root() is a getter for the root role,
//return Root object if already exists
//otherwise create a new Root object
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

//snapshot() is a getter for the snapshot role,
//return a Snapshot object if already exists
//otherwise create a new Snapshot object
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

//RootVersion is getter for version of Root role
func (r *Repo) RootVersion() (int, error) {
	root, err := r.root()
	if err != nil {
		return -1, err
	}
	return root.Version, nil
}

//Targets is getter for the targeted files
func (r *Repo) Targets() (data.TargetFiles, error) {
	targets, err := r.targets()
	if err != nil {
		return nil, err
	}
	return targets.Targets, nil
}

//SetTargetsVersion is setter for version of top Target role
func (r *Repo) SetTargetsVersion(v int) error {
	t, err := r.targets()
	if err != nil {
		return err
	}
	t.Version = v
	return r.setMeta("targets.json", t)
}

//TargetsVersion is getter for version of top Target role
func (r *Repo) TargetsVersion() (int, error) {
	t, err := r.targets()
	if err != nil {
		return -1, err
	}
	return t.Version, nil
}

//SetTimestampVersion is a setter for the version of Timestamp role
func (r *Repo) SetTimestampVersion(v int) error {
	ts, err := r.timestamp()
	if err != nil {
		return err
	}
	ts.Version = v
	r.versionUpdated["timestamp.json"] = struct{}{}
	return r.setMeta("timestamp.json", ts)
}

//TimestampVersion is a getter for the version of Timestamp role
func (r *Repo) TimestampVersion() (int, error) {
	ts, err := r.timestamp()
	if err != nil {
		return -1, err
	}
	return ts.Version, nil
}

//SetSnapshotVersion is a setter for the version of Snapshot role
func (r *Repo) SetSnapshotVersion(v int) error {
	s, err := r.snapshot()
	if err != nil {
		return err
	}
	s.Version = v
	r.versionUpdated["snapshot.json"] = struct{}{}
	return r.setMeta("snapshot.json", s)
}

//SnapshotVersion is a getter for the version of Snapshot role
func (r *Repo) SnapshotVersion() (int, error) {
	s, err := r.snapshot()
	if err != nil {
		return -1, err
	}
	return s.Version, nil
}

//targets is getter for top Target role if existed,
//otherwise return a new Target role.
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

//timestamp is getter for Snapshot role if existed,
//otherwise return a new Snapshot role.
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

//GenKey call the function to generate a key pair for a role
//with default expiration date of root,
//default value is stored in data.DefaultExpires
func (r *Repo) GenKey(role string) ([]string, error) {
	return r.GenKeyWithExpires(role, data.DefaultExpires("root"))
}

//GenKeyWithExpires generate a key pair,
//add the private part to root role metadata,
//return the public key's ID
func (r *Repo) GenKeyWithExpires(keyRole string, expires time.Time) ([]string, error) {
	key, err := sign.GenerateEd25519Key()
	if err != nil {
		return []string{}, err
	}

	if err = r.AddPrivateKeyWithExpires(keyRole, key, expires); err != nil {
		return []string{}, err
	}

	return key.PublicData().IDs(), nil
}

//AddPrivateKey will call AddPrivateKeyWithExpires() with expiration added
func (r *Repo) AddPrivateKey(role string, key *sign.PrivateKey) error {
	return r.AddPrivateKeyWithExpires(role, key, data.DefaultExpires(role))
}

//AddPrivateKeyWithExpires will first verify the role and expiration,
//save the private part to local storage,
//format public part and add into Root role
func (r *Repo) AddPrivateKeyWithExpires(keyRole string, key *sign.PrivateKey, expires time.Time) error {
	root, err := r.root()
	if err != nil {
		return err
	}

	if !verify.ValidRole(keyRole) {
		return ErrInvalidRole{keyRole}
	}

	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	if err := r.local.SavePrivateKey(keyRole, key); err != nil {
		return err
	}
	pk := key.PublicData()

	role, ok := root.Roles[keyRole]
	if !ok {
		role = &data.Role{KeyIDs: []string{}, Threshold: 1}
		root.Roles[keyRole] = role
	}
	changed := false
	if role.AddKeyIDs(pk.IDs()) {
		changed = true
	}

	if root.AddKey(pk) {
		changed = true
	}

	if !changed {
		return nil
	}

	root.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated["root.json"]; !ok {
		root.Version++
		r.versionUpdated["root.json"] = struct{}{}
	}

	return r.setMeta("root.json", root)
}

//validExpires examine the expiration date is valid,
//only if the expiration date is in the future
func validExpires(expires time.Time) bool {
	return expires.Sub(time.Now()) > 0
}

//RootKeys return all Key objects in root metadata
func (r *Repo) RootKeys() ([]*data.Key, error) {
	root, err := r.root()
	if err != nil {
		return nil, err
	}
	role, ok := root.Roles["root"]
	if !ok {
		return nil, nil
	}

	// We might have multiple key ids that correspond to the same key, so
	// make sure we only return unique keys.
	seen := make(map[string]struct{})
	rootKeys := []*data.Key{}
	for _, id := range role.KeyIDs {
		key, ok := root.Keys[id]
		if !ok {
			return nil, fmt.Errorf("tuf: invalid root metadata")
		}
		found := false
		if _, ok := seen[id]; ok {
			found = true
			break
		}
		if !found {
			for _, id := range key.IDs() {
				seen[id] = struct{}{}
			}
			rootKeys = append(rootKeys, key)
		}
	}
	return rootKeys, nil
}

//TargetKeys return Key objects in Top Target metadata
//similar as RootKeys(), as top Target will contain delegated target roles
func (r *Repo) TargetKeys() ([]*data.Key, error) {
	root, err := r.root()
	if err != nil {
		return nil, err
	}
	role, ok := root.Roles["targets"]
	if !ok {
		return nil, nil
	}
	seen := make(map[string]struct{})
	targetKeys := []*data.Key{}
	for _, id := range role.KeyIDs {
		key, ok := root.Keys[id]
		if !ok {
			return nil, fmt.Errorf("tuf: invalid top target metadata")
		}
		found := false
		if _, ok := seen[id]; ok {
			found = true
			break
		}
		if !found {
			for _, id := range key.IDs() {
				seen[id] = struct{}{}
			}
			targetKeys = append(targetKeys, key)
		}
	}
	return targetKeys, nil
}

//RevokeKey will call RevokeKeyWithExpires
//add the default expiration time of root default
func (r *Repo) RevokeKey(role, id string) error {
	return r.RevokeKeyWithExpires(role, id, data.DefaultExpires("root"))
}

//RevokeKeyWithExpires will remove all matched keys from Root,
//and update Root's expiration & version
func (r *Repo) RevokeKeyWithExpires(keyRole, id string, expires time.Time) error {
	if !verify.ValidRole(keyRole) {
		return ErrInvalidRole{keyRole}
	}

	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	root, err := r.root()
	if err != nil {
		return err
	}

	key, ok := root.Keys[id]
	if !ok {
		return ErrKeyNotFound{keyRole, id}
	}

	role, ok := root.Roles[keyRole]
	if !ok {
		return ErrKeyNotFound{keyRole, id}
	}

	keyIDs := make([]string, 0, len(role.KeyIDs))

	// There may be multiple keyids that correspond to this key, so
	// filter all of them out.
	for _, keyID := range role.KeyIDs {
		if key.ContainsID(keyID) {
			continue
		}
		keyIDs = append(keyIDs, keyID)
	}
	if len(keyIDs) == len(role.KeyIDs) {
		return ErrKeyNotFound{keyRole, id}
	}
	role.KeyIDs = keyIDs

	for _, keyID := range key.IDs() {
		delete(root.Keys, keyID)
	}
	root.Roles[keyRole] = role
	root.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated["root.json"]; !ok {
		root.Version++
		r.versionUpdated["root.json"] = struct{}{}
	}

	return r.setMeta("root.json", root)
}

func (r *Repo) jsonMarshal(v interface{}) ([]byte, error) {
	b, err := cjson.Marshal(v)
	if err != nil {
		return []byte{}, err
	}

	if r.prefix == "" && r.indent == "" {
		return b, nil
	}

	var out bytes.Buffer
	if err := json.Indent(&out, b, r.prefix, r.indent); err != nil {
		return []byte{}, err
	}

	return out.Bytes(), nil
}

//setMeta will retrive the keys of this role,
//format the data as a json marshal,
//then storage to the local storage
func (r *Repo) setMeta(name string, meta interface{}) error {
	keys, err := r.getSigningKeys(strings.TrimSuffix(name, ".json"))
	if err != nil {
		return err
	}
	s, err := sign.Marshal(meta, keys...)
	if err != nil {
		return err
	}
	b, err := r.jsonMarshal(s)
	if err != nil {
		return err
	}
	r.meta[name] = b
	return r.local.SetMeta(name, b)
}

//Sign will get the metadata of a role,
//verify the keys, sign it,
//then write to the local.
func (r *Repo) Sign(name string) error {
	role := strings.TrimSuffix(name, ".json")
	if !verify.ValidRole(role) {
		return ErrInvalidRole{role}
	}

	s, err := r.signedMeta(name)
	if err != nil {
		return err
	}

	keys, err := r.getSigningKeys(role)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return ErrInsufficientKeys{name}
	}
	for _, k := range keys {
		sign.Sign(s, k)
	}

	b, err := r.jsonMarshal(s)
	if err != nil {
		return err
	}
	r.meta[name] = b
	return r.local.SetMeta(name, b)
}

// getSigningKeys returns available signing keys.
//
// Only keys contained in the keys db are returned (i.e. local keys which have
// been revoked are omitted), except for the root role in which case all local
// keys are returned (revoked root keys still need to sign new root metadata so
// clients can verify the new root.json and update their keys db accordingly).
func (r *Repo) getSigningKeys(name string) ([]sign.Signer, error) {
	signingKeys, err := r.local.GetSigningKeys(name)
	if err != nil {
		return nil, err
	}
	if name == "root" {
		return signingKeys, nil
	}
	db, err := r.db()
	if err != nil {
		return nil, err
	}
	role := db.GetRole(name)
	if role == nil {
		return nil, nil
	}
	if len(role.KeyIDs) == 0 {
		return nil, nil
	}
	keys := make([]sign.Signer, 0, len(role.KeyIDs))
	for _, key := range signingKeys {
		for _, id := range key.IDs() {
			if _, ok := role.KeyIDs[id]; ok {
				keys = append(keys, key)
			}
		}
	}
	return keys, nil
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

func validSnapManifest(name string) bool {
	for _, m := range snapshotManifests {
		if m == name {
			return true
		}
	}
	return false
}

//AddTarget and followed three is a set of functions adding targets,
//first two add default expiration parameters
func (r *Repo) AddTarget(path string, custom json.RawMessage) error {
	return r.AddTargets([]string{path}, custom)
}

func (r *Repo) AddTargets(paths []string, custom json.RawMessage) error {
	return r.AddTargetsWithExpires(paths, custom, data.DefaultExpires("targets"))
}

func (r *Repo) AddTargetWithExpires(path string, custom json.RawMessage, expires time.Time) error {
	return r.AddTargetsWithExpires([]string{path}, custom, expires)
}

//AddTargetsWithExpires first examine expiration, normalize the paths of targeted files,
//all targeted files should be in the directory "staged"
//walk through these files in dir"staged", check them exist,
//put metadata of the targeted file into top Target role,
//update top Target version
func (r *Repo) AddTargetsWithExpires(paths []string, custom json.RawMessage, expires time.Time) error {
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	t, err := r.targets()
	if err != nil {
		return err
	}
	normalizedPaths := make([]string, len(paths))
	for i, path := range paths {
		normalizedPaths[i] = util.NormalizeTarget(path)
	}
	if err := r.local.WalkStagedTargets(normalizedPaths, func(path string, target io.Reader) (err error) {
		meta, err := util.GenerateTargetFileMeta(target, r.hashAlgorithms...)
		if err != nil {
			return err
		}
		path = util.NormalizeTarget(path)

		// if we have custom metadata, set it, otherwise maintain
		// existing metadata if present
		if len(custom) > 0 {
			meta.Custom = &custom
		} else if t, ok := t.Targets[path]; ok {
			meta.Custom = t.Custom
		}

		// G2 -> we no longer desire any readers to ever observe non-prefix targets.
		delete(t.Targets, "/"+path)
		t.Targets[path] = meta
		return nil
	}); err != nil {
		return err
	}
	t.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated["targets.json"]; !ok {
		t.Version++
		r.versionUpdated["targets.json"] = struct{}{}
	}
	return r.setMeta("targets.json", t)
}

//The following four is a set of functions removing targets,
//first two add default expiration parameters
func (r *Repo) RemoveTarget(path string) error {
	return r.RemoveTargets([]string{path})
}

func (r *Repo) RemoveTargets(paths []string) error {
	return r.RemoveTargetsWithExpires(paths, data.DefaultExpires("targets"))
}

func (r *Repo) RemoveTargetWithExpires(path string, expires time.Time) error {
	return r.RemoveTargetsWithExpires([]string{path}, expires)
}

// If paths is empty, all targets will be removed.
func (r *Repo) RemoveTargetsWithExpires(paths []string, expires time.Time) error {
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	t, err := r.targets()
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		t.Targets = make(data.TargetFiles)
	} else {
		removed := false
		for _, path := range paths {
			path = util.NormalizeTarget(path)
			if _, ok := t.Targets[path]; !ok {
				continue
			}
			removed = true
			// G2 -> we no longer desire any readers to ever observe non-prefix targets.
			delete(t.Targets, "/"+path)
			delete(t.Targets, path)
		}
		if !removed {
			return nil
		}
	}
	t.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated["targets.json"]; !ok {
		t.Version++
		r.versionUpdated["targets.json"] = struct{}{}
	}
	return r.setMeta("targets.json", t)
}

//Snapshot call next function with default expiration date
func (r *Repo) Snapshot(t CompressionType) error {
	return r.SnapshotWithExpires(t, data.DefaultExpires("snapshot"))
}

//SnapshotWithExpires creates snapshot object and database for use,
//expands snapshotManifests to include delegated target roles,
//verify each of its signatures and update version
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

	//Expand snapshotManifest to include delegated roles
	targ, err := r.targets()
	if err != nil {
		return err
	}

	for name := range targ.Roles {
		snapshotManifests = append(snapshotManifests, name+".json")
	}

	// TODO: generate compressed manifests
	for _, name := range snapshotManifests {
		if err := r.verifySignature(name, db); err != nil {
			return err
		}
		var err error
		snapshot.Meta[name], err = r.snapshotFileMeta(name)
		if err != nil {
			return err
		}
	}
	snapshot.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated["snapshot.json"]; !ok {
		snapshot.Version++
		r.versionUpdated["snapshot.json"] = struct{}{}
	}
	return r.setMeta("snapshot.json", snapshot)
}

//Timestamp call next function with default expiration date
func (r *Repo) Timestamp() error {
	return r.TimestampWithExpires(data.DefaultExpires("timestamp"))
}

//TimestampWithExpires verifies snapshot, and update its own version
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
	timestamp.Meta["snapshot.json"], err = r.timestampFileMeta("snapshot.json")
	if err != nil {
		return err
	}
	timestamp.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated["timestamp.json"]; !ok {
		timestamp.Version++
		r.versionUpdated["timestamp.json"] = struct{}{}
	}
	return r.setMeta("timestamp.json", timestamp)
}

//fileVersions() acquires all role versions except Timestamp
func (r *Repo) fileVersions() (map[string]int, error) {
	root, err := r.root()
	if err != nil {
		return nil, err
	}
	targets, err := r.targets()
	if err != nil {
		return nil, err
	}
	snapshot, err := r.snapshot()
	if err != nil {
		return nil, err
	}
	versions := make(map[string]int)
	versions["root.json"] = root.Version
	versions["targets.json"] = targets.Version
	versions["snapshot.json"] = snapshot.Version

	//delegated target roles shall also being put in versions
	for tar := range targets.Roles {
		temp, err := r.delegationTargets(tar + ".json")
		if err != nil {
			return nil, err
		}
		versions[tar+".json"] = temp.Version
	}
	return versions, nil
}

//fileHashes() obtains Hashes component from
//all roles, include all delegated roles.
func (r *Repo) fileHashes() (map[string]data.Hashes, error) {
	hashes := make(map[string]data.Hashes)
	target, err := r.targets()
	if err != nil {
		return nil, err
	}
	timestamp, err := r.timestamp()
	if err != nil {
		return nil, err
	}
	snapshot, err := r.snapshot()
	if err != nil {
		return nil, err
	}
	if m, ok := snapshot.Meta["root.json"]; ok {
		hashes["root.json"] = m.Hashes
	}
	if m, ok := snapshot.Meta["targets.json"]; ok {
		hashes["targets.json"] = m.Hashes
	}
	for tar := range target.Roles {
		if m, ok := snapshot.Meta[tar+".json"]; ok {
			hashes[tar+".json"] = m.Hashes
		}
	}
	if m, ok := timestamp.Meta["snapshot.json"]; ok {
		hashes["snapshot.json"] = m.Hashes
	}
	t, err := r.targets()
	if err != nil {
		return nil, err
	}
	for name, meta := range t.Targets {
		hashes[path.Join("targets", name)] = meta.Hashes
	}
	for tar := range target.Roles {
		temp, err := r.delegationTargets(tar + ".json")
		if err != nil {
			return nil, err
		}
		for name, meta := range temp.Targets {
			hashes[path.Join("targets", name)] = meta.Hashes
		}
	}
	return hashes, nil
}

//Commit will do all verifications, include:
//all roles and delegated roles are valid,
//not missing any metadata,
//verify snapshot and timestamp are updated,
//verify all signatures,
//after all these call local Commit,
//which will move the targeted files under /staged to /repo.
func (r *Repo) Commit() error {
	// check roles are valid
	root, err := r.root()
	if err != nil {
		return err
	}

	// check roles in root are valid
	for name, role := range root.Roles {
		if len(role.KeyIDs) < role.Threshold {
			return ErrNotEnoughKeys{name, len(role.KeyIDs), role.Threshold}
		}
	}

	// check delegated target roles are valid
	target, err := r.targets()
	if err != nil {
		return err
	}
	for name, role := range target.Roles {
		if len(role.KeyIDs) < role.Threshold {
			return ErrNotEnoughKeys{name, len(role.KeyIDs), role.Threshold}
		}
	}

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
		actual, err := r.snapshotFileMeta(name)
		if err != nil {
			return err
		}
		if err := util.SnapshotFileMetaEqual(actual, expected); err != nil {
			return fmt.Errorf("tuf: invalid %s in snapshot.json: %s", name, err)
		}
	}

	// verify hashes in timestamp.json are up to date
	timestamp, err := r.timestamp()
	if err != nil {
		return err
	}
	snapshotMeta, err := r.timestampFileMeta("snapshot.json")
	if err != nil {
		return err
	}
	if err := util.TimestampFileMetaEqual(snapshotMeta, timestamp.Meta["snapshot.json"]); err != nil {
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

	versions, err := r.fileVersions()
	if err != nil {
		return err
	}
	hashes, err := r.fileHashes()
	if err != nil {
		return err
	}

	if err := r.local.Commit(root.ConsistentSnapshot, versions, hashes); err != nil {
		return err
	}

	// We can start incrementing versin numbers again now that we've
	// successfully committed the metadata to the local store.
	r.versionUpdated = make(map[string]struct{})

	return nil
}

func (r *Repo) Clean() error {
	return r.local.Clean()
}

func (r *Repo) verifySignature(name string, db *verify.DB) error {
	s, err := r.signedMeta(name)
	if err != nil {
		return err
	}
	role := strings.TrimSuffix(name, ".json")
	if err := db.Verify(s, role, 0); err != nil {
		return ErrInsufficientSignatures{name, err}
	}
	return nil
}

func (r *Repo) snapshotFileMeta(name string) (data.SnapshotFileMeta, error) {
	b, ok := r.meta[name]
	if !ok {
		return data.SnapshotFileMeta{}, ErrMissingMetadata{name}
	}
	return util.GenerateSnapshotFileMeta(bytes.NewReader(b), r.hashAlgorithms...)
}

func (r *Repo) timestampFileMeta(name string) (data.TimestampFileMeta, error) {
	b, ok := r.meta[name]
	if !ok {
		return data.TimestampFileMeta{}, ErrMissingMetadata{name}
	}
	return util.GenerateTimestampFileMeta(bytes.NewReader(b), r.hashAlgorithms...)
}

//delegationTargets is a getter for those delegation target roles
//Used for delegation only, create new target when not exist
//Name entry here should in format "roleName.json"
func (r *Repo) delegationTargets(nameJSON string) (*data.Targets, error) {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	targetsJSON, ok := r.meta[nameJSON]
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

// DelegateTargetVersion is a getter for a non-top target roles' meta
func (r *Repo) DelegateTargetVersion(nameJSON string) (int, error) {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	d, err := r.delegationTargets(nameJSON)
	if err != nil {
		return -1, err
	}
	return d.Version, nil
}

//SetDelegateTargetVersion is a setter of version
//for non-top target meta
func (r *Repo) SetDelegateTargetVersion(nameJSON string, v int) error {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	d, err := r.delegationTargets(nameJSON)
	if err != nil {
		return err
	}
	d.Version = v
	return r.setMeta(nameJSON, d)
}

//DelegateGenKey invokes DelegateGenKeyWithExpires with default expire time
func (r *Repo) DelegateGenKey(role string) ([]string, error) {
	return r.DelegateGenKeyWithExpires(role, data.DefaultExpires("targets"))
}

//DelegateGenKeyWithExpires generate a new key pair,
//invoke addkey and returns ID of new key
func (r *Repo) DelegateGenKeyWithExpires(keyRole string, expires time.Time) ([]string, error) {
	key, err := sign.GenerateEd25519Key()
	if err != nil {
		return []string{}, err
	}

	if err = r.DelegateAddPrivateKeyWithExpires(keyRole, key, expires); err != nil {
		return []string{}, err
	}

	return key.PublicData().IDs(), nil
}

//DelegateAddPrivateKey add a single private key
func (r *Repo) DelegateAddPrivateKey(role string, key *sign.PrivateKey) error {
	return r.DelegateAddPrivateKeyWithExpires(role, key, data.DefaultExpires(role))
}

//DelegateAddPrivateKeyWithExpires save new key to local,
//Add new role information and key info,
//Update the top targets.json
func (r *Repo) DelegateAddPrivateKeyWithExpires(nameJSON string, key *sign.PrivateKey, expires time.Time) error {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	name := strings.TrimSuffix(nameJSON, ".json")

	target, err := r.targets()
	if err != nil {
		return err
	}

	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	if err := r.local.SavePrivateKey(name, key); err != nil {
		return err
	}
	pk := key.PublicData()

	role, ok := target.Roles[name]
	if !ok {
		role = &data.Role{KeyIDs: []string{}, Threshold: 1}
		target.Roles[name] = role
	}

	changed := false
	if role.AddKeyIDs(pk.IDs()) {
		changed = true
	}

	if target.TargetAddKey(pk) {
		changed = true
	}

	if !changed {
		return nil
	}

	target.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated["targets.json"]; !ok {
		target.Version++
		r.versionUpdated["targets.json"] = struct{}{}
	}

	return r.setMeta("targets.json", target)
}

//DelegateRevokeKey revoke a key for a certain delegated role
func (r *Repo) DelegateRevokeKey(role, id string) error {
	return r.DelegateRevokeKeyWithExpires(role, id, data.DefaultExpires("targets"))
}

//DelegateRevokeKeyWithExpires revoke a key with new expire set
func (r *Repo) DelegateRevokeKeyWithExpires(keyRole, id string, expires time.Time) error {

	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	targ, err := r.targets()
	if err != nil {
		return err
	}

	key, ok := targ.Keys[id]
	if !ok {
		return ErrKeyNotFound{keyRole, id}
	}

	role, ok := targ.Roles[keyRole]
	if !ok {
		return ErrKeyNotFound{keyRole, id}
	}

	keyIDs := make([]string, 0, len(role.KeyIDs))

	// There may be multiple keyids that correspond to this key, so
	// filter all of them out.
	for _, keyID := range role.KeyIDs {
		if key.ContainsID(keyID) {
			continue
		}
		keyIDs = append(keyIDs, keyID)
	}
	if len(keyIDs) == len(role.KeyIDs) {
		return ErrKeyNotFound{keyRole, id}
	}
	role.KeyIDs = keyIDs

	for _, keyID := range key.IDs() {
		delete(targ.Keys, keyID)
	}
	targ.Roles[keyRole] = role
	targ.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated["targets.json"]; !ok {
		targ.Version++
		r.versionUpdated["targets.json"] = struct{}{}
	}

	return r.setMeta("targets.json", targ)
}

//DelegateAddTarget add a target to non-top target role
func (r *Repo) DelegateAddTarget(nameJSON, path string, custom json.RawMessage) error {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	return r.DelegateAddTargets(nameJSON, []string{path}, custom)
}

//DelegateAddTargets add targets to non-top target role
func (r *Repo) DelegateAddTargets(nameJSON string, paths []string, custom json.RawMessage) error {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	return r.DelegateAddTargetsWithExpires(nameJSON, paths, custom, data.DefaultExpires("targets"))
}

//DelegateAddTargetWithExpires adds single target to non-top target  role
func (r *Repo) DelegateAddTargetWithExpires(nameJSON string, path string, custom json.RawMessage, expires time.Time) error {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	return r.DelegateAddTargetsWithExpires(nameJSON, []string{path}, custom, expires)
}

//DelegateAddTargetsWithExpires add targets to non-top target role with expire date
func (r *Repo) DelegateAddTargetsWithExpires(nameJSON string, paths []string, custom json.RawMessage, expires time.Time) error {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}
	d, err := r.delegationTargets(nameJSON)
	if err != nil {
		return err
	}
	normalizedPaths := make([]string, len(paths))
	for i, path := range paths {
		normalizedPaths[i] = util.NormalizeTarget(path)
	}

	if err := r.local.WalkStagedTargets(normalizedPaths, func(path string, target io.Reader) (err error) {
		meta, err := util.GenerateTargetFileMeta(target, r.hashAlgorithms...)
		if err != nil {
			return err
		}
		path = util.NormalizeTarget(path)

		// if we have custom metadata, set it, otherwise maintain
		// existing metadata if present
		if len(custom) > 0 {
			meta.Custom = &custom
		} else if d, ok := d.Targets[path]; ok {
			meta.Custom = d.Custom
		}

		delete(d.Targets, "/"+path)
		d.Targets[path] = meta
		return nil
	}); err != nil {
		return err
	}
	d.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated[nameJSON]; !ok {
		d.Version++
		r.versionUpdated[nameJSON] = struct{}{}
	}
	return r.setMeta(nameJSON, d)
}

//DelegateRemoveTarget remove target for non-top target role
func (r *Repo) DelegateRemoveTarget(nameJSON, path string) error {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	return r.DelegateRemoveTargets(nameJSON, []string{path})
}

//DelegateRemoveTargets remove targets for non-top target role
func (r *Repo) DelegateRemoveTargets(nameJSON string, paths []string) error {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	return r.DelegateRemoveTargetsWithExpires(nameJSON, paths, data.DefaultExpires("targets"))
}

//DelegateRemoveTargetWithExpires calls the next function
func (r *Repo) DelegateRemoveTargetWithExpires(nameJSON string, path string, expires time.Time) error {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	return r.DelegateRemoveTargetsWithExpires(nameJSON, []string{path}, expires)
}

// DelegateRemoveTargetsWithExpires remove
// If paths is empty, all targets will be removed
func (r *Repo) DelegateRemoveTargetsWithExpires(nameJSON string, paths []string, expires time.Time) error {
	if !strings.Contains(nameJSON, ".json") {
		nameJSON = nameJSON + ".json"
	}
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}
	d, err := r.delegationTargets(nameJSON)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		d.Targets = make(data.TargetFiles)
	} else {
		removed := false
		for _, path := range paths {
			path = util.NormalizeTarget(path)
			if _, ok := d.Targets[path]; !ok {
				continue
			}
			removed = true
			// G2 -> we no longer desire any readers to ever observe non-prefix targets.
			delete(d.Targets, "/"+path)
			delete(d.Targets, path)
		}
		if !removed {
			return nil
		}
	}
	d.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated[nameJSON]; !ok {
		d.Version++
		r.versionUpdated[nameJSON] = struct{}{}
	}
	return r.setMeta(nameJSON, d)
}

package tuf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/internal/signer"
	"github.com/theupdateframework/go-tuf/pkg/keys"
	"github.com/theupdateframework/go-tuf/sign"
	"github.com/theupdateframework/go-tuf/util"
	"github.com/theupdateframework/go-tuf/verify"
)

// topLevelMetadata determines the order signatures are verified when committing.
var topLevelMetadata = []string{
	"root.json",
	"targets.json",
	"snapshot.json",
	"timestamp.json",
}

var snapshotMetadata = []string{
	"root.json",
	"targets.json",
}

// TargetsWalkFunc is a function of a target path name and a target payload used to
// execute some function on each staged target file. For example, it may normalize path
// names and generate target file metadata with additional custom metadata.
type TargetsWalkFunc func(path string, target io.Reader) error

type LocalStore interface {
	// GetMeta returns a map from metadata file names (e.g. root.json) to their raw JSON payload or an error.
	GetMeta() (map[string]json.RawMessage, error)

	// SetMeta is used to update a metadata file name with a JSON payload.
	SetMeta(string, json.RawMessage) error

	// WalkStagedTargets calls targetsFn for each staged target file in paths.
	//
	// If paths is empty, all staged target files will be walked.
	WalkStagedTargets(paths []string, targetsFn TargetsWalkFunc) error

	// Commit is used to publish staged files to the repository
	Commit(bool, map[string]int, map[string]data.Hashes) error

	// GetSigners return a list of signers for a role.
	GetSigners(string) ([]keys.Signer, error)

	// SaveSigner adds a signer to a role.
	SaveSigner(string, keys.Signer) error

	// Clean is used to remove all staged metadata files.
	Clean() error
}

type PassphraseChanger interface {
	// ChangePassphrase changes the passphrase for a role keys file.
	ChangePassphrase(string) error
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

func (r *Repo) Init(consistentSnapshot bool) error {
	t, err := r.targets()
	if err != nil {
		return err
	}
	if len(t.Targets) > 0 {
		return ErrInitNotAllowed
	}
	root := data.NewRoot()
	root.ConsistentSnapshot = consistentSnapshot
	err = r.setMeta("root.json", root)
	if err == nil {
		fmt.Println("Repository initialized")
	}
	return err
}

func (r *Repo) db() (*verify.DB, error) {
	db := verify.NewDB()
	root, err := r.root()
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

func (r *Repo) RootVersion() (int, error) {
	root, err := r.root()
	if err != nil {
		return -1, err
	}
	return root.Version, nil
}

func (r *Repo) GetThreshold(keyRole string) (int, error) {
	root, err := r.root()
	if err != nil {
		return -1, err
	}
	role, ok := root.Roles[keyRole]
	if !ok {
		return -1, ErrInvalidRole{keyRole}
	}

	return role.Threshold, nil
}

func (r *Repo) SetThreshold(keyRole string, t int) error {
	if !validMetadata(keyRole + ".json") {
		// Delegations are not currently supported, so return an error if this is not a
		// top-level metadata file.
		return ErrInvalidRole{keyRole}
	}
	root, err := r.root()
	if err != nil {
		return err
	}
	role, ok := root.Roles[keyRole]
	if !ok {
		return ErrInvalidRole{keyRole}
	}
	if role.Threshold == t {
		// Change was a no-op.
		return nil
	}
	role.Threshold = t
	if _, ok := r.versionUpdated["root.json"]; !ok {
		root.Version++
		r.versionUpdated["root.json"] = struct{}{}
	}
	return r.setMeta("root.json", root)
}

func (r *Repo) Targets() (data.TargetFiles, error) {
	targets, err := r.targets()
	if err != nil {
		return nil, err
	}
	return targets.Targets, nil
}

func (r *Repo) SetTargetsVersion(v int) error {
	t, err := r.targets()
	if err != nil {
		return err
	}
	t.Version = v
	return r.setMeta("targets.json", t)
}

func (r *Repo) TargetsVersion() (int, error) {
	t, err := r.targets()
	if err != nil {
		return -1, err
	}
	return t.Version, nil
}

func (r *Repo) SetTimestampVersion(v int) error {
	ts, err := r.timestamp()
	if err != nil {
		return err
	}
	ts.Version = v
	r.versionUpdated["timestamp.json"] = struct{}{}
	return r.setMeta("timestamp.json", ts)
}

func (r *Repo) TimestampVersion() (int, error) {
	ts, err := r.timestamp()
	if err != nil {
		return -1, err
	}
	return ts.Version, nil
}

func (r *Repo) SetSnapshotVersion(v int) error {
	s, err := r.snapshot()
	if err != nil {
		return err
	}

	s.Version = v
	r.versionUpdated["snapshot.json"] = struct{}{}
	return r.setMeta("snapshot.json", s)
}

func (r *Repo) SnapshotVersion() (int, error) {
	s, err := r.snapshot()
	if err != nil {
		return -1, err
	}
	return s.Version, nil
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

func (r *Repo) ChangePassphrase(keyRole string) error {
	if !verify.ValidRole(keyRole) {
		return ErrInvalidRole{keyRole}
	}

	if p, ok := r.local.(PassphraseChanger); ok {
		return p.ChangePassphrase(keyRole)
	}

	return ErrChangePassphraseNotSupported
}

func (r *Repo) GenKey(role string) ([]string, error) {
	return r.GenKeyWithExpires(role, data.DefaultExpires("root"))
}

func (r *Repo) GenKeyWithExpires(keyRole string, expires time.Time) (keyids []string, err error) {
	signer, err := keys.GenerateEd25519Key()
	if err != nil {
		return []string{}, err
	}

	if err = r.AddPrivateKeyWithExpires(keyRole, signer, expires); err != nil {
		return []string{}, err
	}
	keyids = signer.PublicData().IDs()
	return
}

func (r *Repo) AddPrivateKey(role string, signer keys.Signer) error {
	return r.AddPrivateKeyWithExpires(role, signer, data.DefaultExpires(role))
}

func (r *Repo) AddPrivateKeyWithExpires(keyRole string, signer keys.Signer, expires time.Time) error {
	if !verify.ValidRole(keyRole) {
		return ErrInvalidRole{keyRole}
	}

	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	if err := r.local.SaveSigner(keyRole, signer); err != nil {
		return err
	}

	if err := r.AddVerificationKeyWithExpiration(keyRole, signer.PublicData(), expires); err != nil {
		return err
	}

	return nil
}

func (r *Repo) AddVerificationKey(keyRole string, pk *data.PublicKey) error {
	return r.AddVerificationKeyWithExpiration(keyRole, pk, data.DefaultExpires(keyRole))
}

func (r *Repo) AddVerificationKeyWithExpiration(keyRole string, pk *data.PublicKey, expires time.Time) error {
	root, err := r.root()
	if err != nil {
		return err
	}

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

func validExpires(expires time.Time) bool {
	return time.Until(expires) > 0
}

func (r *Repo) RootKeys() ([]*data.PublicKey, error) {
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
	rootKeys := []*data.PublicKey{}
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

func (r *Repo) RevokeKey(role, id string) error {
	return r.RevokeKeyWithExpires(role, id, data.DefaultExpires("root"))
}

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

	// Create a list of filtered key IDs that do not contain the revoked key IDs.
	filteredKeyIDs := make([]string, 0, len(role.KeyIDs))

	// There may be multiple keyids that correspond to this key, so
	// filter all of them out.
	for _, keyID := range role.KeyIDs {
		if !key.ContainsID(keyID) {
			filteredKeyIDs = append(filteredKeyIDs, keyID)
		}
	}
	if len(filteredKeyIDs) == len(role.KeyIDs) {
		return ErrKeyNotFound{keyRole, id}
	}
	role.KeyIDs = filteredKeyIDs
	root.Roles[keyRole] = role

	// Only delete the key from root.Keys if the key is no longer in use by
	// any other role.
	key_in_use := false
	for _, role := range root.Roles {
		for _, keyID := range role.KeyIDs {
			if key.ContainsID(keyID) {
				key_in_use = true
			}
		}
	}
	if !key_in_use {
		for _, keyID := range key.IDs() {
			delete(root.Keys, keyID)
		}
	}
	root.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated["root.json"]; !ok {
		root.Version++
		r.versionUpdated["root.json"] = struct{}{}
	}

	err = r.setMeta("root.json", root)
	if err == nil {
		fmt.Println("Revoked", keyRole, "key with ID", id, "in root metadata")
	}
	return err
}

func (r *Repo) jsonMarshal(v interface{}) ([]byte, error) {
	b, err := cjson.EncodeCanonical(v)
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

func (r *Repo) setMeta(roleFilename string, meta interface{}) error {
	keys, err := r.getSortedSigningKeys(strings.TrimSuffix(roleFilename, ".json"))
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
	r.meta[roleFilename] = b
	return r.local.SetMeta(roleFilename, b)
}

func (r *Repo) Sign(roleFilename string) error {
	role := strings.TrimSuffix(roleFilename, ".json")
	if !verify.ValidRole(role) {
		return ErrInvalidRole{role}
	}

	s, err := r.SignedMeta(roleFilename)
	if err != nil {
		return err
	}

	keys, err := r.getSortedSigningKeys(role)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return ErrInsufficientKeys{roleFilename}
	}
	for _, k := range keys {
		sign.Sign(s, k)
	}

	b, err := r.jsonMarshal(s)
	if err != nil {
		return err
	}
	r.meta[roleFilename] = b
	err = r.local.SetMeta(roleFilename, b)
	if err == nil {
		fmt.Println("Signed", roleFilename, "with", len(keys), "key(s)")
	}
	return err
}

// AddOrUpdateSignature allows users to add or update a signature generated with an external tool.
// The name must be a valid metadata file name, like root.json.
func (r *Repo) AddOrUpdateSignature(roleFilename string, signature data.Signature) error {
	role := strings.TrimSuffix(roleFilename, ".json")
	if !verify.ValidRole(role) {
		return ErrInvalidRole{role}
	}

	// Check key ID is in valid for the role.
	db, err := r.db()
	if err != nil {
		return err
	}
	roleData := db.GetRole(role)
	if roleData == nil {
		return ErrInvalidRole{role}
	}
	if !roleData.ValidKey(signature.KeyID) {
		return verify.ErrInvalidKey
	}

	s, err := r.SignedMeta(roleFilename)
	if err != nil {
		return err
	}

	// Add or update signature.
	signatures := make([]data.Signature, 0, len(s.Signatures)+1)
	for _, sig := range s.Signatures {
		if sig.KeyID != signature.KeyID {
			signatures = append(signatures, sig)
		}
	}
	signatures = append(signatures, signature)
	s.Signatures = signatures

	// Check signature on signed meta. Ignore threshold errors as this may not be fully
	// signed.
	if err := db.VerifySignatures(s, role); err != nil {
		if _, ok := err.(verify.ErrRoleThreshold); !ok {
			return err
		}
	}

	b, err := r.jsonMarshal(s)
	if err != nil {
		return err
	}
	r.meta[roleFilename] = b

	return r.local.SetMeta(roleFilename, b)
}

// getSortedSigningKeys returns available signing keys, sorted by key ID.
//
// Only keys contained in the keys db are returned (i.e. local keys which have
// been revoked are omitted), except for the root role in which case all local
// keys are returned (revoked root keys still need to sign new root metadata so
// clients can verify the new root.json and update their keys db accordingly).
func (r *Repo) getSortedSigningKeys(name string) ([]keys.Signer, error) {
	signingKeys, err := r.local.GetSigners(name)
	if err != nil {
		return nil, err
	}
	if name == "root" {
		sorted := make([]keys.Signer, len(signingKeys))
		copy(sorted, signingKeys)
		sort.Sort(signer.ByIDs(sorted))
		return sorted, nil
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
	keys := make([]keys.Signer, 0, len(role.KeyIDs))
	for _, key := range signingKeys {
		for _, id := range key.PublicData().IDs() {
			if _, ok := role.KeyIDs[id]; ok {
				keys = append(keys, key)
			}
		}
	}

	sort.Sort(signer.ByIDs(keys))

	return keys, nil
}

// Used to retrieve the signable portion of the metadata when using an external signing tool.
func (r *Repo) SignedMeta(roleFilename string) (*data.Signed, error) {
	b, ok := r.meta[roleFilename]
	if !ok {
		return nil, ErrMissingMetadata{roleFilename}
	}
	s := &data.Signed{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}

func validMetadata(roleFilename string) bool {
	for _, m := range topLevelMetadata {
		if m == roleFilename {
			return true
		}
	}
	return false
}

func (r *Repo) AddTarget(path string, custom json.RawMessage) error {
	return r.AddTargets([]string{path}, custom)
}

func (r *Repo) AddTargets(paths []string, custom json.RawMessage) error {
	return r.AddTargetsWithExpires(paths, custom, data.DefaultExpires("targets"))
}

func (r *Repo) AddTargetWithExpires(path string, custom json.RawMessage, expires time.Time) error {
	return r.AddTargetsWithExpires([]string{path}, custom, expires)
}

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

	err = r.setMeta("targets.json", t)
	if err == nil {
		fmt.Println("Added/staged targets:")
		for k := range t.Targets {
			fmt.Println("*", k)
		}
	}
	return err
}

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
	removed_targets := []string{}
	if len(paths) == 0 {
		for rt := range t.Targets {
			removed_targets = append(removed_targets, rt)
		}
		t.Targets = make(data.TargetFiles)
	} else {
		removed := false
		for _, path := range paths {
			path = util.NormalizeTarget(path)
			if _, ok := t.Targets[path]; !ok {
				fmt.Println("The following target is not present:", path)
				continue
			}
			removed = true
			// G2 -> we no longer desire any readers to ever observe non-prefix targets.
			delete(t.Targets, "/"+path)
			delete(t.Targets, path)
			removed_targets = append(removed_targets, path)
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

	err = r.setMeta("targets.json", t)
	if err == nil {
		fmt.Println("Removed targets:")
		for _, v := range removed_targets {
			fmt.Println("*", v)
		}
		if len(t.Targets) != 0 {
			fmt.Println("Added/staged targets:")
			for k := range t.Targets {
				fmt.Println("*", k)
			}
		} else {
			fmt.Println("There are no added/staged targets")
		}
	}
	return err
}

func (r *Repo) Snapshot() error {
	return r.SnapshotWithExpires(data.DefaultExpires("snapshot"))
}

func (r *Repo) SnapshotWithExpires(expires time.Time) error {
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

	for _, name := range snapshotMetadata {
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
	err = r.setMeta("snapshot.json", snapshot)
	if err == nil {
		fmt.Println("Staged snapshot.json metadata with expiration date:", snapshot.Expires)
	}
	return err
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
	timestamp.Meta["snapshot.json"], err = r.timestampFileMeta("snapshot.json")
	if err != nil {
		return err
	}
	timestamp.Expires = expires.Round(time.Second)
	if _, ok := r.versionUpdated["timestamp.json"]; !ok {
		timestamp.Version++
		r.versionUpdated["timestamp.json"] = struct{}{}
	}

	err = r.setMeta("timestamp.json", timestamp)
	if err == nil {
		fmt.Println("Staged timestamp.json metadata with expiration date:", timestamp.Expires)
	}
	return err
}

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
	return versions, nil
}

func (r *Repo) fileHashes() (map[string]data.Hashes, error) {
	hashes := make(map[string]data.Hashes)
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
	return hashes, nil
}

func (r *Repo) Commit() error {
	// check we have all the metadata
	for _, name := range topLevelMetadata {
		if _, ok := r.meta[name]; !ok {
			return ErrMissingMetadata{name}
		}
	}

	// check roles are valid
	root, err := r.root()
	if err != nil {
		return err
	}
	for name, role := range root.Roles {
		if len(role.KeyIDs) < role.Threshold {
			return ErrNotEnoughKeys{name, len(role.KeyIDs), role.Threshold}
		}
	}

	// verify hashes in snapshot.json are up to date
	snapshot, err := r.snapshot()
	if err != nil {
		return err
	}
	for _, name := range snapshotMetadata {
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
	for _, name := range topLevelMetadata {
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

	err = r.local.Commit(root.ConsistentSnapshot, versions, hashes)
	if err == nil {
		// We can start incrementing version numbers again now that we've
		// successfully committed the metadata to the local store.
		r.versionUpdated = make(map[string]struct{})
		fmt.Println("Committed successfully")
	}
	return err
}

func (r *Repo) Clean() error {
	err := r.local.Clean()
	if err == nil {
		fmt.Println("Removed all staged metadata and target files")
	}
	return err
}

func (r *Repo) verifySignature(roleFilename string, db *verify.DB) error {
	s, err := r.SignedMeta(roleFilename)
	if err != nil {
		return err
	}
	role := strings.TrimSuffix(roleFilename, ".json")
	if err := db.Verify(s, role, 0); err != nil {
		return ErrInsufficientSignatures{roleFilename, err}
	}
	return nil
}

func (r *Repo) snapshotFileMeta(roleFilename string) (data.SnapshotFileMeta, error) {
	b, ok := r.meta[roleFilename]
	if !ok {
		return data.SnapshotFileMeta{}, ErrMissingMetadata{roleFilename}
	}
	return util.GenerateSnapshotFileMeta(bytes.NewReader(b), r.hashAlgorithms...)
}

func (r *Repo) timestampFileMeta(roleFilename string) (data.TimestampFileMeta, error) {
	b, ok := r.meta[roleFilename]
	if !ok {
		return data.TimestampFileMeta{}, ErrMissingMetadata{roleFilename}
	}
	return util.GenerateTimestampFileMeta(bytes.NewReader(b), r.hashAlgorithms...)
}

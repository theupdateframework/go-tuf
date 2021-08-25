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

	cjson "github.com/tent/canonical-json-go"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/internal/roles"
	"github.com/theupdateframework/go-tuf/internal/signer"
	"github.com/theupdateframework/go-tuf/internal/targets"
	"github.com/theupdateframework/go-tuf/pkg/keys"
	"github.com/theupdateframework/go-tuf/sign"
	"github.com/theupdateframework/go-tuf/util"
	"github.com/theupdateframework/go-tuf/verify"
)

const (
	// The maximum number of delegations to visit while traversing the delegations graph.
	defaultMaxDelegations = 32
)

// topLevelMetadata determines the order signatures are verified when committing.
var topLevelMetadata = []string{
	"root.json",
	"targets.json",
	"snapshot.json",
	"timestamp.json",
}

// TargetsWalkFunc is a function of a target path name and a target payload used to
// execute some function on each staged target file. For example, it may normalize path
// names and generate target file metadata with additional custom metadata.
type TargetsWalkFunc func(path string, target io.Reader) error

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
	t, err := r.topLevelTargets()
	if err != nil {
		return err
	}
	if len(t.Targets) > 0 {
		return ErrInitNotAllowed
	}
	root := data.NewRoot()
	root.ConsistentSnapshot = consistentSnapshot
	return r.setMeta("root.json", root)
}

func (r *Repo) topLevelKeysDB() (*verify.DB, error) {
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
	if !roles.IsTopLevelRole(keyRole) {
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
	targets, err := r.topLevelTargets()
	if err != nil {
		return nil, err
	}
	return targets.Targets, nil
}

func (r *Repo) SetTargetsVersion(v int) error {
	t, err := r.topLevelTargets()
	if err != nil {
		return err
	}
	t.Version = v
	return r.setMeta("targets.json", t)
}

func (r *Repo) TargetsVersion() (int, error) {
	t, err := r.topLevelTargets()
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

func (r *Repo) topLevelTargets() (*data.Targets, error) {
	return r.targets("targets")
}

func (r *Repo) targets(roleName string) (*data.Targets, error) {
	targetsJSON, ok := r.meta[roleName+".json"]
	if !ok {
		return data.NewTargets(), nil
	}
	s := &data.Signed{}
	if err := json.Unmarshal(targetsJSON, s); err != nil {
		return nil, fmt.Errorf("error unmarshalling for targets %q: %w", roleName, err)
	}
	targets := &data.Targets{}
	if err := json.Unmarshal(s.Signed, targets); err != nil {
		return nil, fmt.Errorf("error unmarshalling signed data for targets %q: %w", roleName, err)
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

func (r *Repo) GenKey(role string) ([]string, error) {
	// Not compatible with delegated roles.

	return r.GenKeyWithExpires(role, data.DefaultExpires("root"))
}

func (r *Repo) GenKeyWithExpires(keyRole string, expires time.Time) (keyids []string, err error) {
	// Not compatible with delegated roles.

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
	// Not compatible with delegated roles.

	return r.AddPrivateKeyWithExpires(role, signer, data.DefaultExpires(role))
}

func (r *Repo) AddPrivateKeyWithExpires(keyRole string, signer keys.Signer, expires time.Time) error {
	// Not compatible with delegated roles.
	if !roles.IsTopLevelRole(keyRole) {
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
	// Not compatible with delegated roles.

	return r.AddVerificationKeyWithExpiration(keyRole, pk, data.DefaultExpires(keyRole))
}

func (r *Repo) AddVerificationKeyWithExpiration(keyRole string, pk *data.PublicKey, expires time.Time) error {
	// Not compatible with delegated roles.
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
	return expires.Sub(time.Now()) > 0
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
	// Not compatible with delegated roles.

	return r.RevokeKeyWithExpires(role, id, data.DefaultExpires("root"))
}

func (r *Repo) RevokeKeyWithExpires(keyRole, id string, expires time.Time) error {
	// Not compatible with delegated roles.

	if !roles.IsTopLevelRole(keyRole) {
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

	return r.setMeta("root.json", root)
}

// AddTargetsDelegation is equivalent to AddTargetsDelegationWithExpires, but
// with a default expiration time.
func (r *Repo) AddTargetsDelegation(delegator string, role data.DelegatedRole, keys []*data.PublicKey) error {
	return r.AddTargetsDelegationWithExpires(delegator, role, keys, data.DefaultExpires("targets"))
}

// AddTargetsDelegationWithExpires adds a delegation from the delegator to the
// role specified in the role argument. Key IDs referenced in role.KeyIDs
// should have corresponding Key entries in the keys argument. New metadata is
// written with the given expiration time.
func (r *Repo) AddTargetsDelegationWithExpires(delegator string, role data.DelegatedRole, keys []*data.PublicKey, expires time.Time) error {
	t, err := r.targets(delegator)
	if err != nil {
		return fmt.Errorf("error getting delegator (%q) metadata: %w", delegator, err)
	}

	if t.Delegations == nil {
		t.Delegations = &data.Delegations{}
	}

	t.Delegations.Keys = make(map[string]*data.PublicKey)
	for _, keyID := range role.KeyIDs {
	keyLoop:
		for _, key := range keys {
			if key.ContainsID(keyID) {
				t.Delegations.Keys[keyID] = key
				break keyLoop
			}
		}
	}

	t.Delegations.Roles = append(t.Delegations.Roles, role)
	t.Expires = expires.Round(time.Second)

	delegatorFile := delegator + ".json"
	if _, ok := r.versionUpdated[delegatorFile]; !ok {
		t.Version++
		r.versionUpdated[delegatorFile] = struct{}{}
	}

	err = r.setMeta(delegatorFile, t)
	if err != nil {
		return fmt.Errorf("error setting metadata for %q: %w", delegatorFile, err)
	}

	delegatee := role.Name
	dt, err := r.targets(delegatee)
	if err != nil {
		return fmt.Errorf("error getting delegatee (%q) metadata: %w", delegatee, err)
	}

	delegateeFile := delegatee + ".json"
	if _, ok := r.versionUpdated[delegateeFile]; !ok {
		dt.Version++
		r.versionUpdated[delegateeFile] = struct{}{}
	}
	err = r.setMeta(delegateeFile, dt)
	if err != nil {
		return fmt.Errorf("error setting metadata for %q: %w", delegateeFile, err)
	}

	return nil
}

// AddTargetsDelegationsForPathHashBins is equivalent to
// AddTargetsDelegationsForPathHashBinsWithExpires, but with a default
// expiration time.
func (r *Repo) AddTargetsDelegationsForPathHashBins(delegator string, binRolePrefix string, log2NumBins uint8, keys []*data.PublicKey, threshold int) error {
	return r.AddTargetsDelegationsForPathHashBinsWithExpires(delegator, binRolePrefix, log2NumBins, keys, threshold, data.DefaultExpires("targets"))
}

// AddTargetsDelegationsForPathHashBinsWithExpires adds 2^(log2NumBins)
// delegations to the delegator role, which partition the target path hash
// space into bins using the PathHashPrefixes delegation mechanism. New
// metadata is written with the given expiration time.
func (r *Repo) AddTargetsDelegationsForPathHashBinsWithExpires(delegator string, binRolePrefix string, log2NumBins uint8, keys []*data.PublicKey, threshold int, expires time.Time) error {
	bins := targets.GenerateHashBins(log2NumBins)
	padWidth := targets.HashPrefixLength(log2NumBins)

	keyIDs := []string{}
	for _, key := range keys {
		keyIDs = append(keyIDs, key.IDs()...)
	}

	for _, bin := range bins {
		name := bin.Name(binRolePrefix, padWidth)
		err := r.AddTargetsDelegationWithExpires(delegator, data.DelegatedRole{
			Name:             name,
			KeyIDs:           keyIDs,
			PathHashPrefixes: bin.Enumerate(padWidth),
			Threshold:        threshold,
		}, keys, expires)
		if err != nil {
			return fmt.Errorf("error adding delegation from %v to %v: %w", delegator, name, err)
		}
	}

	return nil
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

func (r *Repo) setMeta(roleFilename string, meta interface{}) error {
	db, err := r.topLevelKeysDB()
	if err != nil {
		return err
	}
	signers, err := r.getSignersInDB(strings.TrimSuffix(roleFilename, ".json"), db)
	if err != nil {
		return err
	}
	return r.setMetaWithSigners(roleFilename, meta, signers)
}

func (r *Repo) setMetaWithSigners(roleFilename string, meta interface{}, signers []keys.Signer) error {
	fmt.Println("signing", roleFilename, signers)
	s, err := sign.Marshal(meta, signers...)
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
	if !roles.IsTopLevelRole(role) {
		return ErrInvalidRole{role}
	}

	s, err := r.SignedMeta(roleFilename)
	if err != nil {
		return err
	}

	db, err := r.topLevelKeysDB()
	if err != nil {
		return err
	}
	keys, err := r.getSignersInDB(role, db)
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
	return r.local.SetMeta(roleFilename, b)
}

// AddOrUpdateSignature allows users to add or update a signature generated with an external tool.
// The name must be a valid metadata file name, like root.json.
func (r *Repo) AddOrUpdateSignature(roleFilename string, signature data.Signature) error {
	role := strings.TrimSuffix(roleFilename, ".json")
	if !roles.IsTopLevelRole(role) {
		return ErrInvalidRole{role}
	}

	// Check key ID is in valid for the role.
	db, err := r.topLevelKeysDB()
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

// getSignersInDB returns available signing interfaces, sorted by key ID.
//
// Only keys contained in the keys db are returned (i.e. local keys which have
// been revoked are omitted), except for the root role in which case all local
// keys are returned (revoked root keys still need to sign new root metadata so
// clients can verify the new root.json and update their keys db accordingly).
func (r *Repo) getSignersInDB(roleName string, db *verify.DB) ([]keys.Signer, error) {
	fmt.Println("getting signing keys for", roleName)
	signers, err := r.local.GetSigners(roleName)
	if err != nil {
		return nil, err
	}

	if roleName == "root" {
		sorted := make([]keys.Signer, len(signers))
		copy(sorted, signers)
		sort.Sort(signer.ByIDs(sorted))
		return sorted, nil
	}

	role := db.GetRole(roleName)
	if role == nil {
		return nil, nil
	}
	if len(role.KeyIDs) == 0 {
		return nil, nil
	}

	signersInDB := make([]keys.Signer, 0, len(role.KeyIDs))
	for _, s := range signers {
		for _, id := range s.PublicData().IDs() {
			if _, ok := role.KeyIDs[id]; ok {
				signersInDB = append(signersInDB, s)
			}
		}
	}

	sort.Sort(signer.ByIDs(signersInDB))

	return signersInDB, nil
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

func (r *Repo) targetDelegationForPath(path string) (*data.Targets, *targets.Delegation, error) {
	topLevelKeysDB, err := r.topLevelKeysDB()
	if err != nil {
		return nil, nil, err
	}

	iterator := targets.NewDelegationsIterator(path, topLevelKeysDB)
	for i := 0; i < defaultMaxDelegations; i++ {
		d, ok := iterator.Next()
		if !ok {
			return nil, nil, ErrNoDelegatedTarget{Path: path}
		}

		targetsMeta, err := r.targets(d.Delegatee.Name)
		if err != nil {
			return nil, nil, err
		}
		fmt.Printf("role: %+v\n", targetsMeta)
		fmt.Printf("role.Delegations: %+v\n", targetsMeta.Delegations)
		fmt.Printf("d: %+v\n", d)
		fmt.Println()

		if targetsMeta.Delegations == nil || len(targetsMeta.Delegations.Roles) == 0 {
			return targetsMeta, &d, nil
		}

		db, err := verify.NewDBFromDelegations(targetsMeta.Delegations)
		if err != nil {
			return nil, nil, err
		}
		iterator.Add(targetsMeta.Delegations.Roles, d.Delegatee.Name, db)
	}

	return nil, nil, ErrNoDelegatedTarget{Path: path}
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

type targetsMetaWithKeyDB struct {
	meta *data.Targets
	db   *verify.DB
}

func (r *Repo) AddTargetsWithExpires(paths []string, custom json.RawMessage, expires time.Time) error {
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	normalizedPaths := make([]string, len(paths))
	for i, path := range paths {
		normalizedPaths[i] = util.NormalizeTarget(path)
	}

	targetsMetaToWrite := map[string]*targetsMetaWithKeyDB{}

	if err := r.local.WalkStagedTargets(normalizedPaths, func(path string, target io.Reader) (err error) {
		targetsMeta, delegation, err := r.targetDelegationForPath(path)
		if err != nil {
			return err
		}
		targetsRoleName := delegation.Delegatee.Name

		twk := &targetsMetaWithKeyDB{
			meta: targetsMeta,
			db:   delegation.DB,
		}

		// We accumulate changes in the targets manifests staged in
		// targetsMetaToWrite. If we've already visited a roleName in the
		// WalkStagedTargets iteration, use the staged metadata instead of the
		// fresh metadata from targetRoleForPath.
		if seenMetaWithKeys, ok := targetsMetaToWrite[targetsRoleName]; ok {
			// Merge the seen keys with the keys for the new target. If all
			// delegations to role.Name use the same keys (probably the most common
			// case with TUF) the merge is a no-op.
			// seenKeys := sets.StringSliceToSet(seenMetaWithKeys.keyIDs)
			// mergedKeys := seenMetaWithKeys.keyIDs

			// for _, keyID := range twk.keyIDs {
			// 	if _, ok := seenKeys[keyID]; !ok {
			// 		mergedKeys = append(mergedKeys, keyID)
			// 		seenKeys[keyID] = struct{}{}
			// 	}
			// }

			// seenMetaWithKeys.keyIDs = mergedKeys
			twk = seenMetaWithKeys
		}

		meta, err := util.GenerateTargetFileMeta(target, r.hashAlgorithms...)
		if err != nil {
			return err
		}
		path = util.NormalizeTarget(path)

		// if we have custom metadata, set it, otherwise maintain
		// existing metadata if present
		if len(custom) > 0 {
			meta.Custom = &custom
		} else if tf, ok := twk.meta.Targets[path]; ok {
			meta.Custom = tf.Custom
		}

		// G2 -> we no longer desire any readers to ever observe non-prefix targets.
		delete(twk.meta.Targets, "/"+path)
		twk.meta.Targets[path] = meta

		targetsMetaToWrite[targetsRoleName] = twk

		return nil
	}); err != nil {
		return err
	}

	if len(targetsMetaToWrite) == 0 {
		t, err := r.topLevelTargets()
		if err != nil {
			return err
		}

		db, err := r.topLevelKeysDB()
		if err != nil {
			return err
		}

		targetsMetaToWrite["targets"] = &targetsMetaWithKeyDB{
			meta: t,
			db:   db,
		}
	}

	exp := expires.Round(time.Second)
	for roleName, twk := range targetsMetaToWrite {
		twk.meta.Expires = exp

		manifestName := roleName + ".json"
		if _, ok := r.versionUpdated[manifestName]; !ok {
			twk.meta.Version++
			r.versionUpdated[manifestName] = struct{}{}
		}

		// signers := r.local.SignersForKeyIDs(twk.keyIDs)
		// signers, err := r.local.SignersForRole(roleName)
		// if err != nil {
		// 	return err
		// }

		// db, err := verify.NewDBFromDelegations(hh)
		// if err != nil {
		// 	return err
		// }
		signers, err := r.getSignersInDB(roleName, twk.db)
		if err != nil {
			return err
		}

		fmt.Println("signers for", roleName, "are", signers)
		fmt.Println("writing to manifest", manifestName)

		err = r.setMetaWithSigners(manifestName, twk.meta, signers)
		if err != nil {
			return err
		}

		// var err error
		// err = r.setMeta(manifestName, twk.meta)
		// if err != nil {
		// 	return err
		// }
	}

	return nil
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

	t, err := r.topLevelTargets()
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

func (r *Repo) Snapshot() error {
	return r.SnapshotWithExpires(data.DefaultExpires("snapshot"))
}

func (r *Repo) snapshotManifests() []string {
	ret := []string{"root.json", "targets.json"}

	for name := range r.meta {
		if !roles.IsVersionedManifest(name) &&
			roles.IsDelegatedTargetsManifest(name) {
			ret = append(ret, name)
		}
	}

	return ret
}

func (r *Repo) SnapshotWithExpires(expires time.Time) error {
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	snapshot, err := r.snapshot()
	if err != nil {
		return err
	}
	// db, err := r.topLevelKeysDB()
	// if err != nil {
	// 	return err
	// }

	for _, name := range r.snapshotManifests() {
		fmt.Println("snapshotting", name)
		// if err := r.verifySignature(name, db); err != nil {
		// 	return err
		// }
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

func (r *Repo) Timestamp() error {
	return r.TimestampWithExpires(data.DefaultExpires("timestamp"))
}

func (r *Repo) TimestampWithExpires(expires time.Time) error {
	if !validExpires(expires) {
		return ErrInvalidExpires{expires}
	}

	db, err := r.topLevelKeysDB()
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

func (r *Repo) fileVersions() (map[string]int, error) {
	versions := make(map[string]int)

	for fileName := range r.meta {
		if roles.IsVersionedManifest(fileName) {
			continue
		}

		roleName := strings.TrimSuffix(fileName, ".json")

		var version int

		switch roleName {
		case "root":
			root, err := r.root()
			if err != nil {
				return nil, err
			}
			version = root.Version
		case "snapshot":
			snapshot, err := r.snapshot()
			if err != nil {
				return nil, err
			}
			version = snapshot.Version
		case "timestamp":
			continue
		default:
			// Targets or delegated targets manifest.
			targets, err := r.targets(roleName)
			if err != nil {
				return nil, err
			}

			version = targets.Version
		}

		versions[fileName] = version
	}

	return versions, nil
}

func (r *Repo) fileHashes() (map[string]data.Hashes, error) {
	hashes := make(map[string]data.Hashes)

	for fileName := range r.meta {
		if roles.IsVersionedManifest(fileName) {
			continue
		}

		roleName := strings.TrimSuffix(fileName, ".json")

		switch roleName {
		case "snapshot":
			timestamp, err := r.timestamp()
			if err != nil {
				return nil, err
			}

			if m, ok := timestamp.Meta[fileName]; ok {
				hashes[fileName] = m.Hashes
			}
		case "timestamp":
			continue
		default:
			snapshot, err := r.snapshot()
			if err != nil {
				return nil, err
			}
			if m, ok := snapshot.Meta[fileName]; ok {
				hashes[fileName] = m.Hashes
			}

			// FIXME: Loading all targets into memory is not scalable if
			// there are many targets. This is used to Commit, so we should
			// only need new targets here.
			if roleName != "root" {
				t, err := r.targets(roleName)
				if err != nil {
					return nil, err
				}
				for name, m := range t.Targets {
					hashes[path.Join("targets", name)] = m.Hashes
				}
			}

		}

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
	for _, name := range r.snapshotManifests() {
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
	db, err := r.topLevelKeysDB()
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

	if err := r.local.Commit(root.ConsistentSnapshot, versions, hashes); err != nil {
		return err
	}

	// We can start incrementing version numbers again now that we've
	// successfully committed the metadata to the local store.
	r.versionUpdated = make(map[string]struct{})

	return nil
}

func (r *Repo) Clean() error {
	return r.local.Clean()
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

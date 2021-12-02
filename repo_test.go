package tuf

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/encrypted"
	"github.com/theupdateframework/go-tuf/pkg/keys"
	"github.com/theupdateframework/go-tuf/util"
	"github.com/theupdateframework/go-tuf/verify"
	"golang.org/x/crypto/ed25519"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type RepoSuite struct{}

var _ = Suite(&RepoSuite{})

func (RepoSuite) TestNewRepo(c *C) {
	testNewRepo(c, NewRepo)
}

func (RepoSuite) TestNewRepoIndent(c *C) {
	testNewRepo(c, func(local LocalStore, hashAlgorithms ...string) (*Repo, error) {
		return NewRepoIndent(local, "", "\t")
	})
}

// UniqueKeys returns the unique keys for each associated role.
// We might have multiple key IDs that correspond to the same key.
func UniqueKeys(r *data.Root) map[string][]*data.PublicKey {
	keysByRole := make(map[string][]*data.PublicKey)
	for name, role := range r.Roles {
		seen := make(map[string]struct{})
		roleKeys := []*data.PublicKey{}
		for _, id := range role.KeyIDs {
			// Double-check that there is actually a key with that ID.
			if key, ok := r.Keys[id]; ok {
				verifier, err := keys.GetVerifier(key)
				if err != nil {
					continue
				}
				val := verifier.Public()
				if _, ok := seen[val]; ok {
					continue
				}
				seen[val] = struct{}{}
				roleKeys = append(roleKeys, key)
			}
		}
		keysByRole[name] = roleKeys
	}
	return keysByRole
}

// AssertNumUniqueKeys verifies that the number of unique root keys for a given role is as expected.
func (*RepoSuite) assertNumUniqueKeys(c *C, root *data.Root, role string, num int) {
	c.Assert(UniqueKeys(root)[role], HasLen, num)
}

func testNewRepo(c *C, newRepo func(local LocalStore, hashAlgorithms ...string) (*Repo, error)) {
	meta := map[string]json.RawMessage{
		"root.json": []byte(`{
		  "signed": {
		    "_type": "root",
		    "version": 1,
		    "expires": "2015-12-26T03:26:55.821520874Z",
		    "keys": {},
		    "roles": {}
		  },
		  "signatures": []
		}`),
		"targets.json": []byte(`{
		  "signed": {
		    "_type": "targets",
		    "version": 1,
		    "expires": "2015-03-26T03:26:55.82155686Z",
		    "targets": {}
		  },
		  "signatures": []
		}`),
		"snapshot.json": []byte(`{
		  "signed": {
		    "_type": "snapshot",
		    "version": 1,
		    "expires": "2015-01-02T03:26:55.821585981Z",
		    "meta": {}
		  },
		  "signatures": []
		}`),
		"timestamp.json": []byte(`{
		  "signed": {
		    "_type": "timestamp",
		    "version": 1,
		    "expires": "2014-12-27T03:26:55.821599702Z",
		    "meta": {}
		  },
		  "signatures": []
		}`),
	}
	local := MemoryStore(meta, nil)
	r, err := newRepo(local)
	c.Assert(err, IsNil)

	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Type, Equals, "root")
	c.Assert(root.Version, Equals, 1)
	c.Assert(root.Keys, NotNil)
	c.Assert(root.Keys, HasLen, 0)

	targets, err := r.targets()
	c.Assert(err, IsNil)
	c.Assert(targets.Type, Equals, "targets")
	c.Assert(targets.Version, Equals, 1)
	c.Assert(targets.Targets, NotNil)
	c.Assert(targets.Targets, HasLen, 0)

	snapshot, err := r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Type, Equals, "snapshot")
	c.Assert(snapshot.Version, Equals, 1)
	c.Assert(snapshot.Meta, NotNil)
	c.Assert(snapshot.Meta, HasLen, 0)

	timestamp, err := r.timestamp()
	c.Assert(err, IsNil)
	c.Assert(timestamp.Type, Equals, "timestamp")
	c.Assert(timestamp.Version, Equals, 1)
	c.Assert(timestamp.Meta, NotNil)
	c.Assert(timestamp.Meta, HasLen, 0)
}

func (rs *RepoSuite) TestInit(c *C) {
	local := MemoryStore(
		make(map[string]json.RawMessage),
		map[string][]byte{"foo.txt": []byte("foo")},
	)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// Init() sets root.ConsistentSnapshot
	for _, v := range []bool{true, false} {
		c.Assert(r.Init(v), IsNil)
		root, err := r.root()
		c.Assert(err, IsNil)
		c.Assert(root.ConsistentSnapshot, Equals, v)
	}

	// Init() fails if targets have been added
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	c.Assert(r.Init(true), Equals, ErrInitNotAllowed)
}

func genKey(c *C, r *Repo, role string) []string {
	keyids, err := r.GenKey(role)
	c.Assert(err, IsNil)
	c.Assert(len(keyids) > 0, Equals, true)
	return keyids
}

func (rs *RepoSuite) TestGenKey(c *C) {
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// generate a key for an unknown role
	_, err = r.GenKey("foo")
	c.Assert(err, Equals, ErrInvalidRole{"foo"})

	// generate a root key
	ids := genKey(c, r, "root")

	// check root metadata is correct
	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, NotNil)
	c.Assert(root.Roles, HasLen, 1)
	rs.assertNumUniqueKeys(c, root, "root", 1)
	rootRole, ok := root.Roles["root"]
	if !ok {
		c.Fatal("missing root role")
	}
	c.Assert(rootRole.KeyIDs, HasLen, 1)
	c.Assert(rootRole.KeyIDs, DeepEquals, ids)
	for _, keyID := range ids {
		k, ok := root.Keys[keyID]
		if !ok {
			c.Fatal("missing key")
		}
		c.Assert(k.IDs(), DeepEquals, ids)
		pk, err := keys.GetVerifier(k)
		c.Assert(err, IsNil)
		c.Assert(pk.Public(), HasLen, ed25519.PublicKeySize)
	}

	// check root key + role are in db
	db, err := r.db()
	c.Assert(err, IsNil)
	for _, keyID := range ids {
		rootKey, err := db.GetVerifier(keyID)
		c.Assert(err, IsNil)
		c.Assert(rootKey.MarshalPublicKey().IDs(), DeepEquals, ids)
		role := db.GetRole("root")
		c.Assert(role.KeyIDs, DeepEquals, util.StringSliceToSet(ids))

		// check the key was saved correctly
		localKeys, err := local.GetSigners("root")
		c.Assert(err, IsNil)
		c.Assert(localKeys, HasLen, 1)
		c.Assert(localKeys[0].PublicData().IDs(), DeepEquals, ids)

		// check RootKeys() is correct
		rootKeys, err := r.RootKeys()
		c.Assert(err, IsNil)
		c.Assert(rootKeys, HasLen, 1)
		c.Assert(rootKeys[0].IDs(), DeepEquals, rootKey.MarshalPublicKey().IDs())
		pk, err := keys.GetVerifier(rootKeys[0])
		c.Assert(err, IsNil)
		c.Assert(pk.Public(), DeepEquals, rootKey.Public())
	}

	rootKey, err := db.GetVerifier(ids[0])
	c.Assert(err, IsNil)

	// generate two targets keys
	genKey(c, r, "targets")
	genKey(c, r, "targets")

	// check root metadata is correct
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, HasLen, 2)
	rs.assertNumUniqueKeys(c, root, "root", 1)
	rs.assertNumUniqueKeys(c, root, "targets", 2)
	targetsRole, ok := root.Roles["targets"]
	if !ok {
		c.Fatal("missing targets role")
	}
	c.Assert(targetsRole.KeyIDs, HasLen, 2)
	targetKeyIDs := make(map[string]struct{}, 2)
	db, err = r.db()
	c.Assert(err, IsNil)
	for _, id := range targetsRole.KeyIDs {
		targetKeyIDs[id] = struct{}{}
		_, ok = root.Keys[id]
		if !ok {
			c.Fatal("missing key")
		}
		verifier, err := db.GetVerifier(id)
		c.Assert(err, IsNil)
		c.Assert(verifier.MarshalPublicKey().ContainsID(id), Equals, true)
	}
	role := db.GetRole("targets")
	c.Assert(role.KeyIDs, DeepEquals, targetKeyIDs)

	// check RootKeys() is unchanged
	rootKeys, err := r.RootKeys()
	c.Assert(err, IsNil)
	c.Assert(rootKeys, HasLen, 1)
	c.Assert(rootKeys[0].IDs(), DeepEquals, rootKey.MarshalPublicKey().IDs())

	// check the keys were saved correctly
	localKeys, err := local.GetSigners("targets")
	c.Assert(err, IsNil)
	c.Assert(localKeys, HasLen, 2)
	for _, key := range localKeys {
		found := false
		for _, id := range targetsRole.KeyIDs {
			if key.PublicData().ContainsID(id) {
				found = true
				break
			}
		}
		if !found {
			c.Fatal("missing key")
		}
	}

	// check root.json got staged
	meta, err := local.GetMeta()
	c.Assert(err, IsNil)
	rootJSON, ok := meta["root.json"]
	if !ok {
		c.Fatal("missing root metadata")
	}
	s := &data.Signed{}
	c.Assert(json.Unmarshal(rootJSON, s), IsNil)
	stagedRoot := &data.Root{}
	c.Assert(json.Unmarshal(s.Signed, stagedRoot), IsNil)
	c.Assert(stagedRoot.Type, Equals, root.Type)
	c.Assert(stagedRoot.Version, Equals, root.Version)
	c.Assert(stagedRoot.Expires.UnixNano(), Equals, root.Expires.UnixNano())

	// make sure both root and stagedRoot have evaluated IDs(), otherwise
	// DeepEquals will fail because those values might not have been
	// computed yet.
	for _, key := range root.Keys {
		key.IDs()
	}
	for _, key := range stagedRoot.Keys {
		key.IDs()
	}
	c.Assert(stagedRoot.Keys, DeepEquals, root.Keys)
	c.Assert(stagedRoot.Roles, DeepEquals, root.Roles)
}

func addPrivateKey(c *C, r *Repo, role string, key keys.Signer) []string {
	err := r.AddPrivateKey(role, key)
	c.Assert(err, IsNil)
	keyids := key.PublicData().IDs()
	c.Assert(len(keyids) > 0, Equals, true)
	return keyids
}

func generateAndAddPrivateKey(c *C, r *Repo, role string) []string {
	signer, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	return addPrivateKey(c, r, role, signer)
}

func (rs *RepoSuite) TestAddPrivateKey(c *C) {
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// generate a key for an unknown role
	signer, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	err = r.AddPrivateKey("foo", signer)
	c.Assert(err, Equals, ErrInvalidRole{"foo"})

	// add a root key
	ids := addPrivateKey(c, r, "root", signer)

	// check root metadata is correct
	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Version, Equals, 1)
	c.Assert(root.Roles, NotNil)
	c.Assert(root.Roles, HasLen, 1)
	rs.assertNumUniqueKeys(c, root, "root", 1)
	rootRole, ok := root.Roles["root"]
	if !ok {
		c.Fatal("missing root role")
	}
	c.Assert(rootRole.KeyIDs, HasLen, 1)
	c.Assert(rootRole.KeyIDs, DeepEquals, ids)
	for _, keyID := range ids {
		k, ok := root.Keys[keyID]
		if !ok {
			c.Fatalf("missing key %s", keyID)
		}
		c.Assert(k.IDs(), DeepEquals, ids)
		pk, err := keys.GetVerifier(k)
		c.Assert(err, IsNil)
		c.Assert(pk.Public(), HasLen, ed25519.PublicKeySize)
	}

	// check root key + role are in db
	db, err := r.db()
	c.Assert(err, IsNil)
	for _, keyID := range ids {
		rootKey, err := db.GetVerifier(keyID)
		c.Assert(err, IsNil)
		c.Assert(rootKey.MarshalPublicKey().IDs(), DeepEquals, ids)
		role := db.GetRole("root")
		c.Assert(role.KeyIDs, DeepEquals, util.StringSliceToSet(ids))

		// check the key was saved correctly
		localKeys, err := local.GetSigners("root")
		c.Assert(err, IsNil)
		c.Assert(localKeys, HasLen, 1)
		c.Assert(localKeys[0].PublicData().IDs(), DeepEquals, ids)

		// check RootKeys() is correct
		rootKeys, err := r.RootKeys()
		c.Assert(err, IsNil)
		c.Assert(rootKeys, HasLen, 1)
		c.Assert(rootKeys[0].IDs(), DeepEquals, rootKey.MarshalPublicKey().IDs())
		pk, err := keys.GetVerifier(rootKeys[0])
		c.Assert(err, IsNil)
		c.Assert(pk.Public(), DeepEquals, rootKey.Public())
	}

	rootKey, err := db.GetVerifier(ids[0])
	c.Assert(err, IsNil)

	// generate two targets keys
	generateAndAddPrivateKey(c, r, "targets")
	generateAndAddPrivateKey(c, r, "targets")

	// check root metadata is correct
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, HasLen, 2)
	rs.assertNumUniqueKeys(c, root, "root", 1)
	rs.assertNumUniqueKeys(c, root, "targets", 2)
	targetsRole, ok := root.Roles["targets"]
	if !ok {
		c.Fatal("missing targets role")
	}
	c.Assert(targetsRole.KeyIDs, HasLen, 2)
	targetKeyIDs := make(map[string]struct{}, 2)
	db, err = r.db()
	c.Assert(err, IsNil)
	for _, id := range targetsRole.KeyIDs {
		targetKeyIDs[id] = struct{}{}
		_, ok = root.Keys[id]
		if !ok {
			c.Fatal("missing key")
		}
		verifier, err := db.GetVerifier(id)
		c.Assert(err, IsNil)
		c.Assert(verifier.MarshalPublicKey().ContainsID(id), Equals, true)
	}
	role := db.GetRole("targets")
	c.Assert(role.KeyIDs, DeepEquals, targetKeyIDs)

	// check RootKeys() is unchanged
	rootKeys, err := r.RootKeys()
	c.Assert(err, IsNil)
	c.Assert(rootKeys, HasLen, 1)
	c.Assert(rootKeys[0].IDs(), DeepEquals, rootKey.MarshalPublicKey().IDs())

	// check the keys were saved correctly
	localKeys, err := local.GetSigners("targets")
	c.Assert(err, IsNil)
	c.Assert(localKeys, HasLen, 2)
	for _, key := range localKeys {
		found := false
		for _, id := range targetsRole.KeyIDs {
			if key.PublicData().ContainsID(id) {
				found = true
				break
			}
		}
		if !found {
			c.Fatal("missing key")
		}
	}

	// check root.json got staged
	meta, err := local.GetMeta()
	c.Assert(err, IsNil)
	rootJSON, ok := meta["root.json"]
	if !ok {
		c.Fatal("missing root metadata")
	}
	s := &data.Signed{}
	c.Assert(json.Unmarshal(rootJSON, s), IsNil)
	stagedRoot := &data.Root{}
	c.Assert(json.Unmarshal(s.Signed, stagedRoot), IsNil)
	c.Assert(stagedRoot.Type, Equals, root.Type)
	c.Assert(stagedRoot.Version, Equals, root.Version)
	c.Assert(stagedRoot.Expires.UnixNano(), Equals, root.Expires.UnixNano())

	// make sure both root and stagedRoot have evaluated IDs(), otherwise
	// DeepEquals will fail because those values might not have been
	// computed yet.
	for _, key := range root.Keys {
		key.IDs()
	}
	for _, key := range stagedRoot.Keys {
		key.IDs()
	}
	c.Assert(stagedRoot.Keys, DeepEquals, root.Keys)
	c.Assert(stagedRoot.Roles, DeepEquals, root.Roles)

	// commit to make sure we don't modify metadata after committing metadata.
	generateAndAddPrivateKey(c, r, "snapshot")
	generateAndAddPrivateKey(c, r, "timestamp")
	c.Assert(r.AddTargets([]string{}, nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// add the same root key to make sure the metadata is unmodified.
	oldRoot, err := r.root()
	c.Assert(err, IsNil)
	addPrivateKey(c, r, "root", signer)
	newRoot, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(oldRoot, DeepEquals, newRoot)
	if _, ok := r.versionUpdated["root.json"]; ok {
		c.Fatal("root should not be marked dirty")
	}
}

func (rs *RepoSuite) TestRevokeKey(c *C) {
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// revoking a key for an unknown role returns ErrInvalidRole
	c.Assert(r.RevokeKey("foo", ""), DeepEquals, ErrInvalidRole{"foo"})

	// revoking a key which doesn't exist returns ErrKeyNotFound
	c.Assert(r.RevokeKey("root", "nonexistent"), DeepEquals, ErrKeyNotFound{"root", "nonexistent"})

	// generate keys
	genKey(c, r, "root")
	target1IDs := genKey(c, r, "targets")
	target2IDs := genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, NotNil)
	c.Assert(root.Roles, HasLen, 4)
	c.Assert(root.Keys, NotNil)
	rs.assertNumUniqueKeys(c, root, "root", 1)
	rs.assertNumUniqueKeys(c, root, "targets", 2)
	rs.assertNumUniqueKeys(c, root, "snapshot", 1)
	rs.assertNumUniqueKeys(c, root, "timestamp", 1)

	// revoke a key
	targetsRole, ok := root.Roles["targets"]
	if !ok {
		c.Fatal("missing targets role")
	}
	c.Assert(targetsRole.KeyIDs, HasLen, len(target1IDs)+len(target2IDs))
	id := targetsRole.KeyIDs[0]
	c.Assert(r.RevokeKey("targets", id), IsNil)

	// make sure all the other key ids were also revoked
	for _, id := range target1IDs {
		c.Assert(r.RevokeKey("targets", id), DeepEquals, ErrKeyNotFound{"targets", id})
	}

	// check root was updated
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, NotNil)
	c.Assert(root.Roles, HasLen, 4)
	c.Assert(root.Keys, NotNil)
	rs.assertNumUniqueKeys(c, root, "root", 1)
	rs.assertNumUniqueKeys(c, root, "targets", 1)
	rs.assertNumUniqueKeys(c, root, "snapshot", 1)
	rs.assertNumUniqueKeys(c, root, "timestamp", 1)
	targetsRole, ok = root.Roles["targets"]
	if !ok {
		c.Fatal("missing targets role")
	}
	c.Assert(targetsRole.KeyIDs, HasLen, 1)
	c.Assert(targetsRole.KeyIDs, DeepEquals, target2IDs)
}

func (rs *RepoSuite) TestRevokeKeyInMultipleRoles(c *C) {
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// generate keys. add a root key that is shared with the targets role
	rootSigner, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(r.AddVerificationKey("root", rootSigner.PublicData()), IsNil)
	sharedSigner, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	sharedIDs := sharedSigner.PublicData().IDs()
	c.Assert(r.AddVerificationKey("root", sharedSigner.PublicData()), IsNil)
	c.Assert(r.AddVerificationKey("targets", sharedSigner.PublicData()), IsNil)
	targetIDs := genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, NotNil)
	c.Assert(root.Roles, HasLen, 4)
	c.Assert(root.Keys, NotNil)
	rs.assertNumUniqueKeys(c, root, "root", 2)
	rs.assertNumUniqueKeys(c, root, "targets", 2)
	rs.assertNumUniqueKeys(c, root, "snapshot", 1)
	rs.assertNumUniqueKeys(c, root, "timestamp", 1)

	// revoke a key
	targetsRole, ok := root.Roles["targets"]
	if !ok {
		c.Fatal("missing targets role")
	}
	c.Assert(targetsRole.KeyIDs, HasLen, len(targetIDs)+len(sharedIDs))
	id := targetsRole.KeyIDs[0]
	c.Assert(r.RevokeKey("targets", id), IsNil)

	// make sure all the other key ids were also revoked
	for _, id := range sharedIDs {
		c.Assert(r.RevokeKey("targets", id), DeepEquals, ErrKeyNotFound{"targets", id})
	}

	// check root was updated
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, NotNil)
	c.Assert(root.Roles, HasLen, 4)
	c.Assert(root.Keys, NotNil)
	// the shared root/targets signer should still be present in root keys
	c.Assert(UniqueKeys(root)["root"], DeepEquals,
		[]*data.PublicKey{rootSigner.PublicData(), sharedSigner.PublicData()})
	rs.assertNumUniqueKeys(c, root, "root", 2)
	rs.assertNumUniqueKeys(c, root, "targets", 1)
	rs.assertNumUniqueKeys(c, root, "snapshot", 1)
	rs.assertNumUniqueKeys(c, root, "timestamp", 1)
	targetsRole, ok = root.Roles["targets"]
	if !ok {
		c.Fatal("missing targets role")
	}
	c.Assert(targetsRole.KeyIDs, HasLen, 1)
	c.Assert(targetsRole.KeyIDs, DeepEquals, targetIDs)
}

func (rs *RepoSuite) TestSign(c *C) {
	meta := map[string]json.RawMessage{"root.json": []byte(`{"signed":{},"signatures":[]}`)}
	local := MemoryStore(meta, nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// signing with no keys returns ErrInsufficientKeys
	c.Assert(r.Sign("root.json"), Equals, ErrInsufficientKeys{"root.json"})

	checkSigIDs := func(keyIDs ...string) {
		meta, err := local.GetMeta()
		c.Assert(err, IsNil)
		rootJSON, ok := meta["root.json"]
		if !ok {
			c.Fatal("missing root.json")
		}
		s := &data.Signed{}
		c.Assert(json.Unmarshal(rootJSON, s), IsNil)
		c.Assert(s.Signatures, HasLen, len(keyIDs))

		// Signatures may be in any order, so must sort key IDs before comparison.
		wantKeyIDs := append([]string{}, keyIDs...)
		sort.Strings(wantKeyIDs)

		gotKeyIDs := []string{}
		for _, sig := range s.Signatures {
			gotKeyIDs = append(gotKeyIDs, sig.KeyID)
		}
		sort.Strings(gotKeyIDs)

		c.Assert(wantKeyIDs, DeepEquals, gotKeyIDs)
	}

	// signing with an available key generates a signature
	signer, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(local.SaveSigner("root", signer), IsNil)
	c.Assert(r.Sign("root.json"), IsNil)
	checkSigIDs(signer.PublicData().IDs()...)

	// signing again does not generate a duplicate signature
	c.Assert(r.Sign("root.json"), IsNil)
	checkSigIDs(signer.PublicData().IDs()...)

	// signing with a new available key generates another signature
	newKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(local.SaveSigner("root", newKey), IsNil)
	c.Assert(r.Sign("root.json"), IsNil)
	checkSigIDs(append(signer.PublicData().IDs(), newKey.PublicData().IDs()...)...)
}

func (rs *RepoSuite) TestCommit(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo"), "bar.txt": []byte("bar")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// commit without root.json
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"root.json"})

	// commit without targets.json
	genKey(c, r, "root")
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"targets.json"})

	// commit without snapshot.json
	genKey(c, r, "targets")
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"snapshot.json"})

	// commit without timestamp.json
	genKey(c, r, "snapshot")
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"timestamp.json"})

	// commit with timestamp.json but no timestamp key
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), DeepEquals, ErrInsufficientSignatures{"timestamp.json", verify.ErrNoSignatures})

	// commit success
	genKey(c, r, "timestamp")
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// commit with an invalid root hash in snapshot.json due to new key creation
	genKey(c, r, "targets")
	c.Assert(r.Sign("targets.json"), IsNil)
	c.Assert(r.Commit(), DeepEquals, errors.New("tuf: invalid root.json in snapshot.json: wrong length, expected 1740 got 2046"))

	// commit with an invalid targets hash in snapshot.json
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.AddTarget("bar.txt", nil), IsNil)
	c.Assert(r.Commit(), DeepEquals, errors.New("tuf: invalid targets.json in snapshot.json: wrong length, expected 725 got 899"))

	// commit with an invalid timestamp
	c.Assert(r.Snapshot(), IsNil)
	err = r.Commit()
	c.Assert(err, NotNil)
	c.Assert(err.Error()[0:44], Equals, "tuf: invalid snapshot.json in timestamp.json")

	// commit with a role's threshold greater than number of keys
	root, err := r.root()
	c.Assert(err, IsNil)
	role, ok := root.Roles["timestamp"]
	if !ok {
		c.Fatal("missing timestamp role")
	}
	c.Assert(role.KeyIDs, HasLen, 1)
	c.Assert(role.Threshold, Equals, 1)
	c.Assert(r.RevokeKey("timestamp", role.KeyIDs[0]), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), DeepEquals, ErrNotEnoughKeys{"timestamp", 0, 1})
}

func (rs *RepoSuite) TestCommitVersions(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// on initial commit everything should be at version 1.
	rootVersion, err := r.RootVersion()
	c.Assert(err, IsNil)
	c.Assert(rootVersion, Equals, 1)

	targetsVersion, err := r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, 1)

	snapshotVersion, err := r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(snapshotVersion, Equals, 1)

	timestampVersion, err := r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, 1)

	// taking a snapshot should only increment snapshot and timestamp.
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	rootVersion, err = r.RootVersion()
	c.Assert(err, IsNil)
	c.Assert(rootVersion, Equals, 1)

	targetsVersion, err = r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, 1)

	snapshotVersion, err = r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(snapshotVersion, Equals, 2)

	timestampVersion, err = r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, 2)

	// rotating multiple keys should increment the root once.
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	rootVersion, err = r.RootVersion()
	c.Assert(err, IsNil)
	c.Assert(rootVersion, Equals, 2)

	targetsVersion, err = r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, 1)

	snapshotVersion, err = r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(snapshotVersion, Equals, 3)

	timestampVersion, err = r.TimestampVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, 3)
}

type tmpDir struct {
	path string
	c    *C
}

func newTmpDir(c *C) *tmpDir {
	return &tmpDir{path: c.MkDir(), c: c}
}

func (t *tmpDir) assertExists(path string) {
	if _, err := os.Stat(filepath.Join(t.path, path)); os.IsNotExist(err) {
		t.c.Fatalf("expected path to exist but it doesn't: %s", path)
	}
}

func (t *tmpDir) assertNotExist(path string) {
	if _, err := os.Stat(filepath.Join(t.path, path)); !os.IsNotExist(err) {
		t.c.Fatalf("expected path to not exist but it does: %s", path)
	}
}

func (t *tmpDir) assertHashedFilesExist(path string, hashes data.Hashes) {
	t.c.Assert(len(hashes) > 0, Equals, true)
	for _, path := range util.HashedPaths(path, hashes) {
		t.assertExists(path)
	}
}

func (t *tmpDir) assertHashedFilesNotExist(path string, hashes data.Hashes) {
	t.c.Assert(len(hashes) > 0, Equals, true)
	for _, path := range util.HashedPaths(path, hashes) {
		t.assertNotExist(path)
	}
}

func (t *tmpDir) assertVersionedFileExist(path string, version int) {
	t.assertExists(util.VersionedPath(path, version))
}

func (t *tmpDir) assertVersionedFileNotExist(path string, version int) {
	t.assertNotExist(util.VersionedPath(path, version))
}

func (t *tmpDir) assertEmpty(dir string) {
	path := filepath.Join(t.path, dir)
	f, err := os.Stat(path)
	if os.IsNotExist(err) {
		t.c.Fatalf("expected dir to exist but it doesn't: %s", dir)
	}
	t.c.Assert(err, IsNil)
	t.c.Assert(f.IsDir(), Equals, true)
	entries, err := ioutil.ReadDir(path)
	t.c.Assert(err, IsNil)
	// check that all (if any) entries are also empty
	for _, e := range entries {
		t.assertEmpty(filepath.Join(dir, e.Name()))
	}
}

func (t *tmpDir) assertFileContent(path, content string) {
	actual := t.readFile(path)
	t.c.Assert(string(actual), Equals, content)
}

func (t *tmpDir) stagedTargetPath(path string) string {
	return filepath.Join(t.path, "staged", "targets", path)
}

func (t *tmpDir) writeStagedTarget(path, data string) {
	path = t.stagedTargetPath(path)
	t.c.Assert(os.MkdirAll(filepath.Dir(path), 0755), IsNil)
	t.c.Assert(ioutil.WriteFile(path, []byte(data), 0644), IsNil)
}

func (t *tmpDir) readFile(path string) []byte {
	t.assertExists(path)
	data, err := ioutil.ReadFile(filepath.Join(t.path, path))
	t.c.Assert(err, IsNil)
	return data
}

func (rs *RepoSuite) TestCommitFileSystem(c *C) {
	tmp := newTmpDir(c)
	local := FileSystemStore(tmp.path, nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// don't use consistent snapshots to make the checks simpler
	c.Assert(r.Init(false), IsNil)

	// cleaning with nothing staged or committed should fail
	c.Assert(r.Clean(), Equals, ErrNewRepository)

	// generating keys should stage root.json and create repo dirs
	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	tmp.assertExists("staged/root.json")
	tmp.assertEmpty("repository")
	tmp.assertEmpty("staged/targets")

	// cleaning with nothing committed should fail
	c.Assert(r.Clean(), Equals, ErrNewRepository)

	// adding a non-existent file fails
	c.Assert(r.AddTarget("foo.txt", nil), Equals, ErrFileNotFound{tmp.stagedTargetPath("foo.txt")})
	tmp.assertEmpty("repository")

	// adding a file stages targets.json
	tmp.writeStagedTarget("foo.txt", "foo")
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	tmp.assertExists("staged/targets.json")
	tmp.assertEmpty("repository")
	t, err := r.targets()
	c.Assert(err, IsNil)
	c.Assert(t.Targets, HasLen, 1)
	if _, ok := t.Targets["foo.txt"]; !ok {
		c.Fatal("missing target file: foo.txt")
	}

	// Snapshot() stages snapshot.json
	c.Assert(r.Snapshot(), IsNil)
	tmp.assertExists("staged/snapshot.json")
	tmp.assertEmpty("repository")

	// Timestamp() stages timestamp.json
	c.Assert(r.Timestamp(), IsNil)
	tmp.assertExists("staged/timestamp.json")
	tmp.assertEmpty("repository")

	// committing moves files from staged -> repository
	c.Assert(r.Commit(), IsNil)
	tmp.assertExists("repository/root.json")
	tmp.assertExists("repository/targets.json")
	tmp.assertExists("repository/snapshot.json")
	tmp.assertExists("repository/timestamp.json")
	tmp.assertFileContent("repository/targets/foo.txt", "foo")
	tmp.assertEmpty("staged/targets")
	tmp.assertEmpty("staged")

	// adding and committing another file moves it into repository/targets
	tmp.writeStagedTarget("path/to/bar.txt", "bar")
	c.Assert(r.AddTarget("path/to/bar.txt", nil), IsNil)
	tmp.assertExists("staged/targets.json")
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	tmp.assertFileContent("repository/targets/foo.txt", "foo")
	tmp.assertFileContent("repository/targets/path/to/bar.txt", "bar")
	tmp.assertEmpty("staged/targets")
	tmp.assertEmpty("staged")

	// removing and committing a file removes it from repository/targets
	c.Assert(r.RemoveTarget("foo.txt"), IsNil)
	tmp.assertExists("staged/targets.json")
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	tmp.assertNotExist("repository/targets/foo.txt")
	tmp.assertFileContent("repository/targets/path/to/bar.txt", "bar")
	tmp.assertEmpty("staged/targets")
	tmp.assertEmpty("staged")
}

func (rs *RepoSuite) TestCommitFileSystemWithNewRepositories(c *C) {
	tmp := newTmpDir(c)

	newRepo := func() *Repo {
		local := FileSystemStore(tmp.path, nil)
		r, err := NewRepo(local)
		c.Assert(err, IsNil)
		return r
	}

	genKey(c, newRepo(), "root")
	genKey(c, newRepo(), "targets")
	genKey(c, newRepo(), "snapshot")
	genKey(c, newRepo(), "timestamp")

	tmp.writeStagedTarget("foo.txt", "foo")
	c.Assert(newRepo().AddTarget("foo.txt", nil), IsNil)
	c.Assert(newRepo().Snapshot(), IsNil)
	c.Assert(newRepo().Timestamp(), IsNil)
	c.Assert(newRepo().Commit(), IsNil)
}

func (rs *RepoSuite) TestConsistentSnapshot(c *C) {
	tmp := newTmpDir(c)
	local := FileSystemStore(tmp.path, nil)
	r, err := NewRepo(local, "sha512", "sha256")
	c.Assert(err, IsNil)

	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	tmp.writeStagedTarget("foo.txt", "foo")
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	tmp.writeStagedTarget("dir/bar.txt", "bar")
	c.Assert(r.AddTarget("dir/bar.txt", nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	versions, err := r.fileVersions()
	c.Assert(err, IsNil)
	c.Assert(versions["root.json"], Equals, 1)
	c.Assert(versions["targets.json"], Equals, 1)
	c.Assert(versions["snapshot.json"], Equals, 1)

	hashes, err := r.fileHashes()
	c.Assert(err, IsNil)

	// root.json, targets.json and snapshot.json should exist at both versioned and unversioned paths
	for _, path := range []string{"root.json", "targets.json", "snapshot.json"} {
		repoPath := filepath.Join("repository", path)
		tmp.assertHashedFilesNotExist(repoPath, hashes[path])
		tmp.assertVersionedFileExist(repoPath, versions[path])
		tmp.assertExists(repoPath)
	}

	// target files should exist at hashed but not unhashed paths
	for _, path := range []string{"targets/foo.txt", "targets/dir/bar.txt"} {
		repoPath := filepath.Join("repository", path)
		tmp.assertHashedFilesExist(repoPath, hashes[path])
		tmp.assertNotExist(repoPath)
	}

	// timestamp.json should exist at an unversioned and unhashed path (it doesn't have a hash)
	c.Assert(hashes["repository/timestamp.json"], IsNil)
	tmp.assertVersionedFileNotExist("repository/timestamp.json", versions["repository/timestamp.json"])
	tmp.assertExists("repository/timestamp.json")

	// removing a file should remove the hashed files
	c.Assert(r.RemoveTarget("foo.txt"), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	versions, err = r.fileVersions()
	c.Assert(err, IsNil)
	c.Assert(versions["root.json"], Equals, 1)
	c.Assert(versions["targets.json"], Equals, 2)
	c.Assert(versions["snapshot.json"], Equals, 2)

	// Save the old hashes for foo.txt to make sure we can assert it doesn't exist later.
	fooHashes := hashes["targets/foo.txt"]
	hashes, err = r.fileHashes()
	c.Assert(err, IsNil)

	// root.json, targets.json and snapshot.json should exist at both versioned and unversioned paths
	for _, path := range []string{"root.json", "targets.json", "snapshot.json"} {
		repoPath := filepath.Join("repository", path)
		tmp.assertHashedFilesNotExist(repoPath, hashes[path])
		tmp.assertVersionedFileExist(repoPath, versions[path])
		tmp.assertExists(repoPath)
	}

	tmp.assertHashedFilesNotExist("repository/targets/foo.txt", fooHashes)
	tmp.assertNotExist("repository/targets/foo.txt")

	// targets should be returned by new repo
	newRepo, err := NewRepo(local, "sha512", "sha256")
	c.Assert(err, IsNil)
	t, err := newRepo.targets()
	c.Assert(err, IsNil)
	c.Assert(t.Targets, HasLen, 1)
	if _, ok := t.Targets["dir/bar.txt"]; !ok {
		c.Fatal("missing targets file: dir/bar.txt")
	}
}

func (rs *RepoSuite) TestExpiresAndVersion(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	past := time.Now().Add(-1 * time.Second)
	_, genKeyErr := r.GenKeyWithExpires("root", past)
	for _, err := range []error{
		genKeyErr,
		r.AddTargetWithExpires("foo.txt", nil, past),
		r.RemoveTargetWithExpires("foo.txt", past),
		r.SnapshotWithExpires(past),
		r.TimestampWithExpires(past),
	} {
		c.Assert(err, Equals, ErrInvalidExpires{past})
	}

	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	c.Assert(r.AddTargets([]string{}, nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Version, Equals, 1)

	expires := time.Now().Add(24 * time.Hour)
	_, err = r.GenKeyWithExpires("root", expires)
	c.Assert(err, IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Expires.Unix(), DeepEquals, expires.Round(time.Second).Unix())
	c.Assert(root.Version, Equals, 2)

	expires = time.Now().Add(12 * time.Hour)
	role, ok := root.Roles["root"]
	if !ok {
		c.Fatal("missing root role")
	}
	c.Assert(role.KeyIDs, HasLen, 2)
	c.Assert(r.RevokeKeyWithExpires("root", role.KeyIDs[0], expires), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Expires.Unix(), DeepEquals, expires.Round(time.Second).Unix())
	c.Assert(root.Version, Equals, 3)

	expires = time.Now().Add(6 * time.Hour)
	c.Assert(r.AddTargetWithExpires("foo.txt", nil, expires), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	targets, err := r.targets()
	c.Assert(err, IsNil)
	c.Assert(targets.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(targets.Version, Equals, 2)

	expires = time.Now().Add(2 * time.Hour)
	c.Assert(r.RemoveTargetWithExpires("foo.txt", expires), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	targets, err = r.targets()
	c.Assert(err, IsNil)
	c.Assert(targets.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(targets.Version, Equals, 3)

	expires = time.Now().Add(time.Hour)
	c.Assert(r.SnapshotWithExpires(expires), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	snapshot, err := r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(snapshot.Version, Equals, 6)

	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta["root.json"].Version, Equals, root.Version)
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, targets.Version)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Version, Equals, 7)

	expires = time.Now().Add(10 * time.Minute)
	c.Assert(r.TimestampWithExpires(expires), IsNil)
	c.Assert(r.Commit(), IsNil)
	timestamp, err := r.timestamp()
	c.Assert(err, IsNil)
	c.Assert(timestamp.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(timestamp.Version, Equals, 8)

	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	timestamp, err = r.timestamp()
	c.Assert(err, IsNil)
	c.Assert(timestamp.Version, Equals, 9)
	c.Assert(timestamp.Meta["snapshot.json"].Version, Equals, snapshot.Version)
}

func (rs *RepoSuite) TestHashAlgorithm(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	type hashTest struct {
		args     []string
		expected []string
	}
	for _, test := range []hashTest{
		{args: []string{}, expected: []string{"sha512"}},
		{args: []string{"sha256"}},
		{args: []string{"sha512", "sha256"}},
	} {
		// generate metadata with specific hash functions
		r, err := NewRepo(local, test.args...)
		c.Assert(err, IsNil)
		genKey(c, r, "root")
		genKey(c, r, "targets")
		genKey(c, r, "snapshot")
		c.Assert(r.AddTarget("foo.txt", nil), IsNil)
		c.Assert(r.Snapshot(), IsNil)
		c.Assert(r.Timestamp(), IsNil)

		// check metadata has correct hash functions
		if test.expected == nil {
			test.expected = test.args
		}
		targets, err := r.targets()
		c.Assert(err, IsNil)
		snapshot, err := r.snapshot()
		c.Assert(err, IsNil)
		timestamp, err := r.timestamp()
		c.Assert(err, IsNil)
		for name, file := range map[string]data.FileMeta{
			"foo.txt":       targets.Targets["foo.txt"].FileMeta,
			"root.json":     snapshot.Meta["root.json"].FileMeta,
			"targets.json":  snapshot.Meta["targets.json"].FileMeta,
			"snapshot.json": timestamp.Meta["snapshot.json"].FileMeta,
		} {
			for _, hashAlgorithm := range test.expected {
				if _, ok := file.Hashes[hashAlgorithm]; !ok {
					c.Fatalf("expected %s hash to contain hash func %s, got %s", name, hashAlgorithm, file.HashAlgorithms())
				}
			}
		}
	}
}

func (rs *RepoSuite) TestKeyPersistence(c *C) {
	tmp := newTmpDir(c)
	oldPassphrase := []byte("old_s3cr3t")
	newPassphrase := []byte("new_s3cr3t")
	// returnNewPassphrase is used to force the passphrase function to return the new passphrase when called by the SaveSigner() method
	returnNewPassphrase := false
	// passphrase mock function
	testPassphraseFunc := func(a string, b, change bool) ([]byte, error) {
		if change || returnNewPassphrase {
			return newPassphrase, nil
		}
		return oldPassphrase, nil
	}
	store := FileSystemStore(tmp.path, testPassphraseFunc)

	assertKeys := func(role string, enc bool, expected []*data.PrivateKey) {
		keysJSON := tmp.readFile("keys/" + role + ".json")
		pk := &persistedKeys{}
		c.Assert(json.Unmarshal(keysJSON, pk), IsNil)

		// check the persisted keys are correct
		var actual []*data.PrivateKey
		pass := oldPassphrase
		if enc {
			c.Assert(pk.Encrypted, Equals, true)
			if returnNewPassphrase {
				pass = newPassphrase
			}
			decrypted, err := encrypted.Decrypt(pk.Data, pass)
			c.Assert(err, IsNil)
			c.Assert(json.Unmarshal(decrypted, &actual), IsNil)
		} else {
			c.Assert(pk.Encrypted, Equals, false)
			c.Assert(json.Unmarshal(pk.Data, &actual), IsNil)
		}

		// Compare slices of unique elements disregarding order.
		c.Assert(actual, HasLen, len(expected))
		for _, gotKey := range actual {
			expectedNumMatches := 0
			for _, x := range actual {
				if reflect.DeepEqual(gotKey, x) {
					expectedNumMatches++
				}
			}

			numMatches := 0
			for _, wantKey := range expected {
				wantCanon, err := cjson.EncodeCanonical(wantKey)
				c.Assert(err, IsNil)

				gotCanon, err := cjson.EncodeCanonical(gotKey)
				c.Assert(err, IsNil)

				if string(wantCanon) == string(gotCanon) {
					numMatches++
				}
			}

			c.Assert(numMatches, Equals, expectedNumMatches, Commentf("actual: %+v, expected: %+v", actual, expected))
		}

		// check GetKeys is correct
		signers, err := store.GetSigners(role)
		c.Assert(err, IsNil)

		// Compare slices of unique elements disregarding order.
		c.Assert(signers, HasLen, len(expected))
		for _, s := range signers {
			expectedNumMatches := 0
			for _, x := range signers {
				if reflect.DeepEqual(s, x) {
					expectedNumMatches++
				}
			}

			numMatches := 0
			for _, e := range expected {
				v, err := keys.GetSigner(e)
				c.Assert(err, IsNil)

				if reflect.DeepEqual(s.PublicData().IDs(), v.PublicData().IDs()) {
					numMatches++
				}
			}

			c.Assert(numMatches, Equals, expectedNumMatches, Commentf("signers: %+v, expected: %+v", signers, expected))
		}
	}

	// save a key and check it gets encrypted
	signer, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	privateKey, err := signer.MarshalPrivateKey()
	c.Assert(err, IsNil)
	c.Assert(store.SaveSigner("root", signer), IsNil)
	assertKeys("root", true, []*data.PrivateKey{privateKey})

	// save another key and check it gets added to the existing keys
	newKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	newPrivateKey, err := newKey.MarshalPrivateKey()
	c.Assert(err, IsNil)
	c.Assert(store.SaveSigner("root", newKey), IsNil)
	assertKeys("root", true, []*data.PrivateKey{privateKey, newPrivateKey})

	// check saving a key to an encrypted file without a passphrase fails
	insecureStore := FileSystemStore(tmp.path, nil)
	signer, err = keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(insecureStore.SaveSigner("root", signer), Equals, ErrPassphraseRequired{"root"})

	// save a key to an insecure store and check it is not encrypted
	signer, err = keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	privateKey, err = signer.MarshalPrivateKey()
	c.Assert(err, IsNil)
	c.Assert(insecureStore.SaveSigner("targets", signer), IsNil)
	assertKeys("targets", false, []*data.PrivateKey{privateKey})

	// Test changing the passphrase
	// 1. Create a secure store with a passphrase (create new object and temp folder so we discard any previous state)
	tmp = newTmpDir(c)
	store = FileSystemStore(tmp.path, testPassphraseFunc)

	// 2. Test changing the passphrase when the keys file does not exist - should FAIL
	c.Assert(store.(PassphraseChanger).ChangePassphrase("root"), NotNil)

	// 3. Generate a new key
	signer, err = keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	privateKey, err = signer.MarshalPrivateKey()
	c.Assert(err, IsNil)
	c.Assert(store.SaveSigner("root", signer), IsNil)

	// 4. Verify the key file can be decrypted using the original passphrase - should SUCCEED
	assertKeys("root", true, []*data.PrivateKey{privateKey})

	// 5. Change the passphrase (our mock passphrase function is called with change=true thus returning the newPassphrase value)
	c.Assert(store.(PassphraseChanger).ChangePassphrase("root"), IsNil)

	// 6. Try to add a key and implicitly decrypt the keys file using the OLD passphrase - should FAIL
	newKey, err = keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	_, err = newKey.MarshalPrivateKey()
	c.Assert(err, IsNil)
	c.Assert(store.SaveSigner("root", newKey), NotNil)

	// 7. Try to add a key and implicitly decrypt the keys using the NEW passphrase - should SUCCEED
	returnNewPassphrase = true
	newKey, err = keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	newPrivateKey, err = newKey.MarshalPrivateKey()
	c.Assert(err, IsNil)
	c.Assert(store.SaveSigner("root", newKey), IsNil)

	// 8. Verify again that the key entries are what we expect after decrypting them using the NEW passphrase
	assertKeys("root", true, []*data.PrivateKey{privateKey, newPrivateKey})
}

func (rs *RepoSuite) TestManageMultipleTargets(c *C) {
	tmp := newTmpDir(c)
	local := FileSystemStore(tmp.path, nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)
	// don't use consistent snapshots to make the checks simpler
	c.Assert(r.Init(false), IsNil)
	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	assertRepoTargets := func(paths ...string) {
		t, err := r.targets()
		c.Assert(err, IsNil)
		for _, path := range paths {
			if _, ok := t.Targets[path]; !ok {
				c.Fatalf("missing target file: %s", path)
			}
		}
	}

	// adding and committing multiple files moves correct targets from staged -> repository
	tmp.writeStagedTarget("foo.txt", "foo")
	tmp.writeStagedTarget("bar.txt", "bar")
	c.Assert(r.AddTargets([]string{"foo.txt", "bar.txt"}, nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	assertRepoTargets("foo.txt", "bar.txt")
	tmp.assertExists("repository/targets/foo.txt")
	tmp.assertExists("repository/targets/bar.txt")

	// adding all targets moves them all from staged -> repository
	count := 10
	files := make([]string, count)
	for i := 0; i < count; i++ {
		files[i] = fmt.Sprintf("file%d.txt", i)
		tmp.writeStagedTarget(files[i], "data")
	}
	c.Assert(r.AddTargets(nil, nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	tmp.assertExists("repository/targets/foo.txt")
	tmp.assertExists("repository/targets/bar.txt")
	assertRepoTargets(files...)
	for _, file := range files {
		tmp.assertExists("repository/targets/" + file)
	}
	tmp.assertEmpty("staged/targets")
	tmp.assertEmpty("staged")

	// removing all targets removes them from the repository and targets.json
	c.Assert(r.RemoveTargets(nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	tmp.assertEmpty("repository/targets")
	t, err := r.targets()
	c.Assert(err, IsNil)
	c.Assert(t.Targets, HasLen, 0)
}

func (rs *RepoSuite) TestCustomTargetMetadata(c *C) {
	files := map[string][]byte{
		"foo.txt": []byte("foo"),
		"bar.txt": []byte("bar"),
		"baz.txt": []byte("baz"),
	}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	custom := json.RawMessage(`{"foo":"bar"}`)
	assertCustomMeta := func(file string, custom *json.RawMessage) {
		t, err := r.targets()
		c.Assert(err, IsNil)
		target, ok := t.Targets[file]
		if !ok {
			c.Fatalf("missing target file: %s", file)
		}
		c.Assert(target.Custom, DeepEquals, custom)
	}

	// check custom metadata gets added to the target
	c.Assert(r.AddTarget("foo.txt", custom), IsNil)
	assertCustomMeta("foo.txt", &custom)

	// check adding bar.txt with no metadata doesn't affect foo.txt
	c.Assert(r.AddTarget("bar.txt", nil), IsNil)
	assertCustomMeta("bar.txt", nil)
	assertCustomMeta("foo.txt", &custom)

	// check adding all files with no metadata doesn't reset existing metadata
	c.Assert(r.AddTargets(nil, nil), IsNil)
	assertCustomMeta("baz.txt", nil)
	assertCustomMeta("bar.txt", nil)
	assertCustomMeta("foo.txt", &custom)
}

func (rs *RepoSuite) TestUnknownKeyIDs(c *C) {
	// generate a repo
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	// add a new key to the root metadata with an unknown key id.
	signer, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)

	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Version, Equals, 1)

	root.Keys["unknown-key-id"] = signer.PublicData()
	r.setMeta("root.json", root)

	// commit the metadata to the store.
	c.Assert(r.AddTargets([]string{}, nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// validate that the unknown key id wasn't stripped when written to the
	// store.
	meta, err := local.GetMeta()
	c.Assert(err, IsNil)

	rootJSON, ok := meta["root.json"]
	c.Assert(ok, Equals, true)

	var signedRoot struct {
		Signed     data.Root        `json:"signed"`
		Signatures []data.Signature `json:"signatures"`
	}
	c.Assert(json.Unmarshal(rootJSON, &signedRoot), IsNil)
	c.Assert(signedRoot.Signed.Version, Equals, 1)

	unknownKey, ok := signedRoot.Signed.Keys["unknown-key-id"]
	c.Assert(ok, Equals, true)
	c.Assert(unknownKey, DeepEquals, signer.PublicData())

	// a new root should preserve the unknown key id.
	root, err = r.root()
	c.Assert(root, NotNil)
	c.Assert(err, IsNil)

	genKey(c, r, "timestamp")
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	meta, err = local.GetMeta()
	c.Assert(err, IsNil)

	rootJSON, ok = meta["root.json"]
	c.Assert(ok, Equals, true)

	c.Assert(json.Unmarshal(rootJSON, &signedRoot), IsNil)
	c.Assert(signedRoot.Signed.Version, Equals, 2)

	unknownKey, ok = signedRoot.Signed.Keys["unknown-key-id"]
	c.Assert(ok, Equals, true)
	c.Assert(unknownKey, DeepEquals, signer.PublicData())
}

func (rs *RepoSuite) TestThreshold(c *C) {
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// Add one key to each role
	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	t, err := r.GetThreshold("root")
	c.Assert(err, IsNil)
	c.Assert(t, Equals, 1)

	// commit the metadata to the store.
	c.Assert(r.AddTargets([]string{}, nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// Set a new threshold. Commit without threshold keys
	c.Assert(r.SetThreshold("root", 2), IsNil)
	t, err = r.GetThreshold("root")
	c.Assert(err, IsNil)
	c.Assert(t, Equals, 2)
	c.Assert(r.Commit(), DeepEquals, ErrNotEnoughKeys{"root", 1, 2})

	// Add a second root key and try again
	genKey(c, r, "root")
	c.Assert(r.Sign("root.json"), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// Check versions updated
	rootVersion, err := r.RootVersion()
	c.Assert(err, IsNil)
	c.Assert(rootVersion, Equals, 2)

	targetsVersion, err := r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, 1)

	snapshotVersion, err := r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(snapshotVersion, Equals, 2)

	timestampVersion, err := r.TimestampVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, 2)
}

func (rs *RepoSuite) TestAddOrUpdateSignatures(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// don't use consistent snapshots to make the checks simpler
	c.Assert(r.Init(false), IsNil)

	// generate root key offline and add as a verification key
	rootKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(r.AddVerificationKey("root", rootKey.PublicData()), IsNil)
	targetsKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(r.AddVerificationKey("targets", targetsKey.PublicData()), IsNil)
	snapshotKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(r.AddVerificationKey("snapshot", snapshotKey.PublicData()), IsNil)
	timestampKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(r.AddVerificationKey("timestamp", timestampKey.PublicData()), IsNil)

	// generate signatures externally and append
	rootMeta, err := r.SignedMeta("root.json")
	c.Assert(err, IsNil)
	rootSig, err := rootKey.SignMessage(rootMeta.Signed)
	c.Assert(err, IsNil)
	for _, id := range rootKey.PublicData().IDs() {
		c.Assert(r.AddOrUpdateSignature("root.json", data.Signature{
			KeyID:     id,
			Signature: rootSig}), IsNil)
	}

	// add targets and sign
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	targetsMeta, err := r.SignedMeta("targets.json")
	c.Assert(err, IsNil)
	targetsSig, err := targetsKey.SignMessage(targetsMeta.Signed)
	c.Assert(err, IsNil)
	for _, id := range targetsKey.PublicData().IDs() {
		r.AddOrUpdateSignature("targets.json", data.Signature{
			KeyID:     id,
			Signature: targetsSig})
	}

	// snapshot and timestamp
	c.Assert(r.Snapshot(), IsNil)
	snapshotMeta, err := r.SignedMeta("snapshot.json")
	c.Assert(err, IsNil)
	snapshotSig, err := snapshotKey.SignMessage(snapshotMeta.Signed)
	c.Assert(err, IsNil)
	for _, id := range snapshotKey.PublicData().IDs() {
		r.AddOrUpdateSignature("snapshot.json", data.Signature{
			KeyID:     id,
			Signature: snapshotSig})
	}

	c.Assert(r.Timestamp(), IsNil)
	timestampMeta, err := r.SignedMeta("timestamp.json")
	c.Assert(err, IsNil)
	timestampSig, err := timestampKey.SignMessage(timestampMeta.Signed)
	c.Assert(err, IsNil)
	for _, id := range timestampKey.PublicData().IDs() {
		r.AddOrUpdateSignature("timestamp.json", data.Signature{
			KeyID:     id,
			Signature: timestampSig})
	}

	// commit successfully!
	c.Assert(r.Commit(), IsNil)
}

func (rs *RepoSuite) TestBadAddOrUpdateSignatures(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// don't use consistent snapshots to make the checks simpler
	c.Assert(r.Init(false), IsNil)

	// generate root key offline and add as a verification key
	rootKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(r.AddVerificationKey("root", rootKey.PublicData()), IsNil)
	targetsKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(r.AddVerificationKey("targets", targetsKey.PublicData()), IsNil)
	snapshotKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(r.AddVerificationKey("snapshot", snapshotKey.PublicData()), IsNil)
	timestampKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(r.AddVerificationKey("timestamp", timestampKey.PublicData()), IsNil)

	// add a signature with a bad role
	rootMeta, err := r.SignedMeta("root.json")
	c.Assert(err, IsNil)
	rootSig, err := rootKey.Sign(rand.Reader, rootMeta.Signed, crypto.Hash(0))
	c.Assert(err, IsNil)
	for _, id := range rootKey.PublicData().IDs() {
		c.Assert(r.AddOrUpdateSignature("invalid_root.json", data.Signature{
			KeyID:     id,
			Signature: rootSig}), Equals, ErrInvalidRole{"invalid_root"})
	}

	// add a root signature with an key ID that is for the targets role
	for _, id := range targetsKey.PublicData().IDs() {
		c.Assert(r.AddOrUpdateSignature("root.json", data.Signature{
			KeyID:     id,
			Signature: rootSig}), Equals, verify.ErrInvalidKey)
	}

	// attempt to add a bad signature to root
	badSig, err := rootKey.Sign(rand.Reader, []byte(""), crypto.Hash(0))
	c.Assert(err, IsNil)
	for _, id := range rootKey.PublicData().IDs() {
		c.Assert(r.AddOrUpdateSignature("root.json", data.Signature{
			KeyID:     id,
			Signature: badSig}), Equals, verify.ErrInvalid)
	}

	// add the correct root signature
	for _, id := range rootKey.PublicData().IDs() {
		c.Assert(r.AddOrUpdateSignature("root.json", data.Signature{
			KeyID:     id,
			Signature: rootSig}), IsNil)
	}
	checkSigIDs := func(role string) {
		s, err := r.SignedMeta(role)
		c.Assert(err, IsNil)
		db, err := r.db()
		c.Assert(err, IsNil)
		// keys is a map of key IDs.
		keys := db.GetRole(strings.TrimSuffix(role, ".json")).KeyIDs
		c.Assert(s.Signatures, HasLen, len(keys))
		// If the lengths are equal, and each signature key ID appears
		// in the role keys, they Sig IDs are equal to keyIDs.
		for _, sig := range s.Signatures {
			if _, ok := keys[sig.KeyID]; !ok {
				c.Fatal("missing key ID in signatures")
			}
		}
	}
	checkSigIDs("root.json")

	// re-adding should not duplicate. this is checked by verifying
	// signature key IDs match with the map of role key IDs.
	for _, id := range rootKey.PublicData().IDs() {
		c.Assert(r.AddOrUpdateSignature("root.json", data.Signature{
			KeyID:     id,
			Signature: rootSig}), IsNil)
	}
	checkSigIDs("root.json")
}

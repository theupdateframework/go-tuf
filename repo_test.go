package tuf

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/encrypted"
	"github.com/theupdateframework/go-tuf/internal/sets"
	"github.com/theupdateframework/go-tuf/pkg/keys"
	"github.com/theupdateframework/go-tuf/pkg/targets"
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
	c.Assert(root.Version, Equals, int64(1))
	c.Assert(root.Keys, NotNil)
	c.Assert(root.Keys, HasLen, 0)

	targets, err := r.topLevelTargets()
	c.Assert(err, IsNil)
	c.Assert(targets.Type, Equals, "targets")
	c.Assert(targets.Version, Equals, int64(1))
	c.Assert(targets.Targets, NotNil)
	c.Assert(targets.Targets, HasLen, 0)

	snapshot, err := r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Type, Equals, "snapshot")
	c.Assert(snapshot.Version, Equals, int64(1))
	c.Assert(snapshot.Meta, NotNil)
	c.Assert(snapshot.Meta, HasLen, 0)

	timestamp, err := r.timestamp()
	c.Assert(err, IsNil)
	c.Assert(timestamp.Type, Equals, "timestamp")
	c.Assert(timestamp.Version, Equals, int64(1))
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

	// Add a target.
	generateAndAddPrivateKey(c, r, "targets")
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)

	// Init() fails if targets have been added
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
	c.Assert(err, Equals, ErrInvalidRole{"foo", "only support adding keys for top-level roles"})

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
	db, err := r.topLevelKeysDB()
	c.Assert(err, IsNil)
	for _, keyID := range ids {
		rootKey, err := db.GetVerifier(keyID)
		c.Assert(err, IsNil)
		c.Assert(rootKey.MarshalPublicKey().IDs(), DeepEquals, ids)
		role := db.GetRole("root")
		c.Assert(role.KeyIDs, DeepEquals, sets.StringSliceToSet(ids))

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
	db, err = r.topLevelKeysDB()
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
	c.Assert(err, Equals, ErrInvalidRole{"foo", "only support adding keys for top-level roles"})

	// add a root key
	ids := addPrivateKey(c, r, "root", signer)

	// check root metadata is correct
	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Version, Equals, int64(1))
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
	db, err := r.topLevelKeysDB()
	c.Assert(err, IsNil)
	for _, keyID := range ids {
		rootKey, err := db.GetVerifier(keyID)
		c.Assert(err, IsNil)
		c.Assert(rootKey.MarshalPublicKey().IDs(), DeepEquals, ids)
		role := db.GetRole("root")
		c.Assert(role.KeyIDs, DeepEquals, sets.StringSliceToSet(ids))

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
	db, err = r.topLevelKeysDB()
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
	if r.local.FileIsStaged("root.json") {
		c.Fatal("root should not be marked dirty")
	}
}

func (rs *RepoSuite) TestRevokeKey(c *C) {
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// revoking a key for an unknown role returns ErrInvalidRole
	c.Assert(r.RevokeKey("foo", ""), DeepEquals, ErrInvalidRole{"foo", "only revocations for top-level roles supported"})

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

	c.Assert(r.Sign("foo.json"), Equals, ErrMissingMetadata{"foo.json"})

	// signing with no keys returns ErrNoKeys
	c.Assert(r.Sign("root.json"), Equals, ErrNoKeys{"root.json"})

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

	// attempt to sign missing metadata
	c.Assert(r.Sign("targets.json"), Equals, ErrMissingMetadata{"targets.json"})
}

func (rs *RepoSuite) TestStatus(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	c.Assert(r.SnapshotWithExpires(time.Now().Add(24*time.Hour)), IsNil)
	c.Assert(r.TimestampWithExpires(time.Now().Add(1*time.Hour)), IsNil)
	c.Assert(r.Commit(), IsNil)

	expires := time.Now().Add(2 * time.Hour)
	c.Assert(r.CheckRoleUnexpired("timestamp", expires), ErrorMatches, "role expired on.*")
	c.Assert(r.CheckRoleUnexpired("snapshot", expires), IsNil)
	c.Assert(r.CheckRoleUnexpired("targets", expires), IsNil)
	c.Assert(r.CheckRoleUnexpired("root", expires), IsNil)
}

func (rs *RepoSuite) TestCommit(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo"), "bar.txt": []byte("bar")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// commit without root.json
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"root.json"})

	// Init should create targets.json, but not signed yet
	r.Init(false)
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"snapshot.json"})

	genKey(c, r, "root")

	// commit without snapshot.json
	genKey(c, r, "targets")
	c.Assert(r.Sign("targets.json"), IsNil)
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
	c.Assert(r.Commit(), DeepEquals, errors.New("tuf: invalid targets.json in snapshot.json: wrong length, expected 338 got 552"))

	// commit with an invalid targets hash in snapshot.json
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.AddTarget("bar.txt", nil), IsNil)
	c.Assert(r.Commit(), DeepEquals, errors.New("tuf: invalid targets.json in snapshot.json: wrong length, expected 552 got 725"))

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
	c.Assert(rootVersion, Equals, int64(1))

	targetsVersion, err := r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, int64(1))

	snapshotVersion, err := r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(snapshotVersion, Equals, int64(1))

	timestampVersion, err := r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, int64(1))

	// taking a snapshot should only increment snapshot and timestamp.
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	rootVersion, err = r.RootVersion()
	c.Assert(err, IsNil)
	c.Assert(rootVersion, Equals, int64(1))

	targetsVersion, err = r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, int64(1))

	snapshotVersion, err = r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(snapshotVersion, Equals, int64(2))

	timestampVersion, err = r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, int64(2))

	// rotating multiple keys should increment the root once.
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	rootVersion, err = r.RootVersion()
	c.Assert(err, IsNil)
	c.Assert(rootVersion, Equals, int64(2))

	targetsVersion, err = r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, int64(1))

	snapshotVersion, err = r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(snapshotVersion, Equals, int64(3))

	timestampVersion, err = r.TimestampVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, int64(3))
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
	for _, path := range util.HashedPaths(path, hashes) {
		t.assertNotExist(path)
	}
}

func (t *tmpDir) assertVersionedFileExist(path string, version int64) {
	t.assertExists(util.VersionedPath(path, version))
}

func (t *tmpDir) assertVersionedFileNotExist(path string, version int64) {
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

	entries, err := os.ReadDir(path)
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
	t.c.Assert(os.WriteFile(path, []byte(data), 0644), IsNil)
}

func (t *tmpDir) readFile(path string) []byte {
	t.assertExists(path)
	data, err := os.ReadFile(filepath.Join(t.path, path))
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
	t, err := r.topLevelTargets()
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
	c.Assert(versions["root.json"], Equals, int64(1))
	c.Assert(versions["targets.json"], Equals, int64(1))
	c.Assert(versions["snapshot.json"], Equals, int64(1))

	hashes, err := r.fileHashes()
	c.Assert(err, IsNil)

	// root.json, targets.json and snapshot.json should exist at both versioned and unversioned paths
	for _, meta := range []string{"root.json", "targets.json", "snapshot.json"} {
		repoPath := path.Join("repository", meta)
		if meta != "root.json" {
			c.Assert(len(hashes[meta]) > 0, Equals, true)
		}
		tmp.assertHashedFilesNotExist(repoPath, hashes[meta])
		tmp.assertVersionedFileExist(repoPath, versions[meta])
		tmp.assertExists(repoPath)
	}

	// target files should exist at hashed but not unhashed paths
	for _, target := range []string{"targets/foo.txt", "targets/dir/bar.txt"} {
		repoPath := path.Join("repository", target)
		tmp.assertHashedFilesExist(repoPath, hashes[target])
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
	c.Assert(versions["root.json"], Equals, int64(1))
	c.Assert(versions["targets.json"], Equals, int64(2))
	c.Assert(versions["snapshot.json"], Equals, int64(2))

	// Save the old hashes for foo.txt to make sure we can assert it doesn't exist later.
	fooHashes := hashes["targets/foo.txt"]
	hashes, err = r.fileHashes()
	c.Assert(err, IsNil)

	// root.json, targets.json and snapshot.json should exist at both versioned and unversioned paths
	for _, meta := range []string{"root.json", "targets.json", "snapshot.json"} {
		repoPath := path.Join("repository", meta)
		if meta != "root.json" {
			c.Assert(len(hashes[meta]) > 0, Equals, true)
		}
		tmp.assertHashedFilesNotExist(repoPath, hashes[meta])
		tmp.assertVersionedFileExist(repoPath, versions[meta])
		tmp.assertExists(repoPath)
	}

	tmp.assertHashedFilesNotExist("repository/targets/foo.txt", fooHashes)
	tmp.assertNotExist("repository/targets/foo.txt")

	// targets should be returned by new repo
	newRepo, err := NewRepo(local, "sha512", "sha256")
	c.Assert(err, IsNil)
	t, err := newRepo.topLevelTargets()
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
	c.Assert(root.Version, Equals, int64(1))

	expires := time.Now().Add(24 * time.Hour)
	_, err = r.GenKeyWithExpires("root", expires)
	c.Assert(err, IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Expires.Unix(), DeepEquals, expires.Round(time.Second).Unix())
	c.Assert(root.Version, Equals, int64(2))

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
	c.Assert(root.Version, Equals, int64(3))

	expires = time.Now().Add(6 * time.Hour)
	c.Assert(r.AddTargetWithExpires("foo.txt", nil, expires), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	targets, err := r.topLevelTargets()
	c.Assert(err, IsNil)
	c.Assert(targets.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(targets.Version, Equals, int64(2))

	expires = time.Now().Add(2 * time.Hour)
	c.Assert(r.RemoveTargetWithExpires("foo.txt", expires), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	targets, err = r.topLevelTargets()
	c.Assert(err, IsNil)
	c.Assert(targets.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(targets.Version, Equals, int64(3))

	expires = time.Now().Add(time.Hour)
	c.Assert(r.SnapshotWithExpires(expires), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	snapshot, err := r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(snapshot.Version, Equals, int64(6))

	_, snapshotHasRoot := snapshot.Meta["root.json"]
	c.Assert(snapshotHasRoot, Equals, false)
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, targets.Version)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Version, Equals, int64(7))

	expires = time.Now().Add(10 * time.Minute)
	c.Assert(r.TimestampWithExpires(expires), IsNil)
	c.Assert(r.Commit(), IsNil)
	timestamp, err := r.timestamp()
	c.Assert(err, IsNil)
	c.Assert(timestamp.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(timestamp.Version, Equals, int64(8))

	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	timestamp, err = r.timestamp()
	c.Assert(err, IsNil)
	c.Assert(timestamp.Version, Equals, int64(9))
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
		targets, err := r.topLevelTargets()
		c.Assert(err, IsNil)
		snapshot, err := r.snapshot()
		c.Assert(err, IsNil)
		timestamp, err := r.timestamp()
		c.Assert(err, IsNil)
		for name, file := range map[string]data.FileMeta{
			"foo.txt":       targets.Targets["foo.txt"].FileMeta,
			"targets.json":  {Length: snapshot.Meta["targets.json"].Length, Hashes: snapshot.Meta["targets.json"].Hashes},
			"snapshot.json": {Length: timestamp.Meta["snapshot.json"].Length, Hashes: timestamp.Meta["snapshot.json"].Hashes},
		} {
			for _, hashAlgorithm := range test.expected {
				if _, ok := file.Hashes[hashAlgorithm]; !ok {
					c.Fatalf("expected %s hash to contain hash func %s, got %s", name, hashAlgorithm, file.Hashes.HashAlgorithms())
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

	c.Assert(insecureStore.SaveSigner("foo", signer), IsNil)
	assertKeys("foo", false, []*data.PrivateKey{privateKey})

	// Test changing the passphrase
	// 1. Create a secure store with a passphrase (create new object and temp folder so we discard any previous state)
	tmp = newTmpDir(c)
	var logBytes bytes.Buffer
	storeOpts := StoreOpts{
		Logger:   log.New(&logBytes, "", 0),
		PassFunc: testPassphraseFunc,
	}
	store = FileSystemStoreWithOpts(tmp.path, storeOpts)

	// 1.5. Changing passphrase works for top-level and delegated roles.
	r, err := NewRepo(store)
	c.Assert(err, IsNil)

	c.Assert(r.ChangePassphrase("targets"), NotNil)
	c.Assert(r.ChangePassphrase("foo"), NotNil)

	// 2. Test changing the passphrase when the keys file does not exist - should FAIL
	c.Assert(store.(PassphraseChanger).ChangePassphrase("root"), NotNil)
	c.Assert(strings.Contains(logBytes.String(), "Missing keys file"), Equals, true)

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
		t, err := r.topLevelTargets()
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
	tmp.assertNotExist("repository/targets")
	t, err := r.topLevelTargets()
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

	generateAndAddPrivateKey(c, r, "targets")

	custom := json.RawMessage(`{"foo":"bar"}`)
	assertCustomMeta := func(file string, custom *json.RawMessage) {
		t, err := r.topLevelTargets()
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
	c.Assert(root.Version, Equals, int64(1))

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
	c.Assert(signedRoot.Signed.Version, Equals, int64(1))

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
	c.Assert(signedRoot.Signed.Version, Equals, int64(2))

	unknownKey, ok = signedRoot.Signed.Keys["unknown-key-id"]
	c.Assert(ok, Equals, true)
	c.Assert(unknownKey, DeepEquals, signer.PublicData())
}

func (rs *RepoSuite) TestThreshold(c *C) {
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	_, err = r.GetThreshold("root")
	c.Assert(err, DeepEquals, ErrInvalidRole{"root", "role missing from root metadata"})
	err = r.SetThreshold("root", 2)
	c.Assert(err, DeepEquals, ErrInvalidRole{"root", "role missing from root metadata"})

	// Add one key to each role
	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	t, err := r.GetThreshold("root")
	c.Assert(err, IsNil)
	c.Assert(t, Equals, 1)

	_, err = r.GetThreshold("foo")
	c.Assert(err, DeepEquals, ErrInvalidRole{"foo", "only thresholds for top-level roles supported"})
	err = r.SetThreshold("foo", 2)
	c.Assert(err, DeepEquals, ErrInvalidRole{"foo", "only thresholds for top-level roles supported"})

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
	c.Assert(rootVersion, Equals, int64(2))

	targetsVersion, err := r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, int64(1))

	snapshotVersion, err := r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(snapshotVersion, Equals, int64(2))

	timestampVersion, err := r.TimestampVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, int64(2))
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
	rootCanonical, err := cjson.EncodeCanonical(rootMeta.Signed)
	c.Assert(err, IsNil)
	rootSig, err := rootKey.SignMessage(rootCanonical)
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
	targetsCanonical, err := cjson.EncodeCanonical(targetsMeta.Signed)
	c.Assert(err, IsNil)
	targetsSig, err := targetsKey.SignMessage(targetsCanonical)
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
	snapshotCanonical, err := cjson.EncodeCanonical(snapshotMeta.Signed)
	c.Assert(err, IsNil)
	snapshotSig, err := snapshotKey.SignMessage(snapshotCanonical)
	c.Assert(err, IsNil)
	for _, id := range snapshotKey.PublicData().IDs() {
		r.AddOrUpdateSignature("snapshot.json", data.Signature{
			KeyID:     id,
			Signature: snapshotSig})
	}

	c.Assert(r.Timestamp(), IsNil)
	timestampMeta, err := r.SignedMeta("timestamp.json")
	c.Assert(err, IsNil)
	timestampCanonical, err := cjson.EncodeCanonical(timestampMeta.Signed)
	c.Assert(err, IsNil)
	timestampSig, err := timestampKey.SignMessage(timestampCanonical)
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

	c.Assert(r.AddOrUpdateSignature("targets.json", data.Signature{
		KeyID:     "foo",
		Signature: nil}), Equals, ErrInvalidRole{"targets", "role is not in verifier DB"})

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

	// attempt to sign `root`, rather than `root.json`
	for _, id := range rootKey.PublicData().IDs() {
		c.Assert(r.AddOrUpdateSignature("root", data.Signature{
			KeyID:     id,
			Signature: nil}), Equals, ErrMissingMetadata{"root"})
	}

	// add a signature with a bad role
	rootMeta, err := r.SignedMeta("root.json")
	c.Assert(err, IsNil)
	rootCanonical, err := cjson.EncodeCanonical(rootMeta.Signed)
	c.Assert(err, IsNil)
	rootSig, err := rootKey.Sign(rand.Reader, rootCanonical, crypto.Hash(0))
	c.Assert(err, IsNil)
	for _, id := range rootKey.PublicData().IDs() {
		c.Assert(r.AddOrUpdateSignature("invalid_root.json", data.Signature{
			KeyID:     id,
			Signature: rootSig}), Equals, ErrInvalidRole{"invalid_root", "no trusted keys for role"})
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
		db, err := r.topLevelKeysDB()
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

func (rs *RepoSuite) TestSignDigest(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	digest := "sha256:bc11b176a293bb341a0f2d0d226f52e7fcebd186a7c4dfca5fc64f305f06b94c"
	hash := "bc11b176a293bb341a0f2d0d226f52e7fcebd186a7c4dfca5fc64f305f06b94c"
	size := int64(42)

	c.Assert(r.AddTargetsWithDigest(hash, "sha256", size, digest, nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	digest_bytes, err := hex.DecodeString("bc11b176a293bb341a0f2d0d226f52e7fcebd186a7c4dfca5fc64f305f06b94c")
	hex_digest_bytes := data.HexBytes(digest_bytes)
	c.Assert(err, IsNil)

	targets, err := r.topLevelTargets()
	c.Assert(err, IsNil)
	c.Assert(targets.Targets["sha256:bc11b176a293bb341a0f2d0d226f52e7fcebd186a7c4dfca5fc64f305f06b94c"].FileMeta.Length, Equals, size)
	c.Assert(targets.Targets["sha256:bc11b176a293bb341a0f2d0d226f52e7fcebd186a7c4dfca5fc64f305f06b94c"].FileMeta.Hashes["sha256"], DeepEquals, hex_digest_bytes)
}

func concat(ss ...[]string) []string {
	ret := []string{}
	for _, s := range ss {
		ret = append(ret, s...)
	}
	return ret
}

func checkSigKeyIDs(c *C, local LocalStore, fileToKeyIDs map[string][]string) {
	metas, err := local.GetMeta()
	c.Assert(err, IsNil)

	for f, keyIDs := range fileToKeyIDs {
		meta, ok := metas[f]
		c.Assert(ok, Equals, true, Commentf("meta file: %v", f))

		s := &data.Signed{}
		err = json.Unmarshal(meta, s)
		c.Assert(err, IsNil)

		gotKeyIDs := []string{}
		for _, sig := range s.Signatures {
			gotKeyIDs = append(gotKeyIDs, sig.KeyID)
		}
		gotKeyIDs = sets.DeduplicateStrings(gotKeyIDs)
		sort.Strings(gotKeyIDs)

		sort.Strings(keyIDs)
		c.Assert(gotKeyIDs, DeepEquals, keyIDs)
	}
}

func (rs *RepoSuite) TestDelegations(c *C) {
	tmp := newTmpDir(c)
	local := FileSystemStore(tmp.path, nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// Add one key to each role
	genKey(c, r, "root")
	targetsKeyIDs := genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	// commit the metadata to the store.
	c.Assert(r.AddTargets([]string{}, nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err := r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta, HasLen, 1)
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(1))

	checkSigKeyIDs(c, local, map[string][]string{
		"1.targets.json": targetsKeyIDs,
	})

	saveNewKey := func(role string) keys.Signer {
		key, err := keys.GenerateEd25519Key()
		c.Assert(err, IsNil)

		err = local.SaveSigner(role, key)
		c.Assert(err, IsNil)

		return key
	}

	// Delegate from targets -> role1 for A/*, B/* with one key, threshold 1.
	role1ABKey := saveNewKey("role1")
	role1AB := data.DelegatedRole{
		Name:      "role1",
		KeyIDs:    role1ABKey.PublicData().IDs(),
		Paths:     []string{"A/*", "B/*"},
		Threshold: 1,
	}
	err = r.AddDelegatedRole("targets", role1AB, []*data.PublicKey{
		role1ABKey.PublicData(),
	})
	c.Assert(err, IsNil)

	// Adding duplicate delegation should return an error.
	err = r.AddDelegatedRole("targets", role1AB, []*data.PublicKey{
		role1ABKey.PublicData(),
	})
	c.Assert(err, NotNil)

	// Delegate from targets -> role2 for C/*, D/* with three key, threshold 2.
	role2CDKey1 := saveNewKey("role2")
	role2CDKey2 := saveNewKey("role2")
	role2CDKey3 := saveNewKey("role2")
	role2CD := data.DelegatedRole{
		Name: "role2",
		KeyIDs: concat(
			role2CDKey1.PublicData().IDs(),
			role2CDKey2.PublicData().IDs(),
			role2CDKey3.PublicData().IDs(),
		),
		Paths:     []string{"C/*", "D/*"},
		Threshold: 2,
	}
	err = r.AddDelegatedRole("targets", role2CD, []*data.PublicKey{
		role2CDKey1.PublicData(),
		role2CDKey2.PublicData(),
		role2CDKey3.PublicData(),
	})
	c.Assert(err, IsNil)

	// Delegate from role1 -> role2 for A/allium.txt with one key, threshold 1.
	role1To2Key := saveNewKey("role2")
	role1To2 := data.DelegatedRole{
		Name:        "role2",
		KeyIDs:      role1To2Key.PublicData().IDs(),
		Paths:       []string{"A/allium.txt"},
		Threshold:   1,
		Terminating: true,
	}
	err = r.AddDelegatedRole("role1", role1To2, []*data.PublicKey{
		role1To2Key.PublicData(),
	})
	c.Assert(err, IsNil)

	checkDelegations := func(delegator string, delegatedRoles ...data.DelegatedRole) {
		t, err := r.targets(delegator)
		c.Assert(err, IsNil)

		// Check if there are no delegations.
		if t.Delegations == nil {
			if delegatedRoles != nil {
				c.Fatal("expected delegated roles on delegator")
			}
			return
		}

		// Check that delegated roles are copied verbatim.
		c.Assert(t.Delegations.Roles, DeepEquals, delegatedRoles)

		// Check that public keys match key IDs in roles.
		expectedKeyIDs := []string{}
		for _, dr := range delegatedRoles {
			expectedKeyIDs = append(expectedKeyIDs, dr.KeyIDs...)
		}
		expectedKeyIDs = sets.DeduplicateStrings(expectedKeyIDs)
		sort.Strings(expectedKeyIDs)

		gotKeyIDs := []string{}
		for _, k := range t.Delegations.Keys {
			gotKeyIDs = append(gotKeyIDs, k.IDs()...)
		}
		gotKeyIDs = sets.DeduplicateStrings(gotKeyIDs)
		sort.Strings(gotKeyIDs)

		c.Assert(gotKeyIDs, DeepEquals, expectedKeyIDs)
	}

	checkDelegations("targets", role1AB, role2CD)
	checkDelegations("role1", role1To2)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta, HasLen, 3)
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(2))
	c.Assert(snapshot.Meta["role1.json"].Version, Equals, int64(1))
	c.Assert(snapshot.Meta["role2.json"].Version, Equals, int64(1))

	checkSigKeyIDs(c, local, map[string][]string{
		"2.targets.json": targetsKeyIDs,
		"1.role1.json":   role1ABKey.PublicData().IDs(),
		"1.role2.json": concat(
			role2CDKey1.PublicData().IDs(),
			role2CDKey2.PublicData().IDs(),
			role2CDKey3.PublicData().IDs(),
			role1To2Key.PublicData().IDs(),
		),
	})

	// Add a variety of targets.
	files := map[string]string{
		// targets.json
		"potato.txt": "potatoes can be starchy or waxy",
		// role1.json
		"A/apple.txt":  "apples are sometimes red",
		"B/banana.txt": "bananas are yellow and sometimes brown",
		// role2.json
		"C/clementine.txt": "clementines are a citrus fruit",
		"D/durian.txt":     "durians are spiky",
		"A/allium.txt":     "alliums include garlic and leeks",
	}
	for name, content := range files {
		tmp.writeStagedTarget(name, content)
		c.Assert(r.AddTarget(name, nil), IsNil)
	}

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta, HasLen, 3)
	// All roles should have new targets.
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(3))
	c.Assert(snapshot.Meta["role1.json"].Version, Equals, int64(2))
	c.Assert(snapshot.Meta["role2.json"].Version, Equals, int64(2))

	checkSigKeyIDs(c, local, map[string][]string{
		"3.targets.json": targetsKeyIDs,
		"2.role1.json":   role1ABKey.PublicData().IDs(),
		"2.role2.json": concat(
			role2CDKey1.PublicData().IDs(),
			role2CDKey2.PublicData().IDs(),
			role2CDKey3.PublicData().IDs(),
			role1To2Key.PublicData().IDs(),
		),
	})

	// Check that the given targets role has signed for the given filenames, with
	// the correct file metadata.
	checkTargets := func(role string, filenames ...string) {
		t, err := r.targets(role)
		c.Assert(err, IsNil)
		c.Assert(t.Targets, HasLen, len(filenames))

		for _, fn := range filenames {
			content := files[fn]

			fm, err := util.GenerateTargetFileMeta(strings.NewReader(content))
			c.Assert(err, IsNil)

			c.Assert(util.TargetFileMetaEqual(t.Targets[fn], fm), IsNil)
		}
	}

	checkTargets("targets", "potato.txt")
	checkTargets("role1", "A/apple.txt", "B/banana.txt")
	checkTargets("role2", "C/clementine.txt", "D/durian.txt", "A/allium.txt")

	// Test AddTargetToPreferredRole.
	// role2 is the default signer for A/allium.txt, but role1 is also eligible
	// for A/*.txt according to the delegation from the top-level targets role.
	c.Assert(r.RemoveTarget("A/allium.txt"), IsNil)
	tmp.writeStagedTarget("A/allium.txt", files["A/allium.txt"])
	c.Assert(r.AddTargetToPreferredRole("A/allium.txt", nil, "role1"), IsNil)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta, HasLen, 3)
	// Only role1 and role2 should have bumped versions.
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(3))
	c.Assert(snapshot.Meta["role1.json"].Version, Equals, int64(3))
	c.Assert(snapshot.Meta["role2.json"].Version, Equals, int64(3))

	checkSigKeyIDs(c, local, map[string][]string{
		"3.targets.json": targetsKeyIDs,
		"3.role1.json":   role1ABKey.PublicData().IDs(),
		"3.role2.json": concat(
			role2CDKey1.PublicData().IDs(),
			role2CDKey2.PublicData().IDs(),
			role2CDKey3.PublicData().IDs(),
			role1To2Key.PublicData().IDs(),
		),
	})

	// role1 now signs A/allium.txt.
	checkTargets("targets", "potato.txt")
	checkTargets("role1", "A/apple.txt", "B/banana.txt", "A/allium.txt")
	checkTargets("role2", "C/clementine.txt", "D/durian.txt")

	// Remove the delegation from role1 to role2.
	c.Assert(r.ResetTargetsDelegations("role1"), IsNil)
	checkDelegations("targets", role1AB, role2CD)
	checkDelegations("role1")

	// Try to sign A/allium.txt with role2.
	// It should fail since we removed the role1 -> role2 delegation.
	c.Assert(r.RemoveTarget("A/allium.txt"), IsNil)
	tmp.writeStagedTarget("A/allium.txt", files["A/allium.txt"])
	c.Assert(r.AddTargetToPreferredRole("A/allium.txt", nil, "role2"), Equals, ErrNoDelegatedTarget{Path: "A/allium.txt"})

	// Try to sign A/allium.txt with the default role (role1).
	c.Assert(r.AddTarget("A/allium.txt", nil), IsNil)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta, HasLen, 3)
	// Only role1 should have a bumped version.
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(3))
	c.Assert(snapshot.Meta["role1.json"].Version, Equals, int64(4))
	c.Assert(snapshot.Meta["role2.json"].Version, Equals, int64(3))

	checkSigKeyIDs(c, local, map[string][]string{
		"3.targets.json": targetsKeyIDs,
		"4.role1.json":   role1ABKey.PublicData().IDs(),
		"3.role2.json": concat(
			// Metadata (and therefore signers) for role2.json shouldn't have
			// changed, even though we revoked role1To2Key. Clients verify the
			// signature using keys specified by 4.role1.json, so role1To2Key
			// shouldn't contribute to the threshold.
			role2CDKey1.PublicData().IDs(),
			role2CDKey2.PublicData().IDs(),
			role2CDKey3.PublicData().IDs(),
			role1To2Key.PublicData().IDs(),
		),
	})

	// Re-sign target signed by role2 to test that role1To2Key is not used going
	// forward.
	c.Assert(r.RemoveTarget("C/clementine.txt"), IsNil)
	tmp.writeStagedTarget("C/clementine.txt", files["C/clementine.txt"])
	c.Assert(r.AddTarget("C/clementine.txt", nil), IsNil)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta, HasLen, 3)
	// Only role2 should have a bumped version.
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(3))
	c.Assert(snapshot.Meta["role1.json"].Version, Equals, int64(4))
	c.Assert(snapshot.Meta["role2.json"].Version, Equals, int64(4))

	checkSigKeyIDs(c, local, map[string][]string{
		"3.targets.json": targetsKeyIDs,
		"4.role1.json":   role1ABKey.PublicData().IDs(),
		"4.role2.json": concat(
			role2CDKey1.PublicData().IDs(),
			role2CDKey2.PublicData().IDs(),
			role2CDKey3.PublicData().IDs(),
			// Note that role1To2Key no longer signs since the role1 -> role2
			// delegation was removed.
		),
	})

	// Targets should still be signed by the same roles.
	checkTargets("targets", "potato.txt")
	checkTargets("role1", "A/apple.txt", "B/banana.txt", "A/allium.txt")
	checkTargets("role2", "C/clementine.txt", "D/durian.txt")

	// Add back the role1 -> role2 delegation, and verify that it doesn't change
	// existing targets in role2.json.
	err = r.AddDelegatedRole("role1", role1To2, []*data.PublicKey{
		role1To2Key.PublicData(),
	})
	c.Assert(err, IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta, HasLen, 3)
	// Both role1 and role2 should have a bumped version.
	// role1 is bumped because the delegations changed.
	// role2 is only bumped because its expiration is bumped.
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(3))
	c.Assert(snapshot.Meta["role1.json"].Version, Equals, int64(5))
	c.Assert(snapshot.Meta["role2.json"].Version, Equals, int64(5))

	checkTargets("targets", "potato.txt")
	checkTargets("role1", "A/apple.txt", "B/banana.txt", "A/allium.txt")
	checkTargets("role2", "C/clementine.txt", "D/durian.txt")
}

func (rs *RepoSuite) TestHashBinDelegations(c *C) {
	tmp := newTmpDir(c)
	local := FileSystemStore(tmp.path, nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// Add one key to each role
	genKey(c, r, "root")
	targetsKeyIDs := genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	hb, err := targets.NewHashBins("bins_", 3)
	if err != nil {
		c.Assert(err, IsNil)
	}

	// Generate key for the intermediate bins role.
	binsKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	err = local.SaveSigner("bins", binsKey)
	c.Assert(err, IsNil)

	// Generate key for the leaf bins role.
	leafKey, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)
	for i := uint64(0); i < hb.NumBins(); i++ {
		b := hb.GetBin(i)
		err = local.SaveSigner(b.RoleName(), leafKey)
		if err != nil {
			c.Assert(err, IsNil)
		}
	}

	err = r.AddDelegatedRole("targets", data.DelegatedRole{
		Name:      "bins",
		KeyIDs:    binsKey.PublicData().IDs(),
		Paths:     []string{"*.txt"},
		Threshold: 1,
	}, []*data.PublicKey{
		binsKey.PublicData(),
	})
	c.Assert(err, IsNil)

	err = r.AddDelegatedRolesForPathHashBins("bins", hb, []*data.PublicKey{leafKey.PublicData()}, 1)
	c.Assert(err, IsNil)
	targets, err := r.targets("bins")
	c.Assert(err, IsNil)
	c.Assert(targets.Delegations.Roles, HasLen, 8)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	tmp.writeStagedTarget("foo.txt", "foo")
	err = r.AddTarget("foo.txt", nil)
	c.Assert(err, IsNil)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err := r.snapshot()
	c.Assert(err, IsNil)
	// 1 targets.json, 1 bins.json, 8 bins_*.json.
	c.Assert(snapshot.Meta, HasLen, 10)
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(1))
	c.Assert(snapshot.Meta["bins.json"].Version, Equals, int64(1))
	c.Assert(snapshot.Meta["bins_0-1.json"].Version, Equals, int64(1))
	c.Assert(snapshot.Meta["bins_2-3.json"].Version, Equals, int64(1))
	c.Assert(snapshot.Meta["bins_4-5.json"].Version, Equals, int64(1))
	c.Assert(snapshot.Meta["bins_6-7.json"].Version, Equals, int64(1))
	c.Assert(snapshot.Meta["bins_8-9.json"].Version, Equals, int64(1))
	c.Assert(snapshot.Meta["bins_a-b.json"].Version, Equals, int64(1))
	c.Assert(snapshot.Meta["bins_c-d.json"].Version, Equals, int64(2))
	c.Assert(snapshot.Meta["bins_e-f.json"].Version, Equals, int64(1))

	targets, err = r.targets("bins_c-d")
	c.Assert(err, IsNil)
	c.Assert(targets.Targets, HasLen, 1)

	checkSigKeyIDs(c, local, map[string][]string{
		"targets.json":    targetsKeyIDs,
		"1.bins.json":     binsKey.PublicData().IDs(),
		"1.bins_0-1.json": leafKey.PublicData().IDs(),
		"1.bins_2-3.json": leafKey.PublicData().IDs(),
		"1.bins_4-5.json": leafKey.PublicData().IDs(),
		"1.bins_6-7.json": leafKey.PublicData().IDs(),
		"1.bins_8-9.json": leafKey.PublicData().IDs(),
		"1.bins_a-b.json": leafKey.PublicData().IDs(),
		"1.bins_c-d.json": leafKey.PublicData().IDs(),
		"2.bins_c-d.json": leafKey.PublicData().IDs(),
		"1.bins_e-f.json": leafKey.PublicData().IDs(),
	})
}

func (rs *RepoSuite) TestResetTargetsDelegationsWithExpires(c *C) {
	tmp := newTmpDir(c)
	local := FileSystemStore(tmp.path, nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// Add one key to each role
	genKey(c, r, "root")
	targetsKeyIDs := genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	// commit the metadata to the store.
	c.Assert(r.AddTargets([]string{}, nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err := r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta, HasLen, 1)
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(1))

	checkSigKeyIDs(c, local, map[string][]string{
		"1.targets.json": targetsKeyIDs,
	})

	role1Key, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)

	err = local.SaveSigner("role1", role1Key)
	c.Assert(err, IsNil)

	// Delegate from targets -> role1 for A/*, B/* with one key, threshold 1.
	role1 := data.DelegatedRole{
		Name:      "role1",
		KeyIDs:    role1Key.PublicData().IDs(),
		Paths:     []string{"A/*", "B/*"},
		Threshold: 1,
	}
	err = r.AddDelegatedRole("targets", role1, []*data.PublicKey{
		role1Key.PublicData(),
	})
	c.Assert(err, IsNil)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta, HasLen, 2)
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(2))
	c.Assert(snapshot.Meta["role1.json"].Version, Equals, int64(1))

	checkSigKeyIDs(c, local, map[string][]string{
		"1.targets.json": targetsKeyIDs,
		"targets.json":   targetsKeyIDs,
		"1.role1.json":   role1Key.PublicData().IDs(),
		"role1.json":     role1Key.PublicData().IDs(),
	})

	c.Assert(r.ResetTargetsDelegations("targets"), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta, HasLen, 2)
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, int64(3))
	c.Assert(snapshot.Meta["role1.json"].Version, Equals, int64(1))

	checkSigKeyIDs(c, local, map[string][]string{
		"2.targets.json": targetsKeyIDs,
		"targets.json":   targetsKeyIDs,
		"1.role1.json":   role1Key.PublicData().IDs(),
		"role1.json":     role1Key.PublicData().IDs(),
	})
}

func (rs *RepoSuite) TestSignWithDelegations(c *C) {
	tmp := newTmpDir(c)
	local := FileSystemStore(tmp.path, nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// Add one key to each role
	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	role1Key, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)

	role1 := data.DelegatedRole{
		Name:      "role1",
		KeyIDs:    role1Key.PublicData().IDs(),
		Paths:     []string{"A/*", "B/*"},
		Threshold: 1,
	}
	err = r.AddDelegatedRole("targets", role1, []*data.PublicKey{
		role1Key.PublicData(),
	})
	c.Assert(err, IsNil)

	// targets.json should be signed, but role1.json is not signed because there
	// is no key in the local store.
	m, err := local.GetMeta()
	c.Assert(err, IsNil)
	targetsMeta := &data.Signed{}
	c.Assert(json.Unmarshal(m["targets.json"], targetsMeta), IsNil)
	c.Assert(len(targetsMeta.Signatures), Equals, 1)
	role1Meta := &data.Signed{}
	c.Assert(json.Unmarshal(m["role1.json"], role1Meta), IsNil)
	c.Assert(len(role1Meta.Signatures), Equals, 0)

	c.Assert(r.Snapshot(), DeepEquals, ErrInsufficientSignatures{"role1.json", verify.ErrNoSignatures})

	// Sign role1.json.
	c.Assert(local.SaveSigner("role1", role1Key), IsNil)
	c.Assert(r.Sign("role1.json"), IsNil)

	m, err = local.GetMeta()
	c.Assert(err, IsNil)
	targetsMeta = &data.Signed{}
	c.Assert(json.Unmarshal(m["targets.json"], targetsMeta), IsNil)
	c.Assert(len(targetsMeta.Signatures), Equals, 1)
	role1Meta = &data.Signed{}
	c.Assert(json.Unmarshal(m["role1.json"], role1Meta), IsNil)
	c.Assert(len(role1Meta.Signatures), Equals, 1)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
}

func (rs *RepoSuite) TestAddOrUpdateSignatureWithDelegations(c *C) {
	tmp := newTmpDir(c)
	local := FileSystemStore(tmp.path, nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// Add one key to each role
	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	role1Key, err := keys.GenerateEd25519Key()
	c.Assert(err, IsNil)

	role1 := data.DelegatedRole{
		Name:      "role1",
		KeyIDs:    role1Key.PublicData().IDs(),
		Paths:     []string{"A/*", "B/*"},
		Threshold: 1,
	}
	err = r.AddDelegatedRole("targets", role1, []*data.PublicKey{
		role1Key.PublicData(),
	})
	c.Assert(err, IsNil)

	// targets.json should be signed, but role1.json is not signed because there
	// is no key in the local store.
	m, err := local.GetMeta()
	c.Assert(err, IsNil)
	targetsMeta := &data.Signed{}
	c.Assert(json.Unmarshal(m["targets.json"], targetsMeta), IsNil)
	c.Assert(len(targetsMeta.Signatures), Equals, 1)
	role1Meta := &data.Signed{}
	c.Assert(json.Unmarshal(m["role1.json"], role1Meta), IsNil)
	c.Assert(len(role1Meta.Signatures), Equals, 0)

	c.Assert(r.Snapshot(), DeepEquals, ErrInsufficientSignatures{"role1.json", verify.ErrNoSignatures})

	// Sign role1.json.
	canonical, err := cjson.EncodeCanonical(role1Meta.Signed)
	c.Assert(err, IsNil)
	sig, err := role1Key.SignMessage(canonical)
	c.Assert(err, IsNil)
	err = r.AddOrUpdateSignature("role1.json", data.Signature{
		KeyID:     role1Key.PublicData().IDs()[0],
		Signature: sig,
	})
	c.Assert(err, IsNil)

	m, err = local.GetMeta()
	c.Assert(err, IsNil)
	targetsMeta = &data.Signed{}
	c.Assert(json.Unmarshal(m["targets.json"], targetsMeta), IsNil)
	c.Assert(len(targetsMeta.Signatures), Equals, 1)
	role1Meta = &data.Signed{}
	c.Assert(json.Unmarshal(m["role1.json"], role1Meta), IsNil)
	c.Assert(len(role1Meta.Signatures), Equals, 1)

	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
}

// Test the offline signature flow: Payload -> SignPayload -> AddSignature
func (rs *RepoSuite) TestOfflineFlow(c *C) {
	// Set up repo.
	meta := make(map[string]json.RawMessage)
	local := MemoryStore(meta, nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)
	c.Assert(r.Init(false), IsNil)
	_, err = r.GenKey("root")
	c.Assert(err, IsNil)

	// Get the payload to sign
	_, err = r.Payload("badrole.json")
	c.Assert(err, Equals, ErrMissingMetadata{"badrole.json"})
	_, err = r.Payload("root")
	c.Assert(err, Equals, ErrMissingMetadata{"root"})
	payload, err := r.Payload("root.json")
	c.Assert(err, IsNil)

	root, err := r.SignedMeta("root.json")
	c.Assert(err, IsNil)
	rootCanonical, err := cjson.EncodeCanonical(root.Signed)
	c.Assert(err, IsNil)
	if !bytes.Equal(payload, rootCanonical) {
		c.Fatalf("Payload(): not canonical.\n%s\n%s", string(payload), string(rootCanonical))
	}

	// Sign the payload
	signed := data.Signed{Signed: payload}
	_, err = r.SignPayload("targets", &signed)
	c.Assert(err, Equals, ErrNoKeys{"targets"})
	numKeys, err := r.SignPayload("root", &signed)
	c.Assert(err, IsNil)
	c.Assert(numKeys, Equals, 1)

	// Add the payload signatures back
	for _, sig := range signed.Signatures {
		// This method checks that the signature verifies!
		err = r.AddOrUpdateSignature("root.json", sig)
		c.Assert(err, IsNil)
	}
}

// Regression test: Snapshotting an invalid root should fail.
func (rs *RepoSuite) TestSnapshotWithInvalidRoot(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// Init should create targets.json, but not signed yet
	r.Init(false)

	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)

	// Clear the root signature so that signature verification fails.
	s, err := r.SignedMeta("root.json")
	c.Assert(err, IsNil)
	c.Assert(s.Signatures, HasLen, 1)
	s.Signatures[0].Signature = data.HexBytes{}
	b, err := r.jsonMarshal(s)
	c.Assert(err, IsNil)
	r.meta["root.json"] = b
	local.SetMeta("root.json", b)

	// Snapshotting should fail.
	c.Assert(r.Snapshot(), Equals, ErrInsufficientSignatures{
		"root.json", verify.ErrRoleThreshold{Expected: 1, Actual: 0}})

	// Correctly sign root
	c.Assert(r.Sign("root.json"), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
}

// Regression test: Do not omit length in target metadata files.
func (rs *RepoSuite) TestTargetMetadataLength(c *C) {
	files := map[string][]byte{"foo.txt": []byte("")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// Init should create targets.json, but not signed yet
	r.Init(false)

	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// Check length field of foo.txt exists.
	meta, err := local.GetMeta()
	c.Assert(err, IsNil)
	targetsJSON, ok := meta["targets.json"]
	if !ok {
		c.Fatal("missing targets metadata")
	}
	s := &data.Signed{}
	c.Assert(json.Unmarshal(targetsJSON, s), IsNil)
	fmt.Fprint(os.Stderr, s.Signed)
	var objMap map[string]json.RawMessage
	c.Assert(json.Unmarshal(s.Signed, &objMap), IsNil)
	targetsMap, ok := objMap["targets"]
	if !ok {
		c.Fatal("missing targets field in targets metadata")
	}
	c.Assert(json.Unmarshal(targetsMap, &objMap), IsNil)
	targetsMap, ok = objMap["foo.txt"]
	if !ok {
		c.Fatal("missing foo.txt in targets")
	}
	c.Assert(json.Unmarshal(targetsMap, &objMap), IsNil)
	lengthMsg, ok := objMap["length"]
	if !ok {
		c.Fatal("missing length field in foo.txt file meta")
	}
	var length int64
	c.Assert(json.Unmarshal(lengthMsg, &length), IsNil)
	c.Assert(length, Equals, int64(0))
}

func (rs *RepoSuite) TestDeprecatedHexEncodedKeysFails(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	r.Init(false)
	// Add a root key with hex-encoded ecdsa format
	signer, err := keys.GenerateEcdsaKey()
	c.Assert(err, IsNil)
	type deprecatedP256Verifier struct {
		PublicKey data.HexBytes `json:"public"`
	}
	pub := signer.PublicKey
	keyValBytes, err := json.Marshal(&deprecatedP256Verifier{PublicKey: elliptic.Marshal(pub.Curve, pub.X, pub.Y)})
	c.Assert(err, IsNil)
	publicData := &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      keyValBytes,
	}
	err = r.AddVerificationKey("root", publicData)
	c.Assert(err, IsNil)
	// TODO: AddVerificationKey does no validation, so perform a sign operation.
	c.Assert(r.Sign("root.json"), ErrorMatches, "tuf: error unmarshalling key: invalid PEM value")
}

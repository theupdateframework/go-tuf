package tuf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/encrypted"
	"github.com/theupdateframework/go-tuf/sign"
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

// AssertNumUniqueKeys verifies that the number of unique root keys for a given role is as expected.
func (*RepoSuite) assertNumUniqueKeys(c *C, root *data.Root, role string, num int) {
	c.Assert(root.UniqueKeys()[role], HasLen, num)
}

//Same function as previous one just for top Target role
func (*RepoSuite) targetAssertUniqueKeys(c *C, targ *data.Targets, role string, num int) {
	c.Assert(targ.TargetUniqueKeys()[role], HasLen, num)
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
			"keys":{},
			"targets": {},
			"roles": {},
			"delegations":{}
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
	c.Assert(targets.Targets, HasLen, 0)
	c.Assert(targets.Keys, HasLen, 0)

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

//Generate a key for a certain delegated role
//default tests are contained
func delegateGenKey(c *C, r *Repo, roleName string) []string {
	keyids, err := r.DelegateGenKey(roleName)
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
		c.Assert(k.Value.Public, HasLen, ed25519.PublicKeySize)
	}

	// check root key + role are in db
	db, err := r.db()
	c.Assert(err, IsNil)
	for _, keyID := range ids {
		rootKey := db.GetKey(keyID)
		c.Assert(rootKey, NotNil)
		c.Assert(rootKey.IDs(), DeepEquals, ids)
		role := db.GetRole("root")
		c.Assert(role.KeyIDs, DeepEquals, util.StringSliceToSet(ids))

		// check the key was saved correctly
		localKeys, err := local.GetSigningKeys("root")
		c.Assert(err, IsNil)
		c.Assert(localKeys, HasLen, 1)
		c.Assert(localKeys[0].IDs(), DeepEquals, ids)

		// check RootKeys() is correct
		rootKeys, err := r.RootKeys()
		c.Assert(err, IsNil)
		c.Assert(rootKeys, HasLen, 1)
		c.Assert(rootKeys[0].IDs(), DeepEquals, rootKey.IDs())
		c.Assert(rootKeys[0].Value.Public, DeepEquals, rootKey.Value.Public)
	}

	rootKey := db.GetKey(ids[0])
	c.Assert(rootKey, NotNil)

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
		key := db.GetKey(id)
		c.Assert(key, NotNil)
		c.Assert(key.ContainsID(id), Equals, true)
	}
	role := db.GetRole("targets")
	c.Assert(role.KeyIDs, DeepEquals, targetKeyIDs)

	// check RootKeys() is unchanged
	rootKeys, err := r.RootKeys()
	c.Assert(err, IsNil)
	c.Assert(rootKeys, HasLen, 1)
	c.Assert(rootKeys[0].IDs(), DeepEquals, rootKey.IDs())

	// check the keys were saved correctly
	localKeys, err := local.GetSigningKeys("targets")
	c.Assert(err, IsNil)
	c.Assert(localKeys, HasLen, 2)
	for _, key := range localKeys {
		found := false
		for _, id := range targetsRole.KeyIDs {
			if key.ContainsID(id) {
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

func addPrivateKey(c *C, r *Repo, role string, key *sign.PrivateKey) []string {
	err := r.AddPrivateKey(role, key)
	c.Assert(err, IsNil)
	keyids := key.PublicData().IDs()
	c.Assert(len(keyids) > 0, Equals, true)
	return keyids
}

func addGeneratedPrivateKey(c *C, r *Repo, role string) []string {
	key, err := sign.GenerateEd25519Key()
	c.Assert(err, IsNil)
	return addPrivateKey(c, r, role, key)
}

func (rs *RepoSuite) TestAddPrivateKey(c *C) {
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// generate a key for an unknown role
	key, err := sign.GenerateEd25519Key()
	c.Assert(err, IsNil)
	err = r.AddPrivateKey("foo", key)
	c.Assert(err, Equals, ErrInvalidRole{"foo"})

	// add a root key
	ids := addPrivateKey(c, r, "root", key)

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
		c.Assert(k.Value.Public, HasLen, ed25519.PublicKeySize)
	}

	// check root key + role are in db
	db, err := r.db()
	c.Assert(err, IsNil)
	for _, keyID := range ids {
		rootKey := db.GetKey(keyID)
		c.Assert(rootKey, NotNil)
		c.Assert(rootKey.IDs(), DeepEquals, ids)
		role := db.GetRole("root")
		c.Assert(role.KeyIDs, DeepEquals, util.StringSliceToSet(ids))

		// check the key was saved correctly
		localKeys, err := local.GetSigningKeys("root")
		c.Assert(err, IsNil)
		c.Assert(localKeys, HasLen, 1)
		c.Assert(localKeys[0].IDs(), DeepEquals, ids)

		// check RootKeys() is correct
		rootKeys, err := r.RootKeys()
		c.Assert(err, IsNil)
		c.Assert(rootKeys, HasLen, 1)
		c.Assert(rootKeys[0].IDs(), DeepEquals, rootKey.IDs())
		c.Assert(rootKeys[0].Value.Public, DeepEquals, rootKey.Value.Public)
	}

	rootKey := db.GetKey(ids[0])
	c.Assert(rootKey, NotNil)

	// generate two targets keys
	addGeneratedPrivateKey(c, r, "targets")
	addGeneratedPrivateKey(c, r, "targets")

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
		key := db.GetKey(id)
		c.Assert(key, NotNil)
		c.Assert(key.ContainsID(id), Equals, true)
	}
	role := db.GetRole("targets")
	c.Assert(role.KeyIDs, DeepEquals, targetKeyIDs)

	// check RootKeys() is unchanged
	rootKeys, err := r.RootKeys()
	c.Assert(err, IsNil)
	c.Assert(rootKeys, HasLen, 1)
	c.Assert(rootKeys[0].IDs(), DeepEquals, rootKey.IDs())

	// check the keys were saved correctly
	localKeys, err := local.GetSigningKeys("targets")
	c.Assert(err, IsNil)
	c.Assert(localKeys, HasLen, 2)
	for _, key := range localKeys {
		found := false
		for _, id := range targetsRole.KeyIDs {
			if key.ContainsID(id) {
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
	addGeneratedPrivateKey(c, r, "snapshot")
	addGeneratedPrivateKey(c, r, "timestamp")
	c.Assert(r.AddTargets([]string{}, nil), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// add the same root key to make sure the metadata is unmodified.
	oldRoot, err := r.root()
	c.Assert(err, IsNil)
	addPrivateKey(c, r, "root", key)
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
	delek1 := delegateGenKey(c, r, "role01")
	delek2 := delegateGenKey(c, r, "role01")
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

	target, err := r.targets()
	c.Assert(err, IsNil)
	c.Assert(target.Roles, HasLen, 1)
	c.Assert(target.Keys, NotNil)
	rs.targetAssertUniqueKeys(c, target, "role01", 2)

	// revoke a key of top Target role
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

	//Revoke a Key for the delegated role
	tempRole, ok := target.Roles["role01"]
	if !ok {
		c.Fatal("missing targets role")
	}
	c.Assert(tempRole.KeyIDs, HasLen, len(delek1)+len(delek2))
	id2 := tempRole.KeyIDs[0]
	c.Assert(r.DelegateRevokeKey("role01", id2), IsNil)
	for _, id := range delek1 {
		c.Assert(r.RevokeKey("role01", id), DeepEquals, ErrInvalidRole{Role: "role01"})
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

	// check target is updated
	target, err = r.targets()
	c.Assert(err, IsNil)
	c.Assert(target.Roles, NotNil)
	c.Assert(target.Roles, HasLen, 1)
	c.Assert(target.Keys, NotNil)
	rs.targetAssertUniqueKeys(c, target, "role01", 1)

	tempRole, ok = target.Roles["role01"]
	if !ok {
		c.Fatal("missing delegated targets role")
	}
	c.Assert(tempRole.KeyIDs, HasLen, 1)
	c.Assert(tempRole.KeyIDs, DeepEquals, delek2)
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
		for i, id := range keyIDs {
			c.Assert(s.Signatures[i].KeyID, Equals, id)
		}
	}

	// signing with an available key generates a signature
	key, err := sign.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(local.SavePrivateKey("root", key), IsNil)
	c.Assert(r.Sign("root.json"), IsNil)
	checkSigIDs(key.PublicData().IDs()...)

	// signing again does not generate a duplicate signature
	c.Assert(r.Sign("root.json"), IsNil)
	checkSigIDs(key.PublicData().IDs()...)

	// signing with a new available key generates another signature
	newKey, err := sign.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(local.SavePrivateKey("root", newKey), IsNil)
	c.Assert(r.Sign("root.json"), IsNil)
	checkSigIDs(append(key.PublicData().IDs(), newKey.PublicData().IDs()...)...)
}

func (rs *RepoSuite) TestDelegation(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo"), "bar.txt": []byte("ear"), "dar.txt": []byte("ear")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	//generate root and target
	genKey(c, r, "root")
	ids1 := genKey(c, r, "targets")

	c.Assert(r.AddTarget("foo.txt", nil), IsNil)

	//initialize new target toles
	keyids, err := r.DelegateGenKey("role01")
	c.Assert(err, IsNil)
	c.Assert(len(keyids) > 0, Equals, true)

	//basic test root and target
	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, NotNil)
	c.Assert(root.Roles, HasLen, 2)
	rs.assertNumUniqueKeys(c, root, "root", 1)
	target, err := r.targets()
	c.Assert(err, IsNil)
	c.Assert(target.Roles, NotNil)
	c.Assert(target.Roles, HasLen, 1)
	rs.assertNumUniqueKeys(c, root, "targets", 1)

	//check top target stores keys of delegated target role
	targetRole, ok := root.Roles["targets"]
	if !ok {
		c.Fatal("missing target role")
	}
	c.Assert(targetRole.KeyIDs, HasLen, 1)
	c.Assert(targetRole.KeyIDs, DeepEquals, ids1)
	for _, keyID := range ids1 {
		k, ok := root.Keys[keyID]
		if !ok {
			c.Fatal("missing key")
		}
		c.Assert(k.IDs(), DeepEquals, ids1)
		c.Assert(k.Value.Public, HasLen, ed25519.PublicKeySize)
	}

	//Check add target file function of delegation
	c.Assert(r.DelegateAddTarget("role01.json", "foo.txt", nil), IsNil)
	tempRole, ok := target.Roles["role01"]
	if !ok {
		c.Fatal("missing target role")
	}
	c.Assert(tempRole.KeyIDs, HasLen, 1)
	c.Assert(tempRole.KeyIDs, DeepEquals, keyids)
	for _, keyID := range keyids {
		k, ok := target.Keys[keyID]
		if !ok {
			c.Fatal("missing key")
		}
		c.Assert(k.IDs(), DeepEquals, keyids)
		c.Assert(k.Value.Public, HasLen, ed25519.PublicKeySize)
	}

	//check non-top target role in db
	db, err := r.db()
	c.Assert(err, IsNil)
	tempKeyIDs := make(map[string]struct{}, 2)
	for _, id := range tempRole.KeyIDs {
		tempKeyIDs[id] = struct{}{}
		_, ok = target.Keys[id]
		if !ok {
			c.Fatal("missing key")
		}
		key := db.GetKey(id)
		c.Assert(key, NotNil)
		c.Assert(key.ContainsID(id), Equals, true)
	}
	role := db.GetRole("role01")
	c.Assert(role.KeyIDs, DeepEquals, tempKeyIDs)

	// check the keys were saved correctly
	localKeys, err := local.GetSigningKeys("role01")
	c.Assert(err, IsNil)
	c.Assert(localKeys, HasLen, 1)
	for _, key := range localKeys {
		found := false
		for _, id := range tempRole.KeyIDs {
			if key.ContainsID(id) {
				found = true
				break
			}
		}
		if !found {
			c.Fatal("missing key")
		}
	}

	// check target.json got staged
	meta, err := local.GetMeta()
	c.Assert(err, IsNil)
	tarJSON, ok := meta["targets.json"]
	if !ok {
		c.Fatal("missing root metadata")
	}
	s := &data.Signed{}
	c.Assert(json.Unmarshal(tarJSON, s), IsNil)
	stagedTarget := &data.Targets{}
	c.Assert(json.Unmarshal(s.Signed, stagedTarget), IsNil)
	c.Assert(stagedTarget.Type, Equals, target.Type)
	c.Assert(stagedTarget.Version, Equals, target.Version)
	c.Assert(stagedTarget.Expires.UnixNano(), Equals, target.Expires.UnixNano())

	//check role01.json got staged
	tempTarget, err := r.delegationTargets("role01.json")
	c.Assert(err, IsNil)
	tempJSON, ok := meta["role01.json"]
	if !ok {
		c.Fatal("missing root metadata")
	}
	s1 := &data.Signed{}
	c.Assert(json.Unmarshal(tempJSON, s1), IsNil)
	stagedTempTarget := &data.Targets{}
	c.Assert(json.Unmarshal(s1.Signed, stagedTempTarget), IsNil)
	c.Assert(stagedTempTarget.Type, Equals, tempTarget.Type)
	c.Assert(stagedTempTarget.Version, Equals, tempTarget.Version)
	c.Assert(stagedTempTarget.Expires.UnixNano(), Equals, tempTarget.Expires.UnixNano())

	// make sure both top-target and staged top-target have evaluated IDs(), otherwise
	// DeepEquals will fail because those values might not have been
	// computed yet.
	for _, key := range target.Keys {
		key.IDs()
	}
	for _, key := range stagedTarget.Keys {
		key.IDs()
	}
	c.Assert(stagedTarget.Keys, DeepEquals, target.Keys)
	c.Assert(stagedTarget.Roles, DeepEquals, target.Roles)

	// make sure both top-target and staged top-target have evaluated IDs(), otherwise
	// DeepEquals will fail because those values might not have been
	// computed yet.
	for _, key := range tempTarget.Keys {
		key.IDs()
	}
	for _, key := range stagedTempTarget.Keys {
		key.IDs()
	}
	c.Assert(stagedTempTarget.Keys, DeepEquals, tempTarget.Keys)
	c.Assert(stagedTempTarget.Roles, DeepEquals, tempTarget.Roles)

	// commit to make sure we don't modify metadata after committing metadata.
	addGeneratedPrivateKey(c, r, "snapshot")
	addGeneratedPrivateKey(c, r, "timestamp")
	c.Assert(r.AddTargets([]string{}, nil), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
}

func (rs *RepoSuite) TestCommit(c *C) {
	files := map[string][]byte{
		"foo.txt": []byte("foo"), "bar.txt": []byte("bar"), "ear.txt": []byte("ear")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// commit without root.json
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"root.json"})

	// commit without targets.json
	genKey(c, r, "root")
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"targets.json"})

	//Add non-top target role
	keyids, err := r.DelegateGenKey("role01")
	c.Assert(err, IsNil)
	c.Assert(len(keyids) > 0, Equals, true)
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"snapshot.json"})

	// commit without snapshot.json
	genKey(c, r, "targets")
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	c.Assert(r.DelegateAddTarget("role01.json", "bar.txt", nil), IsNil)
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"snapshot.json"})

	// commit without timestamp.json
	genKey(c, r, "snapshot")
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"timestamp.json"})

	// commit with timestamp.json but no timestamp key
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), DeepEquals, ErrInsufficientSignatures{"timestamp.json", verify.ErrNoSignatures})

	// commit success
	genKey(c, r, "timestamp")
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// commit with an invalid root hash in snapshot.json due to new key creation
	genKey(c, r, "targets")
	c.Assert(r.Sign("targets.json"), IsNil)
	c.Assert(r.Commit(), DeepEquals, errors.New("tuf: invalid root.json in snapshot.json: wrong length, expected 1740 got 2046"))

	// commit with an invalid root hash in snapshot.json due to new key creation (non-top target)
	keyids2, err := r.DelegateGenKey("role01")
	c.Assert(err, IsNil)
	c.Assert(len(keyids2) > 0, Equals, true)
	c.Assert(r.Commit(), DeepEquals, errors.New("tuf: invalid root.json in snapshot.json: wrong length, expected 1740 got 2046"))

	// commit with an invalid targets hash in snapshot.json
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.AddTarget("bar.txt", nil), IsNil)
	c.Assert(r.Commit(), DeepEquals, errors.New("tuf: invalid targets.json in snapshot.json: wrong length, expected 1392 got 1566"))

	// commit with an invalid timestamp
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	// TODO: Change this test once Snapshot() supports compression and we
	//       can guarantee the error will end in "wrong length" by
	//       compressing a file and thus changing the size of snapshot.json
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
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), DeepEquals, ErrNotEnoughKeys{"timestamp", 0, 1})
}

func (rs *RepoSuite) TestCommitVersions(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo"), "bar.txt": []byte("bar")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	delegateGenKey(c, r, "role01")

	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	c.Assert(r.DelegateAddTarget("role01.json", "bar.txt", nil), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// on initial commit everything should be at version 1.
	rootVersion, err := r.RootVersion()
	c.Assert(err, IsNil)
	c.Assert(rootVersion, Equals, 1)

	targetsVersion, err := r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, 1)

	delegateVersion, err := r.DelegateTargetVersion("role01.json")
	c.Assert(err, IsNil)
	c.Assert(delegateVersion, Equals, 1)

	snapshotVersion, err := r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(snapshotVersion, Equals, 1)

	timestampVersion, err := r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, 1)

	// taking a snapshot should only incremept snapshot and timestamp.
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	rootVersion, err = r.RootVersion()
	c.Assert(err, IsNil)
	c.Assert(rootVersion, Equals, 1)

	targetsVersion, err = r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, 1)

	delegateVersion, err = r.DelegateTargetVersion("role01.json")
	c.Assert(err, IsNil)
	c.Assert(delegateVersion, Equals, 1)

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
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
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

	timestampVersion, err = r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, 3)

	//adding extra keys for non-top target role
	//should increase top-target version by 1
	delegateGenKey(c, r, "role01")
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	rootVersion, err = r.RootVersion()
	c.Assert(err, IsNil)
	c.Assert(rootVersion, Equals, 2)

	targetsVersion, err = r.TargetsVersion()
	c.Assert(err, IsNil)
	c.Assert(targetsVersion, Equals, 2)

	snapshotVersion, err = r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(snapshotVersion, Equals, 4)

	timestampVersion, err = r.SnapshotVersion()
	c.Assert(err, IsNil)
	c.Assert(timestampVersion, Equals, 4)
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
	delegateGenKey(c, r, "role01")
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

	//adding a file stages non-top target
	tmp.writeStagedTarget("ear.txt", "ear")
	c.Assert(r.DelegateAddTarget("role01.json", "ear.txt", nil), IsNil)
	tmp.assertExists("staged/role01.json")
	tmp.assertEmpty("repository")
	d, err := r.delegationTargets("role01.json")
	c.Assert(err, IsNil)
	c.Assert(d.Targets, HasLen, 1)
	if _, ok := d.Targets["ear.txt"]; !ok {
		c.Fatal("missing target file: ear.txt")
	}

	// Snapshot() stages snapshot.json
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
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
	tmp.assertExists("repository/role01.json")
	tmp.assertExists("repository/snapshot.json")
	tmp.assertExists("repository/timestamp.json")
	tmp.assertFileContent("repository/targets/foo.txt", "foo")
	tmp.assertFileContent("repository/targets/ear.txt", "ear")
	tmp.assertEmpty("staged/targets")
	tmp.assertEmpty("staged")

	// adding and committing another file moves it into repository/targets
	tmp.writeStagedTarget("path/to/bar.txt", "bar")
	c.Assert(r.AddTarget("path/to/bar.txt", nil), IsNil)
	tmp.assertExists("staged/targets.json")
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	tmp.assertFileContent("repository/targets/foo.txt", "foo")
	tmp.assertFileContent("repository/targets/path/to/bar.txt", "bar")
	tmp.assertEmpty("staged/targets")
	tmp.assertEmpty("staged")

	// removing and committing a file removes it from repository/targets
	c.Assert(r.RemoveTarget("foo.txt"), IsNil)
	tmp.assertExists("staged/targets.json")
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	tmp.assertNotExist("repository/targets/foo.txt")
	tmp.assertFileContent("repository/targets/path/to/bar.txt", "bar")
	tmp.assertEmpty("staged/targets")
	tmp.assertEmpty("staged")

	//Same function above for non-top target meta
	tmp.writeStagedTarget("path/to/hop.txt", "hop")
	c.Assert(r.DelegateAddTarget("role01.json", "path/to/hop.txt", nil), IsNil)
	tmp.assertExists("staged/role01.json")
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	tmp.assertFileContent("repository/targets/ear.txt", "ear")
	tmp.assertFileContent("repository/targets/path/to/hop.txt", "hop")
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
	delegateGenKey(c, newRepo(), "role01")
	genKey(c, newRepo(), "snapshot")
	genKey(c, newRepo(), "timestamp")

	tmp.writeStagedTarget("foo.txt", "foo")
	c.Assert(newRepo().AddTarget("foo.txt", nil), IsNil)
	tmp.writeStagedTarget("bar.txt", "bar")
	c.Assert(newRepo().DelegateAddTarget("role01.json", "bar.txt", nil), IsNil)
	c.Assert(newRepo().Snapshot(CompressionTypeNone), IsNil)
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
	delegateGenKey(c, r, "role01")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	tmp.writeStagedTarget("foo.txt", "foo")
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)
	tmp.writeStagedTarget("dir/bar.txt", "bar")
	c.Assert(r.AddTarget("dir/bar.txt", nil), IsNil)
	tmp.writeStagedTarget("doi.txt", "doi")
	c.Assert(r.DelegateAddTarget("role01.json", "doi.txt", nil), IsNil)
	tmp.writeStagedTarget("dir/sec.txt", "sec")
	c.Assert(r.DelegateAddTarget("role01.json", "dir/sec.txt", nil), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	versions, err := r.fileVersions()
	c.Assert(err, IsNil)
	c.Assert(versions["root.json"], Equals, 1)
	c.Assert(versions["targets.json"], Equals, 1)
	c.Assert(versions["role01.json"], Equals, 1)
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
	c.Assert(r.DelegateRemoveTarget("role01.json", "doi.txt"), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	versions, err = r.fileVersions()
	c.Assert(err, IsNil)
	c.Assert(versions["root.json"], Equals, 1)
	c.Assert(versions["targets.json"], Equals, 2)
	c.Assert(versions["role01.json"], Equals, 2)
	c.Assert(versions["snapshot.json"], Equals, 2)

	// Save the old hashes for foo.txt to make sure we can assert it doesn't exist later.
	fooHashes := hashes["targets/foo.txt"]
	doiHashes := hashes["targets/doi.txt"]
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

	tmp.assertHashedFilesNotExist("repository/targets/doi.txt", doiHashes)
	tmp.assertNotExist("repository/targets/doi.txt")

	// targets should be returned by new repo
	newRepo, err := NewRepo(local, "sha512", "sha256")
	c.Assert(err, IsNil)
	t, err := newRepo.targets()
	c.Assert(err, IsNil)
	c.Assert(t.Targets, HasLen, 1)
	if _, ok := t.Targets["dir/bar.txt"]; !ok {
		c.Fatal("missing targets file: dir/bar.txt")
	}
	d, err := newRepo.delegationTargets("role01.json")
	c.Assert(err, IsNil)
	c.Assert(d.Targets, HasLen, 1)
	if _, ok := d.Targets["dir/sec.txt"]; !ok {
		c.Fatal("missing targets file: dir/sec.txt")
	}
}

func (rs *RepoSuite) TestExpiresAndVersion(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo"), "bar.txt": []byte("bar")}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	past := time.Now().Add(-1 * time.Second)
	_, genKeyErr := r.GenKeyWithExpires("root", past)
	for _, err := range []error{
		genKeyErr,
		r.AddTargetWithExpires("foo.txt", nil, past),
		r.RemoveTargetWithExpires("foo.txt", past),
		r.SnapshotWithExpires(CompressionTypeNone, past),
		r.TimestampWithExpires(past),
	} {
		c.Assert(err, Equals, ErrInvalidExpires{past})
	}

	genKey(c, r, "root")
	genKey(c, r, "targets")
	delegateGenKey(c, r, "role01")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	c.Assert(r.AddTargets([]string{}, nil), IsNil)
	c.Assert(r.DelegateAddTargets("role01.json", []string{}, nil), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Version, Equals, 1)

	expires := time.Now().Add(24 * time.Hour)
	_, err = r.GenKeyWithExpires("root", expires)
	c.Assert(err, IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
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
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Expires.Unix(), DeepEquals, expires.Round(time.Second).Unix())
	c.Assert(root.Version, Equals, 3)

	expires = time.Now().Add(6 * time.Hour)
	c.Assert(r.AddTargetWithExpires("foo.txt", nil, expires), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	targets, err := r.targets()
	c.Assert(err, IsNil)
	c.Assert(targets.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(targets.Version, Equals, 2)

	expires = time.Now().Add(2 * time.Hour)
	c.Assert(r.RemoveTargetWithExpires("foo.txt", expires), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	targets, err = r.targets()
	c.Assert(err, IsNil)
	c.Assert(targets.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(targets.Version, Equals, 3)

	expires = time.Now().Add(6 * time.Hour)
	c.Assert(r.DelegateAddTargetWithExpires("role01.json", "bar.txt", nil, expires), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	temp, err := r.delegationTargets("role01.json")
	c.Assert(err, IsNil)
	c.Assert(temp.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(temp.Version, Equals, 2)

	expires = time.Now().Add(2 * time.Hour)
	c.Assert(r.DelegateRemoveTargetWithExpires("role01.json", "bar.txt", expires), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	temp, err = r.delegationTargets("role01.json")
	c.Assert(err, IsNil)
	c.Assert(temp.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(temp.Version, Equals, 3)

	expires = time.Now().Add(time.Hour)
	c.Assert(r.SnapshotWithExpires(CompressionTypeNone, expires), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	snapshot, err := r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(snapshot.Version, Equals, 8)

	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Meta["root.json"].Version, Equals, root.Version)
	c.Assert(snapshot.Meta["targets.json"].Version, Equals, targets.Version)

	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Version, Equals, 9)

	expires = time.Now().Add(10 * time.Minute)
	c.Assert(r.TimestampWithExpires(expires), IsNil)
	c.Assert(r.Commit(), IsNil)
	timestamp, err := r.timestamp()
	c.Assert(err, IsNil)
	c.Assert(timestamp.Expires.Unix(), Equals, expires.Round(time.Second).Unix())
	c.Assert(timestamp.Version, Equals, 10)

	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	timestamp, err = r.timestamp()
	c.Assert(err, IsNil)
	c.Assert(timestamp.Version, Equals, 11)
	c.Assert(timestamp.Meta["snapshot.json"].Version, Equals, snapshot.Version)
}

func (rs *RepoSuite) TestHashAlgorithm(c *C) {
	files := map[string][]byte{"foo.txt": []byte("foo"), "bar.txt": []byte("bar")}
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
		delegateGenKey(c, r, "role01")
		genKey(c, r, "snapshot")
		c.Assert(r.AddTarget("foo.txt", nil), IsNil)
		c.Assert(r.DelegateAddTarget("role01.json", "bar.txt", nil), IsNil)
		c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
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
		temp, err := r.delegationTargets("role01.json")
		c.Assert(err, IsNil)
		for name, file := range map[string]data.FileMeta{
			"foo.txt":       targets.Targets["foo.txt"].FileMeta,
			"bar.txt":       temp.Targets["bar.txt"].FileMeta,
			"root.json":     snapshot.Meta["root.json"].FileMeta,
			"targets.json":  snapshot.Meta["targets.json"].FileMeta,
			"role01.json":   snapshot.Meta["role01.json"].FileMeta,
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

func testPassphraseFunc(p []byte) util.PassphraseFunc {
	return func(string, bool) ([]byte, error) { return p, nil }
}

func (rs *RepoSuite) TestKeyPersistence(c *C) {
	tmp := newTmpDir(c)
	passphrase := []byte("s3cr3t")
	store := FileSystemStore(tmp.path, testPassphraseFunc(passphrase))

	assertKeys := func(role string, enc bool, expected []*sign.PrivateKey) {
		keysJSON := tmp.readFile("keys/" + role + ".json")
		pk := &persistedKeys{}
		c.Assert(json.Unmarshal(keysJSON, pk), IsNil)

		// check the persisted keys are correct
		var actual []*sign.PrivateKey
		if enc {
			c.Assert(pk.Encrypted, Equals, true)
			decrypted, err := encrypted.Decrypt(pk.Data, passphrase)
			c.Assert(err, IsNil)
			c.Assert(json.Unmarshal(decrypted, &actual), IsNil)
		} else {
			c.Assert(pk.Encrypted, Equals, false)
			c.Assert(json.Unmarshal(pk.Data, &actual), IsNil)
		}
		c.Assert(actual, HasLen, len(expected))
		for i, key := range expected {
			c.Assert(expected[i], DeepEquals, key)
		}

		// check GetKeys is correct
		signers, err := store.GetSigningKeys(role)
		c.Assert(err, IsNil)
		c.Assert(signers, HasLen, len(expected))
		for i, s := range signers {
			c.Assert(s.IDs(), DeepEquals, expected[i].PublicData().IDs())
		}
	}

	// save a key and check it gets encrypted
	key, err := sign.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(store.SavePrivateKey("root", key), IsNil)
	assertKeys("root", true, []*sign.PrivateKey{key})

	// save another key and check it gets added to the existing keys
	newKey, err := sign.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(store.SavePrivateKey("root", newKey), IsNil)
	assertKeys("root", true, []*sign.PrivateKey{key, newKey})

	// check saving a key to an encrypted file without a passphrase fails
	insecureStore := FileSystemStore(tmp.path, nil)
	key, err = sign.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(insecureStore.SavePrivateKey("root", key), Equals, ErrPassphraseRequired{"root"})

	// save a key to an insecure store and check it is not encrypted
	key, err = sign.GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(insecureStore.SavePrivateKey("targets", key), IsNil)
	assertKeys("targets", false, []*sign.PrivateKey{key})
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
	delegateGenKey(c, r, "role01")
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
	assertDelegateRepoTargets := func(paths ...string) {
		d, err := r.delegationTargets("role01.json")
		c.Assert(err, IsNil)
		for _, path := range paths {
			if _, ok := d.Targets[path]; !ok {
				c.Fatalf("missing target file: %s", path)
			}
		}
	}

	// adding and committing multiple files moves correct targets from staged -> repository
	tmp.writeStagedTarget("foo.txt", "foo")
	tmp.writeStagedTarget("bar.txt", "bar")
	c.Assert(r.AddTargets([]string{"foo.txt", "bar.txt"}, nil), IsNil)
	tmp.writeStagedTarget("sin.txt", "sin")
	tmp.writeStagedTarget("cos.txt", "cos")
	c.Assert(r.DelegateAddTargets("role01.json", []string{"sin.txt", "cos.txt"}, nil), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
	assertRepoTargets("foo.txt", "bar.txt")
	tmp.assertExists("repository/targets/foo.txt")
	tmp.assertExists("repository/targets/bar.txt")
	assertDelegateRepoTargets("sin.txt", "cos.txt")
	tmp.assertExists("repository/targets/sin.txt")
	tmp.assertExists("repository/targets/cos.txt")

	// adding all targets moves them all from staged -> repository
	count := 10
	files := make([]string, count)
	for i := 0; i < count; i++ {
		files[i] = fmt.Sprintf("file%d.txt", i)
		tmp.writeStagedTarget(files[i], "data")
	}
	c.Assert(r.AddTargets(nil, nil), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
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
	c.Assert(r.DelegateRemoveTargets("role01.json", nil), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
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
		"sin.txt": []byte("sin"),
		"cos.txt": []byte("cos"),
		"tan.txt": []byte("tan"),
	}
	local := MemoryStore(make(map[string]json.RawMessage), files)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)
	delegateGenKey(c, r, "role01")

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

	delegateCustom := json.RawMessage(`{"trig":"trig"}`)
	delegateAssertCustomMeta := func(file string, custom *json.RawMessage) {
		d, err := r.delegationTargets("role01.json")
		c.Assert(err, IsNil)
		target, ok := d.Targets[file]
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

	c.Assert(r.DelegateAddTarget("role01.json", "sin.txt", delegateCustom), IsNil)
	delegateAssertCustomMeta("sin.txt", &delegateCustom)

	c.Assert(r.DelegateAddTarget("role01.json", "cos.txt", nil), IsNil)
	delegateAssertCustomMeta("cos.txt", nil)
	delegateAssertCustomMeta("sin.txt", &delegateCustom)

	c.Assert(r.DelegateAddTargets("role01.json", nil, nil), IsNil)
	delegateAssertCustomMeta("tan.txt", nil)
	delegateAssertCustomMeta("cos.txt", nil)
	delegateAssertCustomMeta("sin.txt", &delegateCustom)
}

func (rs *RepoSuite) TestUnknownKeyIDs(c *C) {
	// generate a repo
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	genKey(c, r, "root")
	genKey(c, r, "targets")
	delegateGenKey(c, r, "role01")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")

	// add a new key to the root metadata with an unknown key id.
	key, err := sign.GenerateEd25519Key()
	c.Assert(err, IsNil)

	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Version, Equals, 1)

	root.Keys["unknown-key-id"] = key.PublicData()
	r.setMeta("root.json", root)

	// commit the metadata to the store.
	c.Assert(r.AddTargets([]string{}, nil), IsNil)
	c.Assert(r.DelegateAddTargets("role01.json", []string{}, nil), IsNil)
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
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
		Signatures []data.Signature `json:signatures"`
	}
	c.Assert(json.Unmarshal(rootJSON, &signedRoot), IsNil)
	c.Assert(signedRoot.Signed.Version, Equals, 1)

	unknownKey, ok := signedRoot.Signed.Keys["unknown-key-id"]
	c.Assert(ok, Equals, true)
	c.Assert(unknownKey, DeepEquals, key.PublicData())

	// a new root should preserve the unknown key id.
	root, err = r.root()

	genKey(c, r, "timestamp")
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
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
	c.Assert(unknownKey, DeepEquals, key.PublicData())
}

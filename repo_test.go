package tuf

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/agl/ed25519"
	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/keys"
	"github.com/flynn/go-tuf/signed"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type RepoSuite struct{}

var _ = Suite(&RepoSuite{})

func (RepoSuite) TestNewRepo(c *C) {
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
	r, err := NewRepo(local)
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

func genKey(c *C, r *Repo, role string) string {
	id, err := r.GenKey(role)
	c.Assert(err, IsNil)
	return id
}

func (RepoSuite) TestGenKey(c *C) {
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// generate a key for an unknown role
	_, err = r.GenKey("foo")
	c.Assert(err, Equals, ErrInvalidRole{"foo"})

	// generate a root key
	id := genKey(c, r, "root")

	// check root metadata is correct
	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, NotNil)
	c.Assert(root.Roles, HasLen, 1)
	c.Assert(root.Keys, NotNil)
	c.Assert(root.Keys, HasLen, 1)
	rootRole, ok := root.Roles["root"]
	if !ok {
		c.Fatal("missing root role")
	}
	c.Assert(rootRole.KeyIDs, HasLen, 1)
	keyID := rootRole.KeyIDs[0]
	c.Assert(keyID, Equals, id)
	k, ok := root.Keys[keyID]
	if !ok {
		c.Fatal("missing key")
	}
	c.Assert(k.ID(), Equals, keyID)
	c.Assert(k.Value.Public, HasLen, ed25519.PublicKeySize)
	c.Assert(k.Value.Private, IsNil)

	// check root key + role are in db
	db, err := r.db()
	c.Assert(err, IsNil)
	rootKey := db.GetKey(keyID)
	c.Assert(rootKey, NotNil)
	c.Assert(rootKey.ID, Equals, keyID)
	role := db.GetRole("root")
	c.Assert(role.KeyIDs, DeepEquals, map[string]struct{}{keyID: {}})

	// check the key was saved correctly
	localKeys, err := local.GetKeys("root")
	c.Assert(err, IsNil)
	c.Assert(localKeys, HasLen, 1)
	c.Assert(localKeys[0].ID(), Equals, keyID)

	// check RootKeys() is correct
	rootKeys, err := r.RootKeys()
	c.Assert(err, IsNil)
	c.Assert(rootKeys, HasLen, 1)
	c.Assert(rootKeys[0].ID(), Equals, rootKey.ID)
	c.Assert(rootKeys[0].Value.Public, DeepEquals, rootKey.Serialize().Value.Public)
	c.Assert(rootKeys[0].Value.Private, IsNil)

	// generate two targets keys
	genKey(c, r, "targets")
	genKey(c, r, "targets")

	// check root metadata is correct
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, HasLen, 2)
	c.Assert(root.Keys, HasLen, 3)
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
		c.Assert(key.ID, Equals, id)
	}
	role = db.GetRole("targets")
	c.Assert(role.KeyIDs, DeepEquals, targetKeyIDs)

	// check RootKeys() is unchanged
	rootKeys, err = r.RootKeys()
	c.Assert(err, IsNil)
	c.Assert(rootKeys, HasLen, 1)
	c.Assert(rootKeys[0].ID(), Equals, rootKey.ID)

	// check the keys were saved correctly
	localKeys, err = local.GetKeys("targets")
	c.Assert(err, IsNil)
	c.Assert(localKeys, HasLen, 2)
	for _, key := range localKeys {
		found := false
		for _, id := range targetsRole.KeyIDs {
			if id == key.ID() {
				found = true
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
	c.Assert(stagedRoot.Keys, DeepEquals, root.Keys)
	c.Assert(stagedRoot.Roles, DeepEquals, root.Roles)
}

func (RepoSuite) TestRevokeKey(c *C) {
	local := MemoryStore(make(map[string]json.RawMessage), nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// revoking a key for an unknown role returns ErrInvalidRole
	c.Assert(r.RevokeKey("foo", ""), DeepEquals, ErrInvalidRole{"foo"})

	// revoking a key which doesn't exist returns ErrKeyNotFound
	c.Assert(r.RevokeKey("root", "nonexistent"), DeepEquals, ErrKeyNotFound{"root", "nonexistent"})

	// generate keys
	genKey(c, r, "root")
	genKey(c, r, "targets")
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, NotNil)
	c.Assert(root.Roles, HasLen, 4)
	c.Assert(root.Keys, NotNil)
	c.Assert(root.Keys, HasLen, 5)

	// revoke a key
	targetsRole, ok := root.Roles["targets"]
	if !ok {
		c.Fatal("missing targets role")
	}
	c.Assert(targetsRole.KeyIDs, HasLen, 2)
	id := targetsRole.KeyIDs[0]
	c.Assert(r.RevokeKey("targets", id), IsNil)

	// check root was updated
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Roles, NotNil)
	c.Assert(root.Roles, HasLen, 4)
	c.Assert(root.Keys, NotNil)
	c.Assert(root.Keys, HasLen, 4)
	targetsRole, ok = root.Roles["targets"]
	if !ok {
		c.Fatal("missing targets role")
	}
	c.Assert(targetsRole.KeyIDs, HasLen, 1)
	c.Assert(targetsRole.KeyIDs[0], Not(Equals), id)
}

func (RepoSuite) TestSign(c *C) {
	meta := map[string]json.RawMessage{"root.json": []byte(`{"signed":{},"signatures":[]}`)}
	local := MemoryStore(meta, nil)
	r, err := NewRepo(local)
	c.Assert(err, IsNil)

	// signing with no keys returns ErrInsufficientKeys
	c.Assert(r.Sign("root.json"), Equals, ErrInsufficientKeys{"root.json"})

	checkSigIDs := func(keyIDs ...string) {
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
	key, err := keys.NewKey()
	c.Assert(err, IsNil)
	c.Assert(local.SaveKey("root", key.SerializePrivate()), IsNil)
	c.Assert(r.Sign("root.json"), IsNil)
	checkSigIDs(key.ID)

	// signing again does not generate a duplicate signature
	c.Assert(r.Sign("root.json"), IsNil)
	checkSigIDs(key.ID)

	// signing with a new available key generates another signature
	newKey, err := keys.NewKey()
	c.Assert(err, IsNil)
	c.Assert(local.SaveKey("root", newKey.SerializePrivate()), IsNil)
	c.Assert(r.Sign("root.json"), IsNil)
	checkSigIDs(key.ID, newKey.ID)
}

func (RepoSuite) TestCommit(c *C) {
	files := map[string][]byte{"/foo.txt": []byte("foo"), "/bar.txt": []byte("bar")}
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
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Commit(), DeepEquals, ErrMissingMetadata{"timestamp.json"})

	// commit with timestamp.json but no timestamp key
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), DeepEquals, ErrInsufficientSignatures{"timestamp.json", signed.ErrNoSignatures})

	// commit success
	genKey(c, r, "timestamp")
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)

	// commit with an invalid root hash in snapshot.json due to new key creation
	genKey(c, r, "targets")
	c.Assert(r.Sign("targets.json"), IsNil)
	c.Assert(r.Commit(), DeepEquals, errors.New("tuf: invalid root.json in snapshot.json: wrong length"))

	// commit with an invalid targets hash in snapshot.json
	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	c.Assert(r.AddTarget("bar.txt", nil), IsNil)
	c.Assert(r.Commit(), DeepEquals, errors.New("tuf: invalid targets.json in snapshot.json: wrong length"))

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

func (RepoSuite) TestExpiresAndVersion(c *C) {
	files := map[string][]byte{"/foo.txt": []byte("foo")}
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
	root, err := r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Version, Equals, 1)

	expires := time.Now().Add(24 * time.Hour)
	_, err = r.GenKeyWithExpires("root", expires)
	c.Assert(err, IsNil)
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Expires.Unix(), DeepEquals, expires.Unix())
	c.Assert(root.Version, Equals, 2)

	expires = time.Now().Add(12 * time.Hour)
	role, ok := root.Roles["root"]
	if !ok {
		c.Fatal("missing root role")
	}
	c.Assert(role.KeyIDs, HasLen, 2)
	c.Assert(r.RevokeKeyWithExpires("root", role.KeyIDs[0], expires), IsNil)
	root, err = r.root()
	c.Assert(err, IsNil)
	c.Assert(root.Expires.Unix(), DeepEquals, expires.Unix())
	c.Assert(root.Version, Equals, 3)

	expires = time.Now().Add(6 * time.Hour)
	genKey(c, r, "targets")
	c.Assert(r.AddTargetWithExpires("foo.txt", nil, expires), IsNil)
	targets, err := r.targets()
	c.Assert(err, IsNil)
	c.Assert(targets.Expires.Unix(), Equals, expires.Unix())
	c.Assert(targets.Version, Equals, 1)

	expires = time.Now().Add(2 * time.Hour)
	c.Assert(r.RemoveTargetWithExpires("foo.txt", expires), IsNil)
	targets, err = r.targets()
	c.Assert(err, IsNil)
	c.Assert(targets.Expires.Unix(), Equals, expires.Unix())
	c.Assert(targets.Version, Equals, 2)

	expires = time.Now().Add(time.Hour)
	genKey(c, r, "snapshot")
	c.Assert(r.SnapshotWithExpires(CompressionTypeNone, expires), IsNil)
	snapshot, err := r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Expires.Unix(), Equals, expires.Unix())
	c.Assert(snapshot.Version, Equals, 1)

	c.Assert(r.Snapshot(CompressionTypeNone), IsNil)
	snapshot, err = r.snapshot()
	c.Assert(err, IsNil)
	c.Assert(snapshot.Version, Equals, 2)

	expires = time.Now().Add(10 * time.Minute)
	genKey(c, r, "timestamp")
	c.Assert(r.TimestampWithExpires(expires), IsNil)
	timestamp, err := r.timestamp()
	c.Assert(err, IsNil)
	c.Assert(timestamp.Expires.Unix(), Equals, expires.Unix())
	c.Assert(timestamp.Version, Equals, 1)

	c.Assert(r.Timestamp(), IsNil)
	timestamp, err = r.timestamp()
	c.Assert(err, IsNil)
	c.Assert(timestamp.Version, Equals, 2)
}

func (RepoSuite) TestHashAlgorithm(c *C) {
	files := map[string][]byte{"/foo.txt": []byte("foo")}
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
		for name, file := range map[string]data.FileMeta{
			"foo.txt":       targets.Targets["/foo.txt"],
			"root.json":     snapshot.Meta["root.json"],
			"targets.json":  snapshot.Meta["targets.json"],
			"snapshot.json": timestamp.Meta["snapshot.json"],
		} {
			for _, hashAlgorithm := range test.expected {
				if _, ok := file.Hashes[hashAlgorithm]; !ok {
					c.Fatalf("expected %s hash to contain hash func %s, got %s", name, hashAlgorithm, file.HashAlgorithms())
				}
			}
		}
	}
}

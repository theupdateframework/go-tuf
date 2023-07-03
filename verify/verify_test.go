package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/pkg/keys"
	"github.com/theupdateframework/go-tuf/sign"
	"golang.org/x/crypto/ed25519"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type VerifySuite struct{}

var _ = Suite(&VerifySuite{})

type ecdsaSigner struct {
	*ecdsa.PrivateKey
}

type ecdsaPublic struct {
	PublicKey *keys.PKIXPublicKey `json:"public"`
}

func (s ecdsaSigner) PublicData() *data.PublicKey {
	keyValBytes, _ := json.Marshal(ecdsaPublic{PublicKey: &keys.PKIXPublicKey{PublicKey: s.Public()}})
	return &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      keyValBytes,
	}
}

func (s ecdsaSigner) SignMessage(message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return s.PrivateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
}

func (s ecdsaSigner) ContainsID(id string) bool {
	return s.PublicData().ContainsID(id)
}

func (ecdsaSigner) MarshalPrivateKey() (*data.PrivateKey, error) {
	return nil, errors.New("not implemented for test")
}

func (ecdsaSigner) UnmarshalPrivateKey(key *data.PrivateKey) error {
	return errors.New("not implemented for test")
}

func (VerifySuite) Test(c *C) {
	type test struct {
		name  string
		keys  []*data.PublicKey
		roles map[string]*data.Role
		s     *data.Signed
		ver   int64
		exp   *time.Time
		typ   string
		role  string
		err   error
		mut   func(*test)
	}

	expiredTime := time.Now().Add(-time.Hour)
	minVer := int64(10)
	tests := []test{
		{
			name: "no signatures",
			mut:  func(t *test) { t.s.Signatures = []data.Signature{} },
			err:  ErrNoSignatures,
		},
		{
			name: "unknown role",
			role: "foo",
			err:  ErrUnknownRole{"foo"},
		},
		{
			// It is impossible to distinguish between an error of an invalid
			// signature and a threshold not achieved. Invalid signatures lead
			// to not achieving the threshold.
			name: "signature wrong length",
			mut:  func(t *test) { t.s.Signatures[0].Signature = []byte{0} },
			err:  ErrRoleThreshold{1, 0},
		},
		{
			name: "key missing from role",
			mut:  func(t *test) { t.roles["root"].KeyIDs = nil },
			err:  ErrRoleThreshold{1, 0},
		},
		{
			name: "invalid signature",
			mut:  func(t *test) { t.s.Signatures[0].Signature = make([]byte, ed25519.SignatureSize) },
			err:  ErrRoleThreshold{1, 0},
		},
		{
			name: "enough signatures with extra invalid signature",
			mut: func(t *test) {
				t.s.Signatures = append(t.s.Signatures, data.Signature{
					KeyID:     t.s.Signatures[0].KeyID,
					Signature: make([]byte, ed25519.SignatureSize)})
			},
		},
		{
			name: "not enough signatures",
			mut:  func(t *test) { t.roles["root"].Threshold = 2 },
			err:  ErrRoleThreshold{2, 1},
		},
		{
			name: "exactly enough signatures",
		},
		{
			name: "more than enough signatures",
			mut: func(t *test) {
				k, _ := keys.GenerateEd25519Key()
				sign.Sign(t.s, k)
				t.keys = append(t.keys, k.PublicData())
				t.roles["root"].KeyIDs = append(t.roles["root"].KeyIDs, k.PublicData().IDs()...)
			},
		},
		{
			name: "duplicate key id",
			mut: func(t *test) {
				t.roles["root"].Threshold = 2
				t.s.Signatures = append(t.s.Signatures, t.s.Signatures[0])
			},
			err: ErrRoleThreshold{2, 1},
		},
		{
			name: "unknown key",
			mut: func(t *test) {
				k, _ := keys.GenerateEd25519Key()
				sign.Sign(t.s, k)
			},
		},
		{
			name: "unknown key below threshold",
			mut: func(t *test) {
				k, _ := keys.GenerateEd25519Key()
				sign.Sign(t.s, k)
				t.roles["root"].Threshold = 2
			},
			err: ErrRoleThreshold{2, 1},
		},
		{
			name: "unknown keys in db",
			mut: func(t *test) {
				k, _ := keys.GenerateEd25519Key()
				sign.Sign(t.s, k)
				t.keys = append(t.keys, k.PublicData())
			},
		},
		{
			name: "unknown keys in db below threshold",
			mut: func(t *test) {
				k, _ := keys.GenerateEd25519Key()
				sign.Sign(t.s, k)
				t.keys = append(t.keys, k.PublicData())
				t.roles["root"].Threshold = 2
			},
			err: ErrRoleThreshold{2, 1},
		},
		{
			name: "wrong type",
			typ:  "bar",
			err:  ErrWrongMetaType,
		},
		{
			name: "low version",
			ver:  minVer - 1,
			err:  ErrLowVersion{minVer - 1, minVer},
		},
		{
			name: "expired",
			exp:  &expiredTime,
			err:  ErrExpired{expiredTime},
		},
		{
			name: "valid ecdsa signature",
			mut: func(t *test) {
				k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				s := ecdsaSigner{k}
				sign.Sign(t.s, s)
				t.s.Signatures = t.s.Signatures[1:]
				t.keys = []*data.PublicKey{s.PublicData()}
				t.roles["root"].KeyIDs = s.PublicData().IDs()
			},
		},
		{
			// The threshold is still achieved.
			name: "invalid second ecdsa signature",
			mut: func(t *test) {
				k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				s := ecdsaSigner{k}
				sign.Sign(t.s, s)
				t.s.Signatures[1].Signature[0]++
				t.keys = append(t.keys, s.PublicData())
				t.roles["root"].KeyIDs = append(t.roles["root"].KeyIDs, s.PublicData().IDs()...)
			},
		},
	}
	for _, t := range tests {
		if t.role == "" {
			t.role = "root"
		}
		if t.ver == 0 {
			t.ver = minVer
		}
		if t.exp == nil {
			expires := time.Now().Add(time.Hour)
			t.exp = &expires
		}
		if t.typ == "" {
			t.typ = t.role
		}
		if t.keys == nil && t.s == nil {
			k, _ := keys.GenerateEd25519Key()
			t.s, _ = sign.Marshal(&signedMeta{Type: t.typ, Version: t.ver, Expires: *t.exp}, k)
			t.keys = []*data.PublicKey{k.PublicData()}
		}
		if t.roles == nil {
			t.roles = map[string]*data.Role{
				"root": {
					KeyIDs:    t.keys[0].IDs(),
					Threshold: 1,
				},
			}
		}
		if t.mut != nil {
			t.mut(&t)
		}

		db := NewDB()
		for _, k := range t.keys {
			for _, id := range k.IDs() {
				err := db.AddKey(id, k)
				c.Assert(err, IsNil)
			}
		}
		for n, r := range t.roles {
			err := db.AddRole(n, r)
			c.Assert(err, IsNil)
		}

		err := db.Verify(t.s, t.role, minVer)
		if e, ok := t.err.(ErrExpired); ok {
			assertErrExpired(c, err, e)
		} else {
			c.Assert(err, DeepEquals, t.err, Commentf("name = %s", t.name))
		}
	}
}

func (VerifySuite) TestVerifyIgnoreExpired(c *C) {
	minVer := int64(10)
	role := "root"
	k, _ := keys.GenerateEd25519Key()
	s, _ := sign.Marshal(&signedMeta{Type: role, Version: minVer, Expires: time.Now().Add(-time.Hour)}, k)
	keys := []*data.PublicKey{k.PublicData()}
	roles := map[string]*data.Role{
		"root": {
			KeyIDs:    keys[0].IDs(),
			Threshold: 1,
		},
	}

	db := NewDB()
	for _, k := range keys {
		for _, id := range k.IDs() {
			err := db.AddKey(id, k)
			c.Assert(err, IsNil)
		}
	}
	for n, r := range roles {
		err := db.AddRole(n, r)
		c.Assert(err, IsNil)
	}

	err := db.VerifyIgnoreExpiredCheck(s, role, minVer)
	c.Assert(err, IsNil)
}

func assertErrExpired(c *C, err error, expected ErrExpired) {
	actual, ok := err.(ErrExpired)
	if !ok {
		c.Fatalf("expected err to have type ErrExpired, got %T", err)
	}
	c.Assert(actual.Expired.Unix(), Equals, expected.Expired.Unix())
}

package tuf

import (
	"github.com/agl/ed25519"
	"github.com/flynn/tuf/data"
	"github.com/flynn/tuf/keys"

	. "gopkg.in/check.v1"
)

type VerifySuite struct{}

var _ = Suite(&VerifySuite{})

func (VerifySuite) Test(c *C) {
	type test struct {
		name  string
		keys  []*data.Key
		roles map[string]*data.Role
		s     *data.Signed
		role  string
		err   error
		mut   func(*test)
	}

	tests := []test{
		{
			name: "no signatures",
			mut:  func(t *test) { t.s.Signatures = []data.Signature{} },
			err:  ErrNoSignatures,
		},
		{
			name: "unknown role",
			role: "foo",
			err:  ErrUnknownRole,
		},
		{
			name: "wrong signature method",
			mut:  func(t *test) { t.s.Signatures[0].Method = "foo" },
			err:  ErrWrongMethod,
		},
		{
			name: "signature wrong length",
			mut:  func(t *test) { t.s.Signatures[0].Signature = []byte{0} },
			err:  ErrInvalid,
		},
		{
			name: "key missing from role",
			mut:  func(t *test) { t.roles["root"].KeyIDs = nil },
			err:  ErrRoleThreshold,
		},
		{
			name: "invalid signature",
			mut:  func(t *test) { t.s.Signatures[0].Signature = make([]byte, ed25519.SignatureSize) },
			err:  ErrInvalid,
		},
		{
			name: "not enough signatures",
			mut:  func(t *test) { t.roles["root"].Threshold = 2 },
			err:  ErrRoleThreshold,
		},
		{
			name: "exactly enough signatures",
		},
		{
			name: "more than enough signatures",
			mut: func(t *test) {
				k, _ := keys.NewKey()
				Sign(t.s, k)
				t.keys = append(t.keys, k.Serialize())
				t.roles["root"].KeyIDs = append(t.roles["root"].KeyIDs, k.ID)
			},
		},
		{
			name: "duplicate key id",
			mut: func(t *test) {
				t.roles["root"].Threshold = 2
				t.s.Signatures = append(t.s.Signatures, t.s.Signatures[0])
			},
			err: ErrRoleThreshold,
		},
		{
			name: "unknown key",
			mut: func(t *test) {
				k, _ := keys.NewKey()
				Sign(t.s, k)
			},
		},
		{
			name: "unknown key below threshold",
			mut: func(t *test) {
				k, _ := keys.NewKey()
				Sign(t.s, k)
				t.roles["root"].Threshold = 2
			},
			err: ErrRoleThreshold,
		},
		{
			name: "unknown keys in db",
			mut: func(t *test) {
				k, _ := keys.NewKey()
				Sign(t.s, k)
				t.keys = append(t.keys, k.Serialize())
			},
		},
		{
			name: "unknown keys in db below threshold",
			mut: func(t *test) {
				k, _ := keys.NewKey()
				Sign(t.s, k)
				t.keys = append(t.keys, k.Serialize())
				t.roles["root"].Threshold = 2
			},
			err: ErrRoleThreshold,
		},
	}
	for _, t := range tests {
		if t.role == "" {
			t.role = "root"
		}
		if t.keys == nil && t.s == nil {
			k, _ := keys.NewKey()
			t.s, _ = MarshalSigned(&struct{}{}, k)
			t.keys = []*data.Key{k.Serialize()}
		}
		if t.roles == nil {
			t.roles = map[string]*data.Role{
				"root": &data.Role{
					KeyIDs:    []string{t.keys[0].ID()},
					Threshold: 1,
				},
			}
		}
		if t.mut != nil {
			t.mut(&t)
		}

		db := keys.NewDB()
		for _, k := range t.keys {
			err := db.AddKey(k.ID(), k)
			c.Assert(err, IsNil)
		}
		for n, r := range t.roles {
			err := db.AddRole(n, r)
			c.Assert(err, IsNil)
		}

		err := VerifySigned(t.s, t.role, db)
		c.Assert(err, Equals, t.err, Commentf("name = %s", t.name))
	}
}

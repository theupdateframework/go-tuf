package verify

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/pkg/keys"
)

func TestDelegationsDB(t *testing.T) {
	var dbTests = []struct {
		testName     string
		delegations  *data.Delegations
		initErr      error
		unmarshalErr error
	}{
		{
			testName:     "empty state",
			delegations:  &data.Delegations{},
			unmarshalErr: ErrNoSignatures,
		},
		{
			testName: "top level role",
			delegations: &data.Delegations{Roles: []data.DelegatedRole{
				{Name: "root"},
			}},
			initErr: ErrInvalidDelegatedRole,
		},
		{
			testName: "invalid role",
			delegations: &data.Delegations{Roles: []data.DelegatedRole{
				{Threshold: 0},
			}},
			initErr: ErrInvalidThreshold,
		},
	}

	for _, tt := range dbTests {
		t.Run(tt.testName, func(t *testing.T) {
			db, err := NewDBFromDelegations(tt.delegations)
			assert.Equal(t, tt.initErr, err)
			if err == nil {
				assert.NotNil(t, db)
				var targets data.Targets
				err = db.Unmarshal([]byte(`{"a":"b"}`), targets, "tree", 0)
				assert.Equal(t, tt.unmarshalErr, err)
			}
		})
	}
}

// Test key database for compliance with TAP-12.
//
// Previously, every key's key ID was the SHA256 of the public key. TAP-12
// allows arbitrary key IDs, with no loss in security.
//
//
// TAP-12: https://github.com/theupdateframework/taps/blob/master/tap12.md
func TestTAP12(t *testing.T) {
	db := NewDB()
	// Need to use a signer type that supports random signatures.
	key1, _ := keys.GenerateRsaKey()
	key2, _ := keys.GenerateRsaKey()
	msg := []byte("{}")
	sig1, _ := key1.SignMessage(msg)
	sig1Duplicate, _ := key1.SignMessage(msg)
	assert.NotEqual(t, sig1, sig1Duplicate, "Signatures should be random")
	sig2, _ := key2.SignMessage(msg)

	// Idempotent: adding the same key with the same ID is okay.
	assert.Nil(t, db.AddKey("key1", key1.PublicData()), "initial add")
	assert.Nil(t, db.AddKey("key1", key1.PublicData()), "re-add")
	// Adding a different key is allowed, unless the key ID is the same.
	assert.Nil(t, db.AddKey("key2", key2.PublicData()), "different key with different ID")
	assert.ErrorIs(t, db.AddKey("key1", key2.PublicData()), ErrRepeatID{"key1"}, "different key with same key ID")
	assert.Nil(t, db.AddKey("key1-duplicate", key1.PublicData()), "same key with different ID should succeed")
	assert.Nil(t, db.AddRole("diffkeys", &data.Role{
		KeyIDs:    []string{"key1", "key2"},
		Threshold: 2,
	}), "adding role")
	assert.Nil(t, db.AddRole("samekeys", &data.Role{
		KeyIDs:    []string{"key1", "key1-alt"},
		Threshold: 2,
	}), "adding role")
	assert.Nil(t, db.VerifySignatures(&data.Signed{
		Signed:     msg,
		Signatures: []data.Signature{{KeyID: "key1", Signature: sig1}, {KeyID: "key2", Signature: sig2}},
	}, "diffkeys"), "Signature with different keys: ")
	assert.ErrorIs(t, db.VerifySignatures(&data.Signed{
		Signed:     msg,
		Signatures: []data.Signature{{KeyID: "key1", Signature: sig1}, {KeyID: "key1-alt", Signature: sig1Duplicate}},
	}, "samekeys"), ErrRoleThreshold{2, 1}, "Threshold signing with repeat key")
}

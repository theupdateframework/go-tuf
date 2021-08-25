package verify

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/data"
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
		{
			testName: "invalid keys",
			delegations: &data.Delegations{Keys: map[string]*data.PublicKey{
				"a": &data.PublicKey{Type: data.KeySchemeEd25519},
			}},
			initErr: ErrWrongID{},
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

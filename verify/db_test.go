package verify

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/data"
)

func TestDelegationsVerifier(t *testing.T) {
	var verifierTests = []struct {
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
			delegations: &data.Delegations{Keys: map[string]*data.Key{
				"a": &data.Key{Type: data.KeySchemeEd25519},
			}},
			initErr: ErrWrongID{},
		},
	}

	for _, tt := range verifierTests {
		t.Run(tt.testName, func(t *testing.T) {
			verifier, err := NewDelegationsVerifier(tt.delegations)
			assert.NotNil(t, verifier)
			assert.Equal(t, tt.initErr, err)
			if err == nil {
				var targets data.Targets
				err = verifier.Unmarshal([]byte(`{"a":"b"}`), targets, "tree", 0)
				assert.Equal(t, tt.unmarshalErr, err)
			}
		})
	}
}

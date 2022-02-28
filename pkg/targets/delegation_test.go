package targets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/verify"
)

var (
	defaultPathPatterns = []string{"tmp", "*"}
	noMatchPathPatterns = []string{"vars", "null"}
)

func TestDelegationsIterator(t *testing.T) {
	topTargetsPubKey := &data.PublicKey{
		Type:       data.KeyTypeEd25519,
		Scheme:     data.KeySchemeEd25519,
		Algorithms: data.HashAlgorithms,
		Value:      []byte(`{"public":"aaaaec567e5901ba3976c34f7cd5169704292439bf71e6aa19c64b96706f95ef"}`),
	}
	delTargetsPubKey := &data.PublicKey{
		Type:       data.KeyTypeEd25519,
		Scheme:     data.KeySchemeEd25519,
		Algorithms: data.HashAlgorithms,
		Value:      []byte(`{"public":"bbbbec567e5901ba3976c34f7cd5169704292439bf71e6aa19c64b96706f95ef"}`),
	}

	defaultKeyIDs := delTargetsPubKey.IDs()
	var iteratorTests = []struct {
		testName    string
		roles       map[string][]data.DelegatedRole
		file        string
		resultOrder []string
		err         error
	}{
		{
			testName: "no delegation",
			roles: map[string][]data.DelegatedRole{
				"targets": {},
			},
			file:        "test.txt",
			resultOrder: []string{"targets"},
		},
		{
			testName: "no termination",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "e", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"b": {
					{Name: "c", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"c": {
					{Name: "d", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"e": {
					{Name: "f", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "g", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"g": {
					{Name: "h", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "i", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "j", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
		},
		{
			testName: "terminated in b",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs, Terminating: true},
					{Name: "e", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"b": {
					{Name: "c", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "d", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "c", "d"},
		},
		{
			testName: "path does not match b",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: noMatchPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "e", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"b": {
					{Name: "c", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "d", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "e"},
		},
		{
			testName: "path does not match b - path prefixes",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", PathHashPrefixes: []string{"33472a4909"}, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "c", PathHashPrefixes: []string{"34c85d1ee84f61f10d7dc633"}, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"c": {

					{Name: "d", PathHashPrefixes: []string{"8baf"}, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "e", PathHashPrefixes: []string{"34c85d1ee84f61f10d7dc633472a49096ed87f8f764bd597831eac371f40ac39"}, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
			},
			file:        "/e/f/g.txt",
			resultOrder: []string{"targets", "c", "e"},
		},
		{
			testName: "err paths and pathHashPrefixes are set",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns, PathHashPrefixes: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"b": {},
			},
			file:        "",
			resultOrder: []string{"targets"},
			err:         data.ErrPathsAndPathHashesSet,
		},
		{
			testName: "cycle avoided 1",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "a", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"a": {
					{Name: "b", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "e", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"b": {
					{Name: "a", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "d", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "a", "b", "d", "e"},
		},
		{
			testName: "cycle avoided 2",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "a", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"a": {
					{Name: "a", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "b", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"b": {
					{Name: "a", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "b", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "c", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"c": {
					{Name: "c", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "a", "b", "c"},
		},
		{
			testName: "diamond delegation",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
					{Name: "c", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"b": {
					{Name: "d", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"c": {
					{Name: "d", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "d", "c"},
		},
		{
			testName: "simple cycle",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "a", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
				"a": {
					{Name: "a", Paths: defaultPathPatterns, Threshold: 1, KeyIDs: defaultKeyIDs},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "a"},
		},
	}

	for _, tt := range iteratorTests {
		t.Run(tt.testName, func(t *testing.T) {
			topLevelDB := verify.NewDB()
			topLevelDB.AddKey(topTargetsPubKey.IDs()[0], topTargetsPubKey)
			topLevelDB.AddRole("targets", &data.Role{
				KeyIDs:    topTargetsPubKey.IDs(),
				Threshold: 1,
			})

			d, err := NewDelegationsIterator(tt.file, topLevelDB)
			assert.NoError(t, err)

			var iterationOrder []string
			for {
				r, ok := d.Next()
				if !ok {
					break
				}

				// A delegation should have associated keys. Testing the exact keys
				// isn't useful in this module since the keys are supplied by the
				// caller in the arguments to Add().
				assert.Greater(t, len(r.Delegatee.KeyIDs), 0)

				iterationOrder = append(iterationOrder, r.Delegatee.Name)
				delegations, ok := tt.roles[r.Delegatee.Name]
				if !ok {
					continue
				}

				db, err := verify.NewDBFromDelegations(&data.Delegations{
					Roles: delegations,
				})
				assert.NoError(t, err)

				err = d.Add(delegations, r.Delegatee.Name, db)
				assert.Equal(t, tt.err, err)
			}
			assert.Equal(t, tt.resultOrder, iterationOrder)
		})
	}
}

func TestNewDelegationsIteratorError(t *testing.T) {
	// Empty DB. It is supposed to have at least the top-level targets role and
	// keys.
	tldb := verify.NewDB()

	_, err := NewDelegationsIterator("targets", tldb)
	assert.ErrorIs(t, err, ErrTopLevelTargetsRoleMissing)
}
